import socket
import time
import datetime
import threading
import platform
import re
import ssl
from .network_disruptor import NetworkDisruptor
from .arp_detector import ARPSpoofDetector
from .cve_checker import CVEChecker
from .ai_analyzer import AIAnalyzer
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from ipaddress import IPv4Network
from scapy.all import IP, TCP, ICMP, sr1, conf

conf.verb = 0

class NetworkScanner:
    def __init__(self, config):
        self.cve_checker = CVEChecker()
        self.ai_analyzer = AIAnalyzer()
        self.disruptor = NetworkDisruptor()
        self.arp_detector = ARPSpoofDetector()
        self.vulnerabilities = []
        self.config = config
        self.scanning = False
        self.scan_id = 0
        self.scan_start_time = None
        self.current_scan_progress = 0
        self.current_executor = None
        self.scan_error_message = None
        
        self.open_ports_data = []
        self.live_hosts = []
        self.ai_results = []
        self.data_lock = threading.Lock()
        self.scan_lock = threading.Lock()
    
    def parse_ip_range(self, ip_input):
        ip_input = ip_input.strip()
        if "/" in ip_input:
            try:
                net = IPv4Network(ip_input, strict=False)
                return [str(ip) for ip in net.hosts()]
            except:
                return []
        if "-" in ip_input:
            try:
                start, end = ip_input.split("-")
                start = start.strip()
                end = end.strip()
                if "." not in end:
                    base = ".".join(start.split(".")[:-1])
                    end = f"{base}.{end}"
                sp = list(map(int, start.split(".")))
                ep = list(map(int, end.split(".")))
                res = [".".join(map(str, sp))]
                while sp != ep:
                    sp[3] += 1
                    for i in (3, 2, 1):
                        if sp[i] == 256:
                            sp[i] = 0
                            sp[i - 1] += 1
                    res.append(".".join(map(str, sp)))
                return res
            except:
                return []
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip_input):
            return [ip_input]
        return []
    
    def should_stop_scan(self, current_scan_id):
        if not self.scanning:
            return True
        if self.scan_id != current_scan_id:
            return True
        if self.scan_start_time and (time.time() - self.scan_start_time) > self.config.TOTAL_SCAN_TIMEOUT:
            return True
        return False
    
    def force_stop_scan(self):
        with self.scan_lock:
            self.scanning = False
            self.scan_id += 1
            if self.current_executor:
                try:
                    self.current_executor.shutdown(wait=False, cancel_futures=True)
                except:
                    pass
                self.current_executor = None
    
    def tcp_ping(self, ip, port, current_scan_id):
        """Single-port TCP connect probe (used for discovery)."""
        if self.should_stop_scan(current_scan_id):
            return False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.config.PING_TIMEOUT)
            result = s.connect_ex((ip, port))
            s.close()
            return result == 0
        except OSError:
            return False

    def tcp_probe_any(self, ip, current_scan_id):
        """True if any common discovery port responds (host likely up)."""
        for port in getattr(self.config, "DISCOVERY_TCP_PORTS", [80, 443, 22]):
            if self.should_stop_scan(current_scan_id):
                return False
            if self.tcp_ping(ip, port, current_scan_id):
                return True
        return False
    
    def icmp_ping(self, ip, current_scan_id):
        if self.should_stop_scan(current_scan_id):
            return False
        try:
            pkt = IP(dst=ip) / ICMP()
            resp = sr1(pkt, timeout=self.config.PING_TIMEOUT, verbose=0)
            return resp is not None
        except OSError:
            return self.tcp_probe_any(ip, current_scan_id)
        except Exception:
            return False
    
    def syn_scan(self, ip, port, current_scan_id):
        if self.should_stop_scan(current_scan_id):
            return False, None
        try:
            pkt = IP(dst=ip) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=self.config.SYN_TIMEOUT, verbose=0)
            if resp is None:
                return False, None
            if resp.haslayer(TCP) and resp[TCP].flags == 0x12:
                try:
                    rst = IP(dst=ip) / TCP(dport=port, flags="R")
                    sr1(rst, timeout=0.1, verbose=0)
                except:
                    pass
                return True, resp
            return False, resp
        except:
            return self.tcp_connect_scan(ip, port, current_scan_id), None
    
    def tcp_connect_scan(self, ip, port, current_scan_id):
        if self.should_stop_scan(current_scan_id):
            return False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            res = s.connect_ex((ip, port))
            s.close()
            return res == 0
        except:
            return False
    
    def get_service_name(self, port):
        return self.config.SERVICE_MAP.get(port, "Unknown")
    
    def detect_os_from_ttl(self, resp):
        try:
            if resp and resp.haslayer(IP):
                ttl = resp[IP].ttl
                if ttl <= 64:
                    return "Linux/Unix"
                if ttl <= 128:
                    return "Windows"
            return "Unknown"
        except:
            return "Unknown"
    
    def get_banner(self, ip, port, current_scan_id):
        if self.should_stop_scan(current_scan_id):
            return self.get_service_name(port), None
        
        try:
            sock = socket.socket()
            sock.settimeout(self.config.BANNER_TIMEOUT)
            sock.connect((ip, port))
            
            if port in [443, 8443]:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=ip)
            
            if port in [80, 443, 8080, 8443]:
                request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: NetScanGo/2.0\r\nConnection: close\r\n\r\n"
                sock.send(request.encode())
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode(errors="ignore").strip()
            sock.close()
            
            if banner:
                return banner[:200], {"banner": banner}
        except:
            pass
        
        return self.get_service_name(port), None
    
    def scan_single_port(self, ip, port, current_scan_id):
        if self.should_stop_scan(current_scan_id):
            return None
        
        try:
            if platform.system().lower() != "windows":
                try:
                    is_open, resp = self.syn_scan(ip, port, current_scan_id)
                except:
                    is_open = self.tcp_connect_scan(ip, port, current_scan_id)
                    resp = None
            else:
                is_open = self.tcp_connect_scan(ip, port, current_scan_id)
                resp = None
            
            if not is_open or self.should_stop_scan(current_scan_id):
                return None
            
            service = self.get_service_name(port)
            os_guess = self.detect_os_from_ttl(resp)
            banner, details = self.get_banner(ip, port, current_scan_id)
            
            if self.should_stop_scan(current_scan_id):
                return None
            
            return {
                "IP": ip,
                "Port": port,
                "Service": service,
                "Version": banner,
                "OS": os_guess,
                "Details": details,
                "Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        except:
            return None
    
    def run_port_scan(self, ip, ports, current_scan_id):
        results = []
        if self.should_stop_scan(current_scan_id):
            return results
        
        try:
            with ThreadPoolExecutor(max_workers=self.config.MAX_THREADS) as executor:
                self.current_executor = executor
                futures = {}
                
                for port in ports:
                    if self.should_stop_scan(current_scan_id):
                        break
                    future = executor.submit(self.scan_single_port, ip, port, current_scan_id)
                    futures[future] = port
                
                for future in as_completed(futures, timeout=self.config.SCAN_TIMEOUT_PER_HOST):
                    if self.should_stop_scan(current_scan_id):
                        for f in futures:
                            f.cancel()
                        break
                    try:
                        result = future.result(timeout=self.config.SINGLE_PORT_TIMEOUT)
                        if result:
                            results.append(result)
                    except:
                        pass
        except:
            pass
        finally:
            self.current_executor = None
        
        return results
    
    def start_scan(self, ip_range, use_ai=False):
        self.force_stop_scan()
        
        with self.scan_lock:
            self.scan_id += 1
            current_scan_id = self.scan_id
            self.current_scan_progress = 0
            self.scanning = True
            self.scan_start_time = time.time()
            self.scan_error_message = None
        
        try:
            ip_list = self.parse_ip_range(ip_range)
            if not ip_list:
                self.scan_error_message = "Invalid IP range"
                self.scanning = False
                return

            with self.data_lock:
                self.open_ports_data.clear()
                self.live_hosts.clear()
                self.vulnerabilities.clear()
                self.ai_results.clear()

            discovered = []
            for i, ip in enumerate(ip_list):
                if self.should_stop_scan(current_scan_id):
                    self.scan_error_message = "Scan stopped by user"
                    return

                if self.icmp_ping(ip, current_scan_id) or self.tcp_probe_any(ip, current_scan_id):
                    if ip not in self.live_hosts:
                        discovered.append(ip)
                        with self.data_lock:
                            self.live_hosts.append(ip)
                    else:
                        discovered.append(ip)

                self.current_scan_progress = int((i / max(1, len(ip_list))) * 20)

            if not discovered:
                cap = getattr(self.config, "MAX_HOSTS_WHEN_DISCOVERY_EMPTY", 1024)
                if len(ip_list) > cap:
                    self.scan_error_message = (
                        f"No ICMP/TCP discovery replies; scanning first {cap} of {len(ip_list)} addresses. "
                        "Narrow the range for full coverage."
                    )
                    discovered = ip_list[:cap]
                else:
                    self.scan_error_message = (
                        "No ICMP/TCP discovery replies; scanning all addresses in range for open ports."
                    )
                    discovered = list(ip_list)
                for ip in discovered:
                    with self.data_lock:
                        if ip not in self.live_hosts:
                            self.live_hosts.append(ip)
            
            self.current_scan_progress = 20
            
            total_hosts = len(discovered)
            for idx, ip in enumerate(discovered):
                if self.should_stop_scan(current_scan_id):
                    self.scan_error_message = "Scan stopped by user"
                    return
                
                results = self.run_port_scan(ip, self.config.DEFAULT_PORTS, current_scan_id)
                
                with self.data_lock:
                    for r in results:
                        exists = any(p["IP"] == r["IP"] and p["Port"] == r["Port"] for p in self.open_ports_data)
                        if not exists:
                            self.open_ports_data.append(r)
                
                progress = 20 + int((idx + 1) / total_hosts * 60)
                self.current_scan_progress = progress
            
            # ✅ FIXED: فحص الثغرات
            if not self.should_stop_scan(current_scan_id):
                self.current_scan_progress = 80
                vulnerabilities = self.scan_for_vulnerabilities(current_scan_id)
                print(f"✅ Found {len(vulnerabilities)} vulnerabilities")
            
            # ✅ FIXED: تحليل الـ AI
            if not self.should_stop_scan(current_scan_id):
                self.current_scan_progress = 90
                ai_analysis = self.run_ai_analysis()
                print("✅ AI analysis complete")
            
            self.current_scan_progress = 100
        
        except Exception as e:
            self.scan_error_message = f"Error: {str(e)}"
        finally:
            self.scanning = False
            self.scan_start_time = None
    
    def scan_for_vulnerabilities(self, current_scan_id):
        """فحص الثغرات للـ services المكتشفة"""
        print("🔍 Starting vulnerability scanning...")
        
        all_vulnerabilities = []
        
        with self.data_lock:
            ports_data = list(self.open_ports_data)
        
        for port_info in ports_data:
            if self.should_stop_scan(current_scan_id):
                break
            
            service = port_info.get('Service', 'Unknown')
            version = port_info.get('Version', 'Unknown')
            ip = port_info.get('IP', 'Unknown')
            port = port_info.get('Port', 0)
            
            if service == "Unknown" or version == "Unknown":
                continue
            
            try:
                cves = self.cve_checker.search_cve_for_service(service, version)
                
                for cve in cves:
                    cve['target_ip'] = ip
                    cve['target_port'] = port
                    cve['affected_service'] = f"{service} {version}"
                    cve['recommendations'] = self.cve_checker.get_recommendations(cve)
                    all_vulnerabilities.append(cve)
                
                is_vuln, msg = self.cve_checker.check_vulnerable_version(service, version)
                if is_vuln:
                    all_vulnerabilities.append({
                        'cve_id': 'LOCAL-CHECK',
                        'description': msg,
                        'severity': 'HIGH',
                        'cvss_score': 7.5,
                        'target_ip': ip,
                        'target_port': port,
                        'affected_service': f"{service} {version}",
                        'recommendations': self.cve_checker.get_recommendations({'severity': 'HIGH'})
                    })
            
            except Exception as e:
                print(f"❌ Error checking vulnerabilities for {service}: {e}")
        
        with self.data_lock:
            self.vulnerabilities = all_vulnerabilities
        
        print(f"✅ Vulnerability scan complete. Found: {len(all_vulnerabilities)}")
        return all_vulnerabilities
    
    def run_ai_analysis(self):
        """تشغيل تحليل الذكاء الاصطناعي"""
        print("🤖 Running AI analysis...")
        
        with self.data_lock:
            vulnerabilities = list(self.vulnerabilities)
            scan_data = {
                'hosts_count': len(self.live_hosts),
                'ports_count': len(self.open_ports_data),
                'services': list(set([p.get('Service', 'Unknown') for p in self.open_ports_data]))
            }
        
        try:
            ai_result = self.ai_analyzer.analyze_vulnerabilities(vulnerabilities, scan_data)
            
            with self.data_lock:
                if ai_result and ai_result.get('status') == 'success':
                    self.ai_results.append(ai_result)
            
            print("✅ AI analysis complete")
            return ai_result
        
        except Exception as e:
            print(f"❌ AI analysis failed: {e}")
            return {
                'status': 'error',
                'analysis': 'AI analysis unavailable',
                'error': str(e)
            }
    
    def get_vulnerability_summary(self):
        """الحصول على ملخص الثغرات"""
        with self.data_lock:
            vulnerabilities = list(self.vulnerabilities)
        
        if not vulnerabilities:
            return {
                'total': 0,
                'by_severity': {},
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        
        by_severity = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        return {
            'total': len(vulnerabilities),
            'by_severity': by_severity,
            'critical': by_severity.get('CRITICAL', 0),
            'high': by_severity.get('HIGH', 0),
            'medium': by_severity.get('MEDIUM', 0),
            'low': by_severity.get('LOW', 0)
        }
    
    def get_detailed_vulnerabilities(self):
        """الحصول على تفاصيل الثغرات الكاملة"""
        with self.data_lock:
            return list(self.vulnerabilities)
    
    def clear_data(self):
        with self.data_lock:
            self.open_ports_data.clear()
            self.live_hosts.clear()
            self.ai_results.clear()
            self.vulnerabilities.clear()
        self.scan_error_message = None
    
    def get_metrics(self):
        return {
            "hosts": len(self.live_hosts),
            "open_ports": len(self.open_ports_data),
            "ai_findings": len(self.ai_results),
        }

    def get_scan_status_message(self):
        """Last scanner notice (errors or discovery fallback info)."""
        return self.scan_error_message