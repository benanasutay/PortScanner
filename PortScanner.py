import socket
import sys
import threading
import time
import argparse
import json
import struct
import random
import subprocess
import platform
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import re
import os

# --- Core Scanner Engine ---

class PortScanner:
    """Main port scanning engine handling all networking logic."""
    
    def __init__(self):
        self.open_ports = []
        self.scan_results = {}
        self.total_ports = 0
        self.scanned_ports = 0
        self.start_time = None
        self.stop_scan_flag = False
        self.os_estimate = "Unknown (Not Scanned)"
        
        # Common service ports mapping
        self.common_ports = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP",
            993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
            6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB"
        }
        
        # Static Vulnerability Signatures
        self.vulnerability_db = {
            "OpenSSH": {
                "7.2": ["CVE-2016-6210: User enumeration"],
                "7.4": ["CVE-2018-15473: User enumeration"],
            },
            "Apache": {
                "2.4.49": ["CVE-2021-41773: Path traversal & RCE"],
                "2.2": ["End of Life Version: Multiple Vulnerabilities"],
            },
            "vsftpd": {
                "2.3.4": ["Backdoor Command Execution (Smile Face)"],
            },
            "RealVNC": {
                "4.1.1": ["Authentication Bypass"],
            }
        }
    
    def check_vulnerabilities(self, service, version):
        """Cross-reference detected version with the static DB."""
        vulns = []
        if service in self.vulnerability_db:
            for vuln_ver, vuln_list in self.vulnerability_db[service].items():
                if version.startswith(vuln_ver):
                    vulns.extend(vuln_list)
        return vulns

    # --- OS Detection Logic ---

    def detect_os_ttl(self, target_ip):
        """Estimate OS based on ICMP TTL (Time To Live)."""
        try:
            # Determine command based on local OS
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', target_ip]
            
            # Run ping (suppress output)
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = proc.communicate()
            output = out.decode('utf-8', errors='ignore').lower()

            # Parse TTL
            ttl_match = re.search(r'ttl=(\d+)', output)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                # Heuristic Analysis
                if ttl <= 64:
                    return f"Linux/Unix (TTL={ttl})"
                elif ttl <= 128:
                    return f"Windows (TTL={ttl})"
                elif ttl <= 255:
                    return f"Cisco/Network Device (TTL={ttl})"
                else:
                    return f"Unknown (TTL={ttl})"
            else:
                return "Unknown (No TTL response)"
        except Exception:
            return "Unknown (Ping Failed)"

    # --- Raw Socket / SYN Packet Helpers ---
    
    def checksum(self, msg):
        """Calculate IP/TCP checksum."""
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + (msg[i+1] if i+1 < len(msg) else 0)
            s = s + w
        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff
        return s

    def create_syn_packet(self, src_ip, dst_ip, dst_port):
        """Construct a raw TCP SYN packet."""
        try:
            # IP Header
            ip_ihl = 5; ip_ver = 4; ip_tos = 0; ip_tot_len = 0
            ip_id = random.randint(1, 65535); ip_frag_off = 0; ip_ttl = 255
            ip_proto = socket.IPPROTO_TCP; ip_check = 0
            ip_saddr = socket.inet_aton(src_ip); ip_daddr = socket.inet_aton(dst_ip)
            ip_ihl_ver = (ip_ver << 4) + ip_ihl
            
            ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, 
                                    ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, 
                                    ip_saddr, ip_daddr)

            # TCP Header
            tcp_source = random.randint(1024, 65535); tcp_dest = dst_port
            tcp_seq = random.randint(0, 4294967295); tcp_ack_seq = 0
            tcp_doff = 5
            # SYN Flag set
            tcp_flags = 0 + (1 << 1) + (0 << 2) + (0 << 3) + (0 << 4) + (0 << 5)
            tcp_window = socket.htons(5840); tcp_check = 0; tcp_urg_ptr = 0
            
            tcp_offset_res = (tcp_doff << 4) + 0
            tcp_header_part = struct.pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, 
                                          tcp_ack_seq, tcp_offset_res, tcp_flags, 
                                          tcp_window, tcp_check, tcp_urg_ptr)
            
            # Pseudo Header for Checksum
            placeholder = 0; protocol = socket.IPPROTO_TCP
            tcp_length = len(tcp_header_part)
            psh = struct.pack('!4s4sBBH', ip_saddr, ip_daddr, placeholder, protocol, tcp_length)
            psh = psh + tcp_header_part
            
            tcp_check = self.checksum(psh)
            
            # Final TCP Header
            tcp_header = struct.pack('!HHLLBBH', tcp_source, tcp_dest, tcp_seq, 
                                     tcp_ack_seq, tcp_offset_res, tcp_flags, 
                                     tcp_window) + struct.pack('H', tcp_check) + struct.pack('!H', tcp_urg_ptr)
            
            return ip_header + tcp_header
        except Exception:
            return None

    # --- Scanning Methods ---

    def scan_port(self, target, port, timeout=1.0, scan_type="tcp"):
        """Dispatcher for different scan types."""
        if self.stop_scan_flag:
            return None
        
        try:
            if scan_type == "tcp":
                return self._tcp_scan(target, port, timeout)
            elif scan_type == "udp":
                return self._udp_scan(target, port, timeout)
            elif scan_type == "syn":
                return self._syn_scan(target, port, timeout)
            else:
                return self._tcp_scan(target, port, timeout)
        except Exception as e:
            return {"port": port, "status": "error", "error": str(e)}

    def _tcp_scan(self, target, port, timeout):
        """Standard TCP Connect Scan."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            result = s.connect_ex((target, port))
            if result == 0:
                banner_data = self._grab_banner(s, target, port)
                s.close()
                return self._format_result(port, "open", "TCP", banner_data)
            else:
                s.close()
                return {"port": port, "status": "closed"}
        except Exception:
            s.close()
            return {"port": port, "status": "filtered"}

    def _udp_scan(self, target, port, timeout):
        """UDP Probe Scan."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            # Common payloads to trigger response
            payloads = {
                53: b'\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00', # DNS
                123: b'\x1b' + 47 * b'\x00', # NTP
            }
            msg = payloads.get(port, b'Hello')
            s.sendto(msg, (target, port))
            data, _ = s.recvfrom(1024)
            s.close()
            return self._format_result(port, "open", "UDP", {"raw_banner": "UDP Response Received"})
        except socket.timeout:
            s.close()
            return {"port": port, "status": "open|filtered"}
        except Exception:
            s.close()
            return {"port": port, "status": "closed"}

    def _syn_scan(self, target, port, timeout):
        """SYN Scan - Attempts raw socket, falls back to TCP."""
        try:
            if os.name == 'nt':
                # Windows raw sockets are restricted, use TCP Connect for reliability in this tool
                return self._tcp_scan(target, port, timeout)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s.close()
                return self._tcp_scan(target, port, timeout)
        except PermissionError:
            return self._tcp_scan(target, port, timeout)
        except Exception:
            return self._tcp_scan(target, port, timeout)

    # --- Banner Grabbing & Parsing ---

    def _grab_banner(self, sock, target, port):
        """Send probes and read banners."""
        info = {"raw_banner": None, "service_info": {}}
        try:
            # Protocol specific triggers
            if port in [80, 8080, 8000]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            elif port == 21:
                pass # FTP sends banner automatically
            else:
                pass # Wait for generic banner
            
            sock.settimeout(2.0)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            if banner:
                info["raw_banner"] = banner
                # Simple parsing logic
                if "SSH" in banner:
                    info["service_info"] = {"server": "SSH", "version": banner.split('-')[1] if '-' in banner else ""}
                elif "Server:" in banner:
                    # HTTP parsing
                    for line in banner.split('\n'):
                        if "Server:" in line:
                            parts = line.split("Server:")[1].strip().split()
                            if parts:
                                srv = parts[0].split('/')
                                info["service_info"]["server"] = srv[0]
                                if len(srv) > 1: info["service_info"]["version"] = srv[1]
                elif "vsFTPd" in banner:
                     info["service_info"] = {"server": "vsftpd", "version": ""}
        except Exception:
            pass
        return info

    def _format_result(self, port, status, proto, banner_data):
        """Format the found port into a dictionary."""
        service = self.common_ports.get(port, "Unknown")
        vulns = []
        
        details = banner_data.get("service_info", {})
        if details.get("server") and details.get("version"):
            vulns = self.check_vulnerabilities(details["server"], details["version"])
            
        return {
            "port": port,
            "status": status,
            "protocol": proto,
            "service": service,
            "banner": banner_data.get("raw_banner"),
            "vulnerabilities": vulns
        }

    # --- Scanner Runner ---

    def scan_range(self, target, start, end, threads=100, scan_type="tcp", enable_os=False, progress_callback=None):
        """Run the threaded scan."""
        self.start_time = time.time()
        self.total_ports = end - start + 1
        self.scanned_ports = 0
        self.stop_scan_flag = False
        self.open_ports = []
        
        # OS Detection (Only if enabled)
        if enable_os:
            self.os_estimate = self.detect_os_ttl(target)
        else:
            self.os_estimate = "Disabled (Use --os)"
        
        self.scan_results = {
            "target": target, 
            "range": f"{start}-{end}", 
            "type": scan_type,
            "os_detection": self.os_estimate,
            "date": datetime.now().isoformat()
        }

        def worker(p):
            if self.stop_scan_flag: return
            res = self.scan_port(target, p, timeout=1.0, scan_type=scan_type)
            self.scanned_ports += 1
            
            if progress_callback:
                progress_callback(self.scanned_ports, self.total_ports)
                
            if res and res["status"] == "open":
                self.open_ports.append(res)

        with ThreadPoolExecutor(max_workers=threads) as executor:
            for p in range(start, end + 1):
                executor.submit(worker, p)
                
        # Sort results by port number
        self.open_ports.sort(key=lambda x: x["port"])
        return self.open_ports

    def export_json(self, filename):
        """Save results to JSON."""
        data = {
            "meta": self.scan_results,
            "results": self.open_ports
        }
        try:
            with open(filename, "w") as f:
                json.dump(data, f, indent=4)
            return True
        except Exception:
            return False

# --- GUI Implementation ---

class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Port Scanner")
        self.root.geometry("800x600")
        self.scanner = PortScanner()
        self.init_ui()

    def init_ui(self):
        # Settings Frame
        frame_top = ttk.LabelFrame(self.root, text="Configuration", padding=10)
        frame_top.pack(fill="x", padx=10, pady=5)

        ttk.Label(frame_top, text="Target IP:").grid(row=0, column=0, padx=5)
        self.entry_ip = ttk.Entry(frame_top, width=20)
        self.entry_ip.insert(0, "127.0.0.1")
        self.entry_ip.grid(row=0, column=1, padx=5)

        ttk.Label(frame_top, text="Ports (Start-End):").grid(row=0, column=2, padx=5)
        self.entry_start = ttk.Entry(frame_top, width=6)
        self.entry_start.insert(0, "1")
        self.entry_start.grid(row=0, column=3)
        ttk.Label(frame_top, text="-").grid(row=0, column=4)
        self.entry_end = ttk.Entry(frame_top, width=6)
        self.entry_end.insert(0, "1024")
        self.entry_end.grid(row=0, column=5)

        ttk.Label(frame_top, text="Type:").grid(row=0, column=6, padx=5)
        self.combo_type = ttk.Combobox(frame_top, values=["tcp", "udp"], width=6, state="readonly")
        self.combo_type.current(0)
        self.combo_type.grid(row=0, column=7)

        self.btn_start = ttk.Button(frame_top, text="Start Scan", command=self.start_scan)
        self.btn_start.grid(row=0, column=8, padx=10)

        # Progress Bar
        self.progress = ttk.Progressbar(self.root, length=100, mode='determinate')
        self.progress.pack(fill="x", padx=10, pady=5)
        self.lbl_status = ttk.Label(self.root, text="Status: Ready")
        self.lbl_status.pack(pady=2)

        # Output Area
        self.txt_output = scrolledtext.ScrolledText(self.root, height=20)
        self.txt_output.pack(fill="both", expand=True, padx=10, pady=5)

        # Export Button
        ttk.Button(self.root, text="Export Results (JSON)", command=self.export_results).pack(pady=5)

    def start_scan(self):
        ip = self.entry_ip.get()
        try:
            start = int(self.entry_start.get())
            end = int(self.entry_end.get())
        except ValueError:
            messagebox.showerror("Error", "Ports must be integers.")
            return

        self.btn_start.config(state="disabled")
        self.txt_output.delete(1.0, tk.END)
        self.lbl_status.config(text="Status: Scanning...")
        
        threading.Thread(target=self.run_scan_thread, args=(ip, start, end), daemon=True).start()

    def run_scan_thread(self, ip, start, end):
        scan_type = self.combo_type.get()
        # GUI does OS detection by default for better UX
        self.scanner.scan_range(
            ip, start, end, 
            threads=100, 
            scan_type=scan_type,
            enable_os=True, 
            progress_callback=self.update_progress
        )
        self.root.after(0, self.finish_scan)

    def update_progress(self, scanned, total):
        # Update UI from thread
        val = (scanned / total) * 100
        self.root.after(0, lambda: self.progress.configure(value=val))

    def finish_scan(self):
        self.btn_start.config(state="normal")
        self.lbl_status.config(text=f"Status: Complete. Found {len(self.scanner.open_ports)} open ports.")
        
        # Header Info
        header = f"{'='*40}\n"
        header += f"SCAN REPORT FOR: {self.entry_ip.get()}\n"
        header += f"OS ESTIMATE: {self.scanner.os_estimate}\n"
        header += f"{'='*40}\n"
        self.txt_output.insert(tk.END, header)
        
        for res in self.scanner.open_ports:
            msg = f"[+] {res['port']}/{res['protocol']} OPEN - {res['service']}\n"
            if res.get("banner"):
                msg += f"    Banner: {res['banner']}\n"
            if res.get("vulnerabilities"):
                for v in res["vulnerabilities"]:
                    msg += f"    [!] VULNERABILITY: {v}\n"
            self.txt_output.insert(tk.END, msg + "\n")

    def export_results(self):
        f = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
        if f:
            if self.scanner.export_json(f):
                messagebox.showinfo("Success", "Export successful.")
            else:
                messagebox.showerror("Error", "Failed to export.")

# --- CLI / Main Entry Point ---

def run_cli():
    parser = argparse.ArgumentParser(
        description="Advanced Python Port Scanner (CLI & GUI)",
        epilog="Examples:\n  py PortScanner.py 192.168.1.1 --os\n  py PortScanner.py 127.0.0.1 -p 1-100 -t 50\n  py PortScanner.py --gui",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("target", nargs="?", help="Target IP address (e.g. 192.168.1.1)")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of concurrent threads (default: 100)")
    parser.add_argument("-s", "--scan-type", choices=["tcp", "udp", "syn"], default="tcp", help="Type of scan (tcp/udp/syn)")
    parser.add_argument("--os", action="store_true", help="Enable OS Detection (TTL-based)")
    parser.add_argument("-o", "--output", help="Save results to a JSON file")
    parser.add_argument("--gui", action="store_true", help="Force launch Graphical User Interface")

    args = parser.parse_args()

    # Determine mode: GUI or CLI
    if args.gui or not args.target:
        print("[*] Launching GUI Mode...")
        root = tk.Tk()
        app = ScannerGUI(root)
        root.mainloop()
    else:
        # CLI Mode
        try:
            start_p, end_p = map(int, args.ports.split('-'))
        except ValueError:
            print("[-] Error: Ports must be in format 'start-end' (e.g., 1-1000)")
            sys.exit(1)

        print(f"\n{'-'*60}")
        print(f" TARGET   : {args.target}")
        print(f" PORTS    : {start_p} to {end_p}")
        print(f" THREADS  : {args.threads}")
        print(f" TYPE     : {args.scan_type.upper()}")
        print(f" OS DETECT: {'Enabled' if args.os else 'Disabled'}")
        print(f"{'-'*60}\n")
        print("[*] Scanning started... Please wait.")

        scanner = PortScanner()
        
        # Simple progress bar for CLI
        def cli_progress(scanned, total):
            percent = (scanned / total) * 100
            bar_length = 30
            filled_length = int(bar_length * scanned // total)
            bar = '█' * filled_length + '-' * (bar_length - filled_length)
            sys.stdout.write(f'\rProgress: |{bar}| {percent:.1f}%')
            sys.stdout.flush()

        t_start = time.time()
        scanner.scan_range(
            args.target, start_p, end_p, 
            threads=args.threads, 
            scan_type=args.scan_type,
            enable_os=args.os,
            progress_callback=cli_progress
        )
        t_end = time.time()

        print(f"\n\n{'='*60}")
        print(f"SCAN REPORT FOR {args.target}")
        if args.os:
            print(f"OS ESTIMATE: {scanner.os_estimate}")
        print(f"Time Elapsed: {t_end - t_start:.2f} seconds")
        print(f"{'='*60}")

        if not scanner.open_ports:
            print("No open ports found.")
        else:
            print(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<15} {'INFO'}")
            print("-" * 60)
            for res in scanner.open_ports:
                banner = res.get('banner', '')
                if banner:
                    # Truncate banner for clean CLI output
                    banner = (banner[:30] + '..') if len(banner) > 30 else banner
                else:
                    banner = ""
                
                print(f"{res['port']}/{res['protocol']:<5} {res['status'].upper():<10} {res['service']:<15} {banner}")
                
                if res.get("vulnerabilities"):
                    for v in res["vulnerabilities"]:
                        print(f"    [!] VULNERABILITY DETECTED: {v}")

        if args.output:
            if scanner.export_json(args.output):
                print(f"\n[+] Results saved to: {args.output}")
            else:
                print(f"\n[-] Failed to save results.")

if __name__ == "__main__":
    run_cli()