import socket
import re
import json
import datetime
import os
import sys
import time
import concurrent.futures
import subprocess
from ipaddress import ip_address
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Any

RED = "\033[31m"
BOLD_RED = "\033[1;31m"
RESET = "\033[0m"

def show_banner():
    ascii_art = r"""
   ___________   .__.__  .__             .___    _____                .__                              
  /   _____/  | _|__|  | |  |   ____   __| _/   /  _  \   ____ _____  |  | ___.__.________ ___________ 
  \_____  \|  |/ /  |  | |  | _/ __ \ / __ |   /  /_\  \ /    \\__  \ |  |<   |  |\___   // __ \_  __ \
  /        \    <|  |  |_|  |_\  ___// /_/ |  /    |    \   |  \/ __ \|  |_\___  | /    /\  ___/|  | \/
 /_______  /__|_ \__|____/____/\___  >____ |  \____|__  /___|  (____  /____/ ____|/_____ \\___  >__|   
         \/     \/                 \/     \/          \/     \/     \/     \/           \/    \/
"""
    # 256-color ANSI sequence for red-to-dark-red gradient (Red Tiger style)
    # 196: Bright Red, 160: Mid Red, 124: Darker Red, 88: Deep Dark Red
    red_shades = [196, 160, 124, 88]
    lines = [line for line in ascii_art.splitlines() if line.strip()]
    
    for line in lines:
        colored_line = ""
        length = len(line)
        for i, ch in enumerate(line):
            if ch == " ":
                colored_line += " "
                continue
            # Map character position across the line to the red shades spectrum
            shade_idx = min(int((i / max(length, 1)) * len(red_shades)), len(red_shades) - 1)
            color_code = red_shades[shade_idx]
            colored_line += f"\033[38;5;{color_code}m{ch}\033[0m"
        print(colored_line)
    print()

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def print_menu():
    print(BOLD_RED + "╔══════════════════════════════════════╗" + RESET)
    print(BOLD_RED + "║        THREAT ANALYZER MENU          ║" + RESET)
    print(BOLD_RED + "║         Made By SkillOnly            ║" + RESET)
    print(BOLD_RED + "╚══════════════════════════════════════╝" + RESET)
    print(RED + "  \033[33m1\033[0m" + RED + ". Network Scanner (socket)" + RESET)
    print(RED + "  \033[33m2\033[0m" + RED + ". Network Scanner (nmap) - advanced" + RESET)
    print(RED + "  \033[33m3\033[0m" + RED + ". Log Analyzer" + RESET)
    print(RED + "  \033[33m4\033[0m" + RED + ". Config Security Linter" + RESET)
    print(RED + "  \033[33m5\033[0m" + RED + ". DDoS / DoS Attack Detector" + RESET)
    print(RED + "  \033[33m6\033[0m" + RED + ". Run All (Full Audit)" + RESET)
    print(RED + "  \033[33m7\033[0m" + RED + ". Exit" + RESET)
    print()

def check_dependencies():
    missing = []
    if not os.system("which nmap > /dev/null 2>&1") == 0:
        missing.append("nmap")
    if not os.system("which tshark > /dev/null 2>&1") == 0:
        missing.append("tshark (part of wireshark)")
    if missing:
        print(RED + "[WARNING] Missing tools:" + RESET, ", ".join(missing))
        print("Install with: sudo apt install nmap wireshark")
        print()

class NetworkScanner:
    def __init__(self, start_ip: str, end_ip: str, ports: List[int] = None, timeout: float = 1.0):
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        self.start_ip = start_ip
        self.end_ip = end_ip
        self.ports = ports
        self.timeout = timeout
        self.active_hosts = {}
        self.scan_results = []
        self.is_single_ip = (start_ip == end_ip)

    def _ip_range(self):
        try:
            start = int(ip_address(self.start_ip))
            end = int(ip_address(self.end_ip))
            if start > end:
                start, end = end, start
            return [str(ip_address(ip_int)) for ip_int in range(start, end + 1)]
        except:
            return []

    def _scan_port(self, ip: str, port: int) -> Optional[Dict]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    service = self._banner_grab(ip, port)
                    return {"ip": ip, "port": port, "state": "open", "service": service}
        except Exception:
            pass
        return None

    def _banner_grab(self, ip: str, port: int) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2.0)
                sock.connect((ip, port))
                if port in [21, 22, 23, 25, 110, 143, 443, 993, 995]:
                    sock.send(b"\r\n")
                elif port == 80:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                elif port == 3306:
                    sock.send(b"\x00\x00\x00\x00\x01\x00\x00\x00\x00")
                banner = sock.recv(1024).decode(errors='ignore').strip().split('\n')[0]
                return banner[:80]
        except:
            pass
        return "unknown"

    def run(self):
        ips = self._ip_range()
        if not ips:
            print("Invalid IP range.")
            return []
        self.active_hosts = {}
        self.scan_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ip = {executor.submit(self._scan_ip, ip): ip for ip in ips}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    if result:
                        self.active_hosts[ip] = result
                except:
                    continue
        for ip, open_ports in self.active_hosts.items():
            for port_info in open_ports:
                self.scan_results.append(port_info)
        return self.scan_results

    def _scan_ip(self, ip: str) -> List[Dict]:
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {executor.submit(self._scan_port, ip, port): port for port in self.ports}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    res = future.result()
                    if res:
                        results.append(res)
                except:
                    pass
        return results

    def print_results(self):
        if not self.scan_results:
            print("No open ports found.")
            return
        print("\n" + BOLD_RED + "=== Scan Results ===" + RESET)
        print(f"IP Range: {self.start_ip} - {self.end_ip}")
        print(f"Active hosts: {len(self.active_hosts)}")
        print("\nOpen ports:")
        print(f"{'IP Address':<20} {'Port':<6} {'Service'}")
        print("-" * 50)
        for entry in self.scan_results:
            print(f"{entry['ip']:<20} {entry['port']:<6} {entry['service']}")
        print()

    def generate_markdown_report(self):
        if not self.scan_results:
            return None
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{timestamp}.md"
        with open(filename, 'w') as f:
            f.write("# Network Scan Report\n\n")
            if self.is_single_ip:
                f.write(f"**Target IP:** {self.start_ip} ** (Not 100% Accurate) **\n")
            else:
                f.write(f"**IP Range:** {self.start_ip} - {self.end_ip}\n")
            f.write(f"**Scan Time:** {datetime.datetime.now().isoformat()}\n")
            f.write(f"**Active Hosts Found:** {len(self.active_hosts)}\n\n")
            f.write("## Open Ports & Services\n\n")
            f.write("| IP Address | Port | Service |\n")
            f.write("|------------|------|---------|\n")
            for entry in self.scan_results:
                f.write(f"| {entry['ip']} | {entry['port']} | {entry['service']} |\n")
        return filename

class LogAnalyzer:
    def __init__(self, log_file: str = None, log_type: str = "auth"):
        self.log_file = log_file
        self.log_type = log_type
        self.failed_attempts = defaultdict(int)
        self.ip_timeline = defaultdict(list)
        self.suspicious_ips = {}
        self.summary = {}

    def run(self) -> Dict:
        if not self.log_file or not os.path.exists(self.log_file):
            return {"error": "Log file not found"}
        self._parse_logs()
        self._detect_bruteforce()
        self._generate_summary()
        return self.summary

    def _parse_logs(self):
        with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if self.log_type == "auth":
                    match = re.search(r'Failed password for .+ from (\d+\.\d+\.\d+\.\d+) port (\d+)', line)
                    if match:
                        ip = match.group(1)
                        self.failed_attempts[ip] += 1
                        self.ip_timeline[ip].append((time.time(), line.strip()))
                elif self.log_type == "nginx":
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+) - - \[.*?\] ".*?" (\d{3})', line)
                    if match:
                        ip = match.group(1)
                        status = int(match.group(2))
                        if status >= 400:
                            self.failed_attempts[ip] += 1
                            self.ip_timeline[ip].append((time.time(), line.strip()))
                elif self.log_type == "generic":
                    ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                    if ip_matches:
                        for ip in ip_matches:
                            self.failed_attempts[ip] += 1
                            self.ip_timeline[ip].append((time.time(), line.strip()))

    def _detect_bruteforce(self, threshold: int = 5, window_seconds: int = 300):
        now = time.time()
        for ip, events in self.ip_timeline.items():
            if len(events) < threshold:
                continue
            recent = [ts for ts, _ in events if now - ts <= window_seconds]
            if len(recent) >= threshold:
                self.suspicious_ips[ip] = {
                    "total_attempts": len(events),
                    "recent_attempts": len(recent),
                    "window_seconds": window_seconds,
                    "threshold": threshold
                }

    def _generate_summary(self):
        self.summary = {
            "analyzed_file": self.log_file,
            "log_type": self.log_type,
            "total_failed_attempts": sum(self.failed_attempts.values()),
            "unique_ips": len(self.failed_attempts),
            "top_offenders": sorted(self.failed_attempts.items(), key=lambda x: x[1], reverse=True)[:10],
            "suspicious_ips": self.suspicious_ips,
            "scan_time": datetime.datetime.now().isoformat()
        }

    def export_json(self, filename: str = "log_analysis.json"):
        with open(filename, 'w') as f:
            json.dump(self.summary, f, indent=2)
        return filename

class ConfigLinter:
    def __init__(self, target_dir: str = "."):
        self.target_dir = target_dir
        self.issues = []

    def run(self) -> List[Dict]:
        self.issues = []
        for root, dirs, files in os.walk(self.target_dir):
            for file in files:
                full_path = os.path.join(root, file)
                if file == "sshd_config" or file.endswith("_config"):
                    self._check_ssh_config(full_path)
                elif file == "Dockerfile" or file == "dockerfile":
                    self._check_dockerfile(full_path)
                elif file.endswith(".env") or file == ".env":
                    self._check_env_file(full_path)
                elif file.endswith(".conf") or file.endswith(".cfg"):
                    self._check_generic_conf(full_path)
        return self.issues

    def _check_ssh_config(self, path: str):
        try:
            with open(path, 'r') as f:
                content = f.read()
            if re.search(r'PermitRootLogin\s+yes', content, re.I):
                self.issues.append({"file": path, "type": "SSH", "severity": "HIGH", "issue": "PermitRootLogin yes enabled"})
            if re.search(r'PasswordAuthentication\s+yes', content, re.I):
                self.issues.append({"file": path, "type": "SSH", "severity": "MEDIUM", "issue": "PasswordAuthentication yes enabled"})
            if not re.search(r'AllowUsers|AllowGroups', content):
                self.issues.append({"file": path, "type": "SSH", "severity": "LOW", "issue": "No user/group restrictions"})
        except:
            pass

    def _check_dockerfile(self, path: str):
        try:
            with open(path, 'r') as f:
                content = f.read()
            if re.search(r'USER\s+root', content, re.I):
                self.issues.append({"file": path, "type": "Docker", "severity": "HIGH", "issue": "Container runs as root"})
            if re.search(r'ADD\s+https?://', content):
                self.issues.append({"file": path, "type": "Docker", "severity": "MEDIUM", "issue": "Insecure download via ADD from HTTP"})
            if re.search(r'ENV\s+.*SECRET|PASSWORD|KEY', content, re.I):
                self.issues.append({"file": path, "type": "Docker", "severity": "HIGH", "issue": "Hardcoded secret in environment"})
        except:
            pass

    def _check_env_file(self, path: str):
        try:
            with open(path, 'r') as f:
                content = f.read()
            secrets = re.findall(r'(API_KEY|SECRET|PASSWORD|TOKEN|KEY)\s*=\s*["\']?([^"\'\s]+)["\']?', content, re.I)
            for key, value in secrets:
                if len(value) > 4:
                    self.issues.append({"file": path, "type": "Env", "severity": "HIGH", "issue": f"Hardcoded secret: {key}"})
            if re.search(r'DEBUG\s*=\s*True', content, re.I):
                self.issues.append({"file": path, "type": "Env", "severity": "MEDIUM", "issue": "Debug mode enabled in production"})
        except:
            pass

    def _check_generic_conf(self, path: str):
        try:
            with open(path, 'r') as f:
                content = f.read()
            if re.search(r'password\s*=\s*[\'"]?\w+[\'"]?', content, re.I):
                self.issues.append({"file": path, "type": "Config", "severity": "HIGH", "issue": "Potential hardcoded password"})
        except:
            pass

    def print_report(self):
        if not self.issues:
            print("No configuration issues found.")
            return
        print(f"Found {len(self.issues)} configuration issues:")
        for issue in self.issues:
            print(f"  [{issue['severity']}] {issue['file']} - {issue['issue']}")

class ReportAggregator:
    @staticmethod
    def combine(scanner_results: Dict, log_results: Dict, lint_results: List[Dict], output_file: str = "full_report.json"):
        report = {
            "scan": scanner_results,
            "log_analysis": log_results,
            "config_linter": lint_results,
            "generated": datetime.datetime.now().isoformat()
        }
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        return output_file

def run_nmap_scan():
    print("\n\033[1mNmap Advanced Scanner\033[0m")
    if not os.system("which nmap > /dev/null 2>&1") == 0:
        print("nmap is not installed. Install with: sudo apt install nmap")
        input("\nPress Enter to return...")
        return

    print("Select scan type:")
    print("  1. Single IP")
    print("  2. IP Range")
    choice = input("Enter 1 or 2: ").strip()
    if choice == "1":
        target = input("Enter IP address: ").strip()
        if not target:
            print("Invalid input.")
            return
    elif choice == "2":
        start = input("Enter start IP: ").strip()
        end = input("Enter end IP: ").strip()
        if not start or not end:
            print("Invalid input.")
            return
        target = f"{start}-{end}"
    else:
        print("Invalid choice.")
        return

    print("Running nmap -A (OS, service, version detection)... This may take several minutes.")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    xml_file = f"nmap_scan_{timestamp}.xml"
    cmd = ["nmap", "-A", target, "-oX", xml_file]
    try:
        subprocess.run(cmd, check=True)
        print(f"Scan complete. Results saved to {xml_file}")
        print("You can view with: xsltproc {} -o nmap_report.html".format(xml_file))
    except subprocess.CalledProcessError:
        print("nmap scan failed.")
    input("\nPress Enter to return to menu...")

def run_attack_detector():
    print("\n\033[1mDDoS / DoS Attack Detector\033[0m")
    if not os.system("which tshark > /dev/null 2>&1") == 0:
        print("tshark (Wireshark) is not installed.")
        print("Install with: sudo apt install wireshark")
        print("\nFalling back to connection count analysis using netstat...")
        detect_dos_netstat()
        input("\nPress Enter to return to menu...")
        return

    print("This will capture packets for 30 seconds to detect flood patterns.")
    print("Make sure you have permission to capture (you may need to run with sudo).")
    interface = input("Enter network interface (default: any): ").strip() or "any"
    duration = input("Capture duration in seconds (default 30): ").strip()
    if duration.isdigit():
        duration = int(duration)
    else:
        duration = 30

    print(f"Capturing on {interface} for {duration} seconds...")
    cmd = [
        "tshark", "-i", interface, "-a", f"duration:{duration}",
        "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.flags.syn",
        "-e", "udp", "-e", "frame.len", "-e", "tcp.len",
        "-Y", "ip or ip6"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration+5)
        lines = result.stdout.strip().split('\n')
        if not lines or lines == ['']:
            print("No packets captured. Try a different interface or run with sudo.")
            input("\nPress Enter to return...")
            return

        packet_count = defaultdict(int)
        syn_count = defaultdict(int)
        total_bytes = defaultdict(int)
        for line in lines:
            parts = line.split('\t')
            if len(parts) >= 1:
                src = parts[0]
                packet_count[src] += 1
                if len(parts) >= 3 and parts[2] == '1':
                    syn_count[src] += 1
                if len(parts) >= 4 and parts[3].isdigit():
                    total_bytes[src] += int(parts[3])

        total_packets = sum(packet_count.values())
        avg_packet_rate = total_packets / duration

        print("\n\033[1m=== Traffic Analysis ===\033[0m")
        print(f"Total packets captured: {total_packets}")
        print(f"Average packet rate: {avg_packet_rate:.2f} packets/second")
        print("\nTop source IPs by packet count:")
        for ip, count in sorted(packet_count.items(), key=lambda x: x[1], reverse=True)[:10]:
            rate = count / duration
            syn = syn_count.get(ip, 0)
            bytes_sent = total_bytes.get(ip, 0)
            print(f"  {ip}: {count} packets ({rate:.2f}/s), {syn} SYN packets, {bytes_sent} bytes")

        threshold = max(3.0, avg_packet_rate * 5)
        suspicious = [ip for ip, cnt in packet_count.items() if (cnt / duration) > threshold and ip != '0.0.0.0']
        if suspicious:
            print("\n\033[31m[!] Potential DoS/DDoS suspects (packet rate > {threshold:.2f}/s):\033[0m")
            for ip in suspicious:
                print(f"  {ip}: {packet_count[ip]/duration:.2f} packets/s, {syn_count.get(ip,0)} SYN packets")
        else:
            print("\nNo suspicious activity detected (based on packet rate).")

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"ddos_report_{timestamp}.json"
        report = {
            "timestamp": datetime.datetime.now().isoformat(),
            "interface": interface,
            "duration": duration,
            "total_packets": total_packets,
            "avg_rate": avg_packet_rate,
            "top_ips": [{"ip": ip, "packets": cnt, "rate": cnt/duration, "syn": syn_count.get(ip,0), "bytes": total_bytes.get(ip,0)}
                        for ip, cnt in sorted(packet_count.items(), key=lambda x: x[1], reverse=True)[:20]],
            "suspicious_ips": suspicious
        }
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\nDetailed report saved to {report_file}")

    except subprocess.TimeoutExpired:
        print("Capture timed out.")
    except Exception as e:
        print(f"Error during capture: {e}")
        print("Try running with sudo or check interface.")
    input("\nPress Enter to return to menu...")

def detect_dos_netstat():
    print("\n[Fallback] Analyzing current network connections...")
    try:
        result = subprocess.run(["ss", "-tun"], capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')[1:]  # skip header
        conn_count = defaultdict(int)
        for line in lines:
            parts = line.split()
            if len(parts) >= 5:
                state = parts[0]
                src = parts[4].split(':')[0]
                if src != '0.0.0.0' and src != '::':
                    conn_count[src] += 1
        print("\nTop IPs by active connections:")
        for ip, count in sorted(conn_count.items(), key=lambda x: x[1], reverse=True)[:15]:
            print(f"  {ip}: {count} connections")
        high = [ip for ip, cnt in conn_count.items() if cnt > 20]
        if high:
            print("\n\033[31m[!] High connection counts detected (possible DoS):\033[0m")
            for ip in high:
                print(f"  {ip}: {conn_count[ip]} connections")
        else:
            print("No excessive connections detected.")
    except Exception as e:
        print(f"Error: {e}")

def run_network_scanner():
    print("\n\033[1mNetwork Scanner (Socket)\033[0m")
    print("Select scan type:")
    print("  1. Single IP (scan one host) - (Not 100% Accurate)")
    print("  2. IP Range (scan multiple hosts)")
    choice = input("Enter 1 or 2: ").strip()
    if choice == "1":
        ip = input("Enter IP address (e.g., 192.168.1.100): ").strip()
        if not ip:
            print("Invalid IP. Returning to menu.")
            return
        start = end = ip
    elif choice == "2":
        start = input("Enter start IP (e.g., 192.168.1.1): ").strip()
        end = input("Enter end IP (e.g., 192.168.1.254): ").strip()
        if not start or not end:
            print("Invalid input. Returning to menu.")
            return
    else:
        print("Invalid choice. Returning to menu.")
        return

    ports_input = input("Enter ports (comma separated, default common ports): ").strip()
    if ports_input:
        ports = [int(p.strip()) for p in ports_input.split(',') if p.strip().isdigit()]
    else:
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

    scanner = NetworkScanner(start_ip=start, end_ip=end, ports=ports)
    print("Scanning... This may take a while.")
    scan_data = scanner.run()
    if not scan_data:
        print("No open ports found or invalid range.")
    else:
        scanner.print_results()
        md_file = scanner.generate_markdown_report()
        if md_file:
            print(f"Report saved to {md_file}")
    input("\nPress Enter to return to menu...")

def run_log_analyzer():
    print("\n\033[1mLog Analyzer\033[0m")
    log_file = input("Enter path to log file (default /var/log/auth.log): ").strip() or "/var/log/auth.log"
    log_type = input("Enter log type (auth/nginx/generic, default auth): ").strip() or "auth"
    analyzer = LogAnalyzer(log_file=log_file, log_type=log_type)
    print("Analyzing logs...")
    log_data = analyzer.run()
    if "error" in log_data:
        print(f"Error: {log_data['error']}")
    else:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        json_file = f"log_analysis_{timestamp}.json"
        analyzer.export_json(filename=json_file)
        print(f"Analysis complete. JSON saved to {json_file}")
        print(f"Total failed attempts: {log_data.get('total_failed_attempts', 0)}")
        print(f"Suspicious IPs detected: {len(log_data.get('suspicious_ips', {}))}")
    input("\nPress Enter to return to menu...")

def run_config_linter():
    print("\n\033[1mConfig Security Linter\033[0m")
    target_dir = input("Enter directory to scan (default .): ").strip() or "."
    linter = ConfigLinter(target_dir=target_dir)
    print("Linting configuration files...")
    issues = linter.run()
    linter.print_report()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = f"lint_report_{timestamp}.json"
    with open(json_file, 'w') as f:
        json.dump(issues, f, indent=2)
    print(f"Detailed report saved to {json_file}")
    input("\nPress Enter to return to menu...")

def run_all():
    print("\n\033[1mRunning Full Audit (All Tools)\033[0m")
    print("\n--- Network Scanner ---")
    print("Select scan type:")
    print("  1. Single IP")
    print("  2. IP Range")
    choice = input("Enter 1 or 2: ").strip()
    if choice == "1":
        ip = input("Enter IP address: ").strip()
        if not ip:
            print("Invalid IP. Skipping network scan.")
            start = end = None
        else:
            start = end = ip
    elif choice == "2":
        start = input("Enter start IP: ").strip()
        end = input("Enter end IP: ").strip()
        if not start or not end:
            print("Invalid input. Skipping network scan.")
            start = end = None
    else:
        print("Invalid choice. Skipping network scan.")
        start = end = None

    if start and end:
        scanner = NetworkScanner(start_ip=start, end_ip=end)
        print("Scanning network...")
        scan_data = scanner.run()
        scanner.print_results()
        md_file = scanner.generate_markdown_report()
        if md_file:
            print(f"Scan report saved to {md_file}")
        scanner_results = {"hosts": len(scanner.active_hosts), "open_entries": len(scan_data), "report_file": md_file}
    else:
        scanner_results = {}

    print("\n--- Log Analyzer ---")
    log_file = input("Enter path to log file (default /var/log/auth.log): ").strip() or "/var/log/auth.log"
    log_type = input("Enter log type (auth/nginx/generic, default auth): ").strip() or "auth"
    analyzer = LogAnalyzer(log_file=log_file, log_type=log_type)
    print("Analyzing logs...")
    log_data = analyzer.run()
    if "error" in log_data:
        print(f"Error: {log_data['error']}")
        log_results = {}
    else:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        json_file = f"log_analysis_{timestamp}.json"
        analyzer.export_json(filename=json_file)
        print(f"Analysis complete. JSON saved to {json_file}")
        log_results = log_data

    print("\n--- Config Linter ---")
    target_dir = input("Enter directory to scan for configs (default .): ").strip() or "."
    linter = ConfigLinter(target_dir=target_dir)
    print("Linting configuration files...")
    issues = linter.run()
    linter.print_report()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = f"lint_report_{timestamp}.json"
    with open(json_file, 'w') as f:
        json.dump(issues, f, indent=2)
    print(f"Lint report saved to {json_file}")

    if scanner_results and log_results and issues:
        combined_file = f"full_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        ReportAggregator.combine(scanner_results, log_results, issues, combined_file)
        print(f"\nFull audit complete. Combined report saved to {combined_file}")
    else:
        print("\nFull audit completed with partial data. Check individual reports.")
    input("\nPress Enter to return to menu...")

def main():
    check_dependencies()
    while True:
        clear_screen()
        show_banner()
        print_menu()
        choice = input("Select an option (1-7): ").strip()
        if choice == "1":
            run_network_scanner()
        elif choice == "2":
            run_nmap_scan()
        elif choice == "3":
            run_log_analyzer()
        elif choice == "4":
            run_config_linter()
        elif choice == "5":
            run_attack_detector()
        elif choice == "6":
            run_all()
        elif choice == "7":
            print("Exiting SKILL ANALYZER. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter a number from 1 to 7.")
            time.sleep(1)

if __name__ == "__main__":
    main()
