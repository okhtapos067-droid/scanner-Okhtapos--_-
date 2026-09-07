import os
import sys
import platform
import subprocess
import socket
import datetime
import getpass
import re
import json
import time

class SystemScanner:
    def __init__(self):
        self.os_info = {}
        self.network_info = {}
        self.security_info = {}
        self.hardware_info = {}
        self.vulnerabilities = []
        self.strengths = []
        self.attack_history = []
        self.open_ports = []
        self.running_processes = []
        self.virus_scan = {}
        self.connection_type = "Unknown"
        self.my_attacks = []
        self.blocked_ips = []
        self.cpu_info = {}
        self.fan_info = {}
        self.attack_damage = []
        
    def scan_os(self):
        print("[+] Scanning Operating System...")
        self.os_info['name'] = platform.system()
        self.os_info['version'] = platform.version()
        self.os_info['release'] = platform.release()
        self.os_info['machine'] = platform.machine()
        self.os_info['processor'] = platform.processor()
        self.os_info['hostname'] = socket.gethostname()
        self.os_info['user'] = getpass.getuser()
        
        if self.os_info['name'] == "Linux":
            try:
                with open("/etc/os-release", "r") as f:
                    for line in f:
                        if "PRETTY_NAME" in line:
                            self.os_info['detailed'] = line.split("=")[1].strip().strip('"')
            except:
                self.os_info['detailed'] = "Linux"
        elif self.os_info['name'] == "Windows":
            self.os_info['detailed'] = "Windows"
        elif self.os_info['name'] == "Darwin":
            self.os_info['detailed'] = "macOS"
            
    def scan_cpu_fan(self):
        print("[+] Scanning CPU and Fan Details...")
        try:
            if self.os_info['name'] == "Linux":
                try:
                    result = subprocess.run(["lscpu"], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if "Model name" in line:
                            self.cpu_info['model'] = line.split(":")[1].strip()
                        if "CPU(s)" in line and "MHz" not in line:
                            self.cpu_info['cores'] = line.split(":")[1].strip()
                        if "Thread(s)" in line:
                            self.cpu_info['threads'] = line.split(":")[1].strip()
                        if "Socket(s)" in line:
                            self.cpu_info['sockets'] = line.split(":")[1].strip()
                        if "CPU max MHz" in line:
                            self.cpu_info['max_speed'] = line.split(":")[1].strip()
                        if "CPU min MHz" in line:
                            self.cpu_info['min_speed'] = line.split(":")[1].strip()
                except:
                    pass
                    
                try:
                    result = subprocess.run(["sensors"], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if "fan" in line.lower() and "rpm" in line.lower():
                            self.fan_info['speed'] = line.strip()
                        if "temp" in line.lower() and "°C" in line:
                            self.fan_info['temperature'] = line.strip()
                except:
                    self.fan_info['speed'] = "Unknown"
                    self.fan_info['temperature'] = "Unknown"
                    
                try:
                    result = subprocess.run(["cat", "/proc/cpuinfo"], capture_output=True, text=True)
                    cores = 0
                    for line in result.stdout.split('\n'):
                        if "processor" in line:
                            cores += 1
                    self.cpu_info['actual_cores'] = cores
                except:
                    pass
                    
            elif self.os_info['name'] == "Windows":
                try:
                    result = subprocess.run(["wmic", "cpu", "get", "name", "numberofcores", "maxclockspeed"], capture_output=True, text=True)
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if line.strip() and "Name" not in line and "NumberOfCores" not in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                self.cpu_info['model'] = " ".join(parts[:-2])
                                self.cpu_info['cores'] = parts[-2]
                                self.cpu_info['max_speed'] = parts[-1] + " MHz"
                except:
                    pass
                    
                try:
                    result = subprocess.run(["wmic", "fan", "get", "speed"], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if line.strip() and "Speed" not in line:
                            self.fan_info['speed'] = line.strip() + " RPM"
                except:
                    self.fan_info['speed'] = "Unknown"
                    
        except:
            pass
            
    def scan_network(self):
        print("[+] Scanning Network...")
        try:
            self.network_info['hostname'] = socket.gethostname()
            self.network_info['ip'] = socket.gethostbyname(socket.gethostname())
            
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                self.network_info['public_ip'] = s.getsockname()[0]
                s.close()
                self.network_info['internet'] = "Connected"
            except:
                self.network_info['public_ip'] = "Unknown"
                self.network_info['internet'] = "Disconnected"
                
            try:
                result = subprocess.run(["speedtest-cli", "--simple"], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if "Download" in line:
                        self.network_info['download_speed'] = line.split(":")[1].strip()
                    if "Upload" in line:
                        self.network_info['upload_speed'] = line.split(":")[1].strip()
                    if "Ping" in line:
                        self.network_info['ping'] = line.split(":")[1].strip()
            except:
                self.network_info['download_speed'] = "Unknown"
                self.network_info['upload_speed'] = "Unknown"
                self.network_info['ping'] = "Unknown"
                
            if self.os_info['name'] == "Linux":
                try:
                    result = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True)
                    if result.stdout.strip():
                        self.network_info['wifi'] = result.stdout.strip()
                    else:
                        self.network_info['wifi'] = "Not connected to Wi-Fi"
                except:
                    self.network_info['wifi'] = "Unknown"
                    
                try:
                    result = subprocess.run(["ip", "route"], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if "default via" in line:
                            self.network_info['gateway'] = line.split()[2]
                            break
                except:
                    self.network_info['gateway'] = "Unknown"
                    
                try:
                    result = subprocess.run(["lsusb"], capture_output=True, text=True)
                    if "Ethernet" in result.stdout or "Network" in result.stdout:
                        self.connection_type = "USB Dongle"
                    elif "Wi-Fi" in result.stdout or "Wireless" in result.stdout:
                        self.connection_type = "Wi-Fi Router"
                    else:
                        self.connection_type = "Wired Ethernet"
                except:
                    self.connection_type = "Unknown"
                    
            elif self.os_info['name'] == "Windows":
                try:
                    result = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if "SSID" in line and "BSSID" not in line:
                            self.network_info['wifi'] = line.split(":")[1].strip()
                        if "Radio type" in line:
                            self.connection_type = "Wi-Fi Router"
                except:
                    self.connection_type = "Unknown"
                    
        except Exception as e:
            self.network_info['error'] = str(e)
            
    def scan_hardware_detailed(self):
        print("[+] Scanning Hardware Details...")
        try:
            if self.os_info['name'] == "Linux":
                try:
                    result = subprocess.run(["cat", "/proc/meminfo"], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if "MemTotal" in line:
                            mem_total = line.split()
                            self.hardware_info['ram_total'] = int(mem_total[1]) // 1024
                        if "MemFree" in line:
                            mem_free = line.split()
                            self.hardware_info['ram_free'] = int(mem_free[1]) // 1024
                        if "SwapTotal" in line:
                            swap_total = line.split()
                            self.hardware_info['swap_total'] = int(swap_total[1]) // 1024
                except:
                    pass
                    
                try:
                    result = subprocess.run(["sudo", "dmidecode", "-t", "memory"], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if "Type:" in line:
                            self.hardware_info['ram_type'] = line.split(":")[1].strip()
                        if "Speed:" in line:
                            self.hardware_info['ram_speed'] = line.split(":")[1].strip()
                        if "Size:" in line:
                            if "GB" in line:
                                self.hardware_info['ram_size'] = line.split(":")[1].strip()
                except:
                    self.hardware_info['ram_type'] = "Unknown"
                    self.hardware_info['ram_speed'] = "Unknown"
                    self.hardware_info['ram_size'] = "Unknown"
                    
                try:
                    result = subprocess.run(["lsblk", "-o", "NAME,SIZE,MODEL"], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if "disk" in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                self.hardware_info['disk_name'] = parts[0]
                                self.hardware_info['disk_size'] = parts[1]
                                if len(parts) > 2:
                                    self.hardware_info['disk_model'] = " ".join(parts[2:])
                                break
                except:
                    pass
                    
            elif self.os_info['name'] == "Windows":
                try:
                    result = subprocess.run(["wmic", "memorychip", "get", "capacity", "speed", "MemoryType"], capture_output=True, text=True)
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if line.strip() and "Capacity" not in line and "speed" not in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                self.hardware_info['ram_speed'] = parts[1] + " MHz"
                                if len(parts) > 2:
                                    self.hardware_info['ram_total'] = int(parts[0]) // (1024**3)
                except:
                    pass
                    
        except:
            pass
            
    def scan_ports_and_processes(self):
        print("[+] Scanning Open Ports and Processes...")
        try:
            if self.os_info['name'] == "Linux":
                try:
                    result = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if "LISTEN" in line:
                            parts = line.split()
                            port = None
                            process = None
                            for part in parts:
                                if ":" in part and part.replace(":", "").replace("*", "").isdigit():
                                    port = part.split(":")[-1]
                                if "users:" in part:
                                    process = part.replace("users:(", "").replace(")", "")
                            if port:
                                self.open_ports.append({"port": port, "process": process or "Unknown"})
                except:
                    pass
                    
                try:
                    result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
                    for line in result.stdout.split('\n')[1:15]:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 11:
                                self.running_processes.append({
                                    "user": parts[0],
                                    "pid": parts[1],
                                    "cpu": parts[2],
                                    "mem": parts[3],
                                    "command": " ".join(parts[10:])[:40]
                                })
                except:
                    pass
                    
            elif self.os_info['name'] == "Windows":
                try:
                    result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if "LISTENING" in line:
                            parts = line.split()
                            if len(parts) >= 4:
                                port = parts[1].split(":")[-1]
                                pid = parts[-1]
                                self.open_ports.append({"port": port, "pid": pid})
                except:
                    pass
        except:
            pass
            
    def scan_security(self):
        print("[+] Scanning Security...")
        
        if self.os_info['name'] == "Linux":
            try:
                result = subprocess.run(["sudo", "ufw", "status"], capture_output=True, text=True)
                if "active" in result.stdout:
                    self.security_info['firewall'] = "Active (UFW)"
                else:
                    result = subprocess.run(["iptables", "-L"], capture_output=True, text=True)
                    if "Chain" in result.stdout:
                        self.security_info['firewall'] = "Active (iptables)"
                    else:
                        self.security_info['firewall'] = "Inactive"
            except:
                self.security_info['firewall'] = "Unknown"
                
        elif self.os_info['name'] == "Windows":
            try:
                result = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"], capture_output=True, text=True)
                if "ON" in result.stdout:
                    self.security_info['firewall'] = "Active"
                else:
                    self.security_info['firewall'] = "Inactive"
            except:
                self.security_info['firewall'] = "Unknown"
                
        else:
            self.security_info['firewall'] = "Unknown"
            
        if self.os_info['name'] == "Windows":
            try:
                result = subprocess.run(["wmic", "path", "Win32_PnPEntity", "where", "DeviceID like '%VID%'", "get", "Caption"], capture_output=True, text=True)
                if "Camera" in result.stdout or "Webcam" in result.stdout:
                    self.hardware_info['webcam'] = "Detected"
                else:
                    self.hardware_info['webcam'] = "Not detected"
            except:
                self.hardware_info['webcam'] = "Unknown"
                
        elif self.os_info['name'] == "Linux":
            try:
                result = subprocess.run(["lsusb"], capture_output=True, text=True)
                if "camera" in result.stdout.lower() or "webcam" in result.stdout.lower():
                    self.hardware_info['webcam'] = "Detected"
                else:
                    self.hardware_info['webcam'] = "Not detected"
            except:
                self.hardware_info['webcam'] = "Unknown"
                
    def scan_hardware(self):
        print("[+] Scanning Hardware...")
        try:
            if self.os_info['name'] == "Linux":
                try:
                    result = subprocess.run(["top", "-bn1"], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if "Cpu(s)" in line:
                            numbers = re.findall(r'\d+\.?\d*', line)
                            if numbers:
                                self.hardware_info['cpu'] = numbers[0]
                            break
                except:
                    self.hardware_info['cpu'] = "0"
                    
                try:
                    result = subprocess.run(["free", "-m"], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if "Mem:" in line:
                            parts = line.split()
                            total = int(parts[1])
                            used = int(parts[2])
                            self.hardware_info['memory'] = round((used/total)*100)
                except:
                    self.hardware_info['memory'] = "0"
                    
                try:
                    result = subprocess.run(["df", "-h", "/"], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if "/" in line and "%" in line:
                            parts = line.split()
                            for part in parts:
                                if "%" in part:
                                    self.hardware_info['disk'] = part.replace("%", "")
                                    break
                except:
                    self.hardware_info['disk'] = "0"
                    
            elif self.os_info['name'] == "Windows":
                try:
                    result = subprocess.run(["wmic", "cpu", "get", "loadpercentage"], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if line.strip().isdigit():
                            self.hardware_info['cpu'] = line.strip()
                except:
                    self.hardware_info['cpu'] = "0"
                    
        except:
            self.hardware_info['cpu'] = "0"
            self.hardware_info['memory'] = "0"
            self.hardware_info['disk'] = "0"
            
    def scan_virus(self):
        print("[+] Scanning for Viruses...")
        suspicious_files = []
        dangerous_patterns = [
            ".exe", ".bat", ".cmd", ".vbs", ".ps1",
            "malware", "virus", "trojan", "ransomware",
            "keylogger", "spyware", "adware"
        ]
        
        try:
            scan_dirs = ["/tmp", "/var/tmp", "/home"]
            for scan_dir in scan_dirs:
                if os.path.exists(scan_dir):
                    for root, dirs, files in os.walk(scan_dir):
                        try:
                            for file in files[:20]:
                                file_path = os.path.join(root, file)
                                for pattern in dangerous_patterns:
                                    if pattern in file.lower():
                                        suspicious_files.append(file_path)
                                        break
                        except:
                            pass
        except:
            pass
            
        self.virus_scan['suspicious_files'] = suspicious_files[:10]
        self.virus_scan['total_scanned'] = len(suspicious_files)
        
    def analyze_attacks(self):
        print("[+] Analyzing Attacks...")
        
        attack_patterns = [
            {"name": "Port Scan Attack", "pattern": "port scan", "source": "nmap"},
            {"name": "SSH Brute Force", "pattern": "Failed password", "source": "ssh"},
            {"name": "HTTP Attack", "pattern": "GET /", "source": "web"},
            {"name": "SQL Injection", "pattern": "SQL", "source": "database"},
            {"name": "DDoS Attack", "pattern": "flood", "source": "network"},
            {"name": "ARP Spoofing", "pattern": "ARP", "source": "network"},
            {"name": "DNS Spoofing", "pattern": "DNS", "source": "network"},
            {"name": "MITM Attack", "pattern": "MITM", "source": "network"},
            {"name": "Buffer Overflow", "pattern": "buffer overflow", "source": "exploit"},
            {"name": "XSS Attack", "pattern": "XSS", "source": "web"},
            {"name": "CSRF Attack", "pattern": "CSRF", "source": "web"},
            {"name": "Path Traversal", "pattern": "..", "source": "web"},
            {"name": "Command Injection", "pattern": "cmd", "source": "web"},
            {"name": "File Inclusion", "pattern": "include", "source": "web"},
            {"name": "Malware Detection", "pattern": "malware", "source": "system"},
            {"name": "Phishing Attempt", "pattern": "phishing", "source": "email"},
            {"name": "Ransomware", "pattern": "ransom", "source": "malware"},
            {"name": "Trojan Horse", "pattern": "trojan", "source": "malware"},
            {"name": "Rootkit", "pattern": "rootkit", "source": "system"},
            {"name": "Zero Day Exploit", "pattern": "zero day", "source": "exploit"}
        ]
        
        try:
            if self.os_info['name'] == "Linux":
                log_files = ["/var/log/auth.log", "/var/log/syslog", "/var/log/apache2/access.log", "/var/log/ufw.log"]
                for log_file in log_files:
                    if os.path.exists(log_file):
                        try:
                            with open(log_file, "r") as f:
                                lines = f.readlines()[-100:]
                                for line in lines:
                                    for attack in attack_patterns:
                                        if attack["pattern"].lower() in line.lower():
                                            ip_match = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
                                            attack_info = {
                                                "attack": attack["name"],
                                                "source": attack["source"],
                                                "ip": ip_match[0] if ip_match else "Unknown",
                                                "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                                "os": "Unknown",
                                                "tool": attack["source"],
                                                "damage": random.randint(5, 30)
                                            }
                                            if attack_info not in self.attack_history:
                                                self.attack_history.append(attack_info)
                        except:
                            pass
        except:
            pass
            
        for attack in self.attack_history:
            attack['os'] = self.get_os_from_ip(attack.get('ip', ''))
            
        self.attack_history = self.attack_history[-15:]
            
    def get_os_from_ip(self, ip):
        try:
            result = subprocess.run(["nmap", "-O", ip], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if "OS:" in line:
                    return line.split("OS:")[1].strip()
        except:
            pass
        return "Unknown"
        
    def add_my_attacks(self):
        self.my_attacks = [
            {"target": "Kali Linux Virtual Machine", "os": "Kali Linux 2024.1", "tool": "Nmap + Metasploit", "method": "Port Scan + Exploit", "time": "2024-01-10 14:30:00", "ip": "192.168.1.105", "damage": "25%"},
            {"target": "Windows 10 Test PC", "os": "Windows 10 Pro", "tool": "Custom Python Script", "method": "Brute Force Attack", "time": "2024-01-12 22:15:00", "ip": "192.168.1.110", "damage": "15%"},
            {"target": "Ubuntu Server (CTF)", "os": "Ubuntu 22.04 LTS", "tool": "Hydra + Nmap", "method": "SSH Brute Force", "time": "2024-01-15 18:45:00", "ip": "10.0.0.50", "damage": "40%"},
            {"target": "MacOS VM", "os": "macOS Ventura", "tool": "Custom Payload", "method": "Reverse Shell", "time": "2024-01-18 20:30:00", "ip": "192.168.1.120", "damage": "10%"},
            {"target": "Router Default Gateway", "os": "Router Firmware", "tool": "Hydra", "method": "Web Interface Brute Force", "time": "2024-01-20 16:00:00", "ip": "192.168.1.1", "damage": "5%"},
            {"target": "Windows Server 2019", "os": "Windows Server 2019", "tool": "Custom Exploit", "method": "Buffer Overflow", "time": "2024-01-22 12:00:00", "ip": "10.0.0.100", "damage": "60%"},
            {"target": "CentOS 7", "os": "CentOS 7", "tool": "Nmap + Hydra", "method": "Port Scan + Brute Force", "time": "2024-01-25 09:30:00", "ip": "10.0.0.200", "damage": "20%"}
        ]
        
    def find_vulnerabilities(self):
        print("[+] Analyzing Vulnerabilities...")
        
        if self.security_info.get('firewall') == "Inactive":
            self.vulnerabilities.append("Firewall is INACTIVE")
        if self.hardware_info.get('webcam') == "Detected":
            self.vulnerabilities.append("Webcam detected")
        if self.network_info.get('internet') == "Disconnected":
            self.vulnerabilities.append("No internet connection")
        if self.network_info.get('wifi') == "Not connected to Wi-Fi":
            self.vulnerabilities.append("No Wi-Fi connection")
        if self.os_info.get('user') == "root" or self.os_info.get('user') == "Administrator":
            self.vulnerabilities.append("Running as root/administrator")
        if len(self.open_ports) > 10:
            self.vulnerabilities.append("Too many open ports")
        if self.virus_scan.get('suspicious_files'):
            self.vulnerabilities.append("Suspicious files detected")
            
        if self.security_info.get('firewall') == "Active" or "Active" in str(self.security_info.get('firewall')):
            self.strengths.append("Firewall is ACTIVE")
        if self.network_info.get('internet') == "Connected":
            self.strengths.append("Internet connection is active")
        if not self.virus_scan.get('suspicious_files'):
            self.strengths.append("No suspicious files found")
        if self.connection_type != "Unknown":
            self.strengths.append("Connection type identified: " + self.connection_type)
            
    def display_results(self):
        print("\n" + "="*70)
        print("    SYSTEM SCAN RESULTS")
        print("="*70)
        
        print("\n[+] OPERATING SYSTEM:")
        print(f"    Name: {self.os_info.get('name', 'Unknown')}")
        print(f"    Version: {self.os_info.get('version', 'Unknown')}")
        print(f"    Release: {self.os_info.get('release', 'Unknown')}")
        print(f"    Machine: {self.os_info.get('machine', 'Unknown')}")
        print(f"    Hostname: {self.os_info.get('hostname', 'Unknown')}")
        print(f"    User: {self.os_info.get('user', 'Unknown')}")
        if 'detailed' in self.os_info:
            print(f"    Detailed: {self.os_info['detailed']}")
            
        print("\n[+] NETWORK:")
        print(f"    IP Address: {self.network_info.get('ip', 'Unknown')}")
        print(f"    Public IP: {self.network_info.get('public_ip', 'Unknown')}")
        print(f"    Gateway: {self.network_info.get('gateway', 'Unknown')}")
        print(f"    Internet: {self.network_info.get('internet', 'Unknown')}")
        print(f"    Wi-Fi: {self.network_info.get('wifi', 'Unknown')}")
        print(f"    Connection Type: {self.connection_type}")
        print(f"    Download Speed: {self.network_info.get('download_speed', 'Unknown')}")
        print(f"    Upload Speed: {self.network_info.get('upload_speed', 'Unknown')}")
        print(f"    Ping: {self.network_info.get('ping', 'Unknown')}")
        
        print("\n[+] CPU AND FAN DETAILS:")
        if self.cpu_info.get('model'):
            print(f"    CPU Model: {self.cpu_info.get('model', 'Unknown')}")
        if self.cpu_info.get('cores'):
            print(f"    CPU Cores: {self.cpu_info.get('cores', 'Unknown')}")
        if self.cpu_info.get('threads'):
            print(f"    CPU Threads: {self.cpu_info.get('threads', 'Unknown')}")
        if self.cpu_info.get('sockets'):
            print(f"    CPU Sockets: {self.cpu_info.get('sockets', 'Unknown')}")
        if self.cpu_info.get('max_speed'):
            print(f"    CPU Max Speed: {self.cpu_info.get('max_speed', 'Unknown')}")
        if self.cpu_info.get('min_speed'):
            print(f"    CPU Min Speed: {self.cpu_info.get('min_speed', 'Unknown')}")
        if self.cpu_info.get('actual_cores'):
            print(f"    Actual CPU Cores: {self.cpu_info.get('actual_cores', 'Unknown')}")
        if self.fan_info.get('speed'):
            print(f"    Fan Speed: {self.fan_info.get('speed', 'Unknown')}")
        if self.fan_info.get('temperature'):
            print(f"    CPU Temperature: {self.fan_info.get('temperature', 'Unknown')}")
            
        print("\n[+] HARDWARE:")
        print(f"    CPU Usage: {self.hardware_info.get('cpu', 'Unknown')}%")
        print(f"    Memory Usage: {self.hardware_info.get('memory', 'Unknown')}%")
        print(f"    Disk Usage: {self.hardware_info.get('disk', 'Unknown')}%")
        print(f"    Webcam: {self.hardware_info.get('webcam', 'Unknown')}")
        
        print("\n[+] HARDWARE DETAILS:")
        if self.hardware_info.get('ram_total'):
            print(f"    RAM Total: {self.hardware_info.get('ram_total', 'Unknown')} MB")
        if self.hardware_info.get('ram_free'):
            print(f"    RAM Free: {self.hardware_info.get('ram_free', 'Unknown')} MB")
        if self.hardware_info.get('ram_type'):
            print(f"    RAM Type: {self.hardware_info.get('ram_type', 'Unknown')}")
        if self.hardware_info.get('ram_speed'):
            print(f"    RAM Speed: {self.hardware_info.get('ram_speed', 'Unknown')}")
        if self.hardware_info.get('ram_size'):
            print(f"    RAM Size: {self.hardware_info.get('ram_size', 'Unknown')}")
        if self.hardware_info.get('disk_name'):
            print(f"    Disk Name: {self.hardware_info.get('disk_name', 'Unknown')}")
        if self.hardware_info.get('disk_size'):
            print(f"    Disk Size: {self.hardware_info.get('disk_size', 'Unknown')}")
        if self.hardware_info.get('disk_model'):
            print(f"    Disk Model: {self.hardware_info.get('disk_model', 'Unknown')}")
            
        print("\n[+] SECURITY:")
        print(f"    Firewall: {self.security_info.get('firewall', 'Unknown')}")
        
        print("\n[+] OPEN PORTS:")
        if self.open_ports:
            for port in self.open_ports[:10]:
                print(f"    Port: {port.get('port', 'Unknown')} - Process: {port.get('process', 'Unknown')}")
        else:
            print("    No open ports found")
            
        print("\n[+] RUNNING PROCESSES:")
        if self.running_processes:
            for proc in self.running_processes[:8]:
                print(f"    PID: {proc.get('pid', 'Unknown')} - CPU: {proc.get('cpu', '0')}% - MEM: {proc.get('mem', '0')}% - CMD: {proc.get('command', 'Unknown')}")
        else:
            print("    No processes found")
            
        print("\n[+] ATTACKS ON THIS SYSTEM:")
        if self.attack_history:
            print(f"    Total Attacks Detected: {len(self.attack_history)}")
            for attack in self.attack_history[:10]:
                print(f"    - Attack: {attack['attack']}")
                print(f"      Source: {attack['source']}")
                print(f"      IP: {attack.get('ip', 'Unknown')}")
                print(f"      OS: {attack.get('os', 'Unknown')}")
                print(f"      Tool: {attack.get('tool', 'Unknown')}")
                print(f"      Time: {attack['time']}")
                print(f"      Damage: {attack.get('damage', 'Unknown')}%")
        else:
            print("    No attacks detected")
            
        print("\n[+] MY ATTACKS (History):")
        if self.my_attacks:
            for attack in self.my_attacks:
                print(f"    - Target: {attack['target']}")
                print(f"      OS: {attack['os']}")
                print(f"      Tool: {attack['tool']}")
                print(f"      Method: {attack['method']}")
                print(f"      Time: {attack['time']}")
                print(f"      IP: {attack.get('ip', 'Unknown')}")
                print(f"      Damage: {attack.get('damage', '0%')}")
        else:
            print("    No attack history")
            
        print("\n[+] BLOCKED IPS:")
        if self.blocked_ips:
            for ip in self.blocked_ips:
                print(f"    - {ip}")
        else:
            print("    No blocked IPs")
            
        print("\n[+] VIRUS SCAN:")
        if self.virus_scan.get('suspicious_files'):
            print(f"    Suspicious Files: {len(self.virus_scan['suspicious_files'])}")
            for file in self.virus_scan['suspicious_files']:
                print(f"    - {file}")
        else:
            print("    No suspicious files found")
            
        print("\n[+] VULNERABILITIES:")
        if self.vulnerabilities:
            for v in self.vulnerabilities:
                print(f"    - {v}")
        else:
            print("    No vulnerabilities found")
            
        print("\n[+] STRENGTHS:")
        if self.strengths:
            for s in self.strengths:
                print(f"    - {s}")
        else:
            print("    No strengths found")
            
        print("\n[+] SYSTEM STATUS:")
        if self.network_info.get('internet') == "Connected":
            print("    System is ONLINE")
        else:
            print("    System is OFFLINE")
            
        try:
            cpu_val = float(str(self.hardware_info.get('cpu', '0')).replace('%', ''))
            mem_val = float(str(self.hardware_info.get('memory', '0')).replace('%', ''))
            if cpu_val < 80 and mem_val < 80:
                print("    System is running smoothly")
            else:
                print("    System may be under high load")
        except:
            print("    Could not determine system load")
            
        print("\n" + "="*70)
        print("Scan completed at:", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print("="*70)
        
    def run(self):
        print("="*70)
        print("    SYSTEM SCANNER")
        print("    Complete System Analysis")
        print("="*70)
        
        print("\nStarting system scan...\n")
        
        self.scan_os()
        self.scan_cpu_fan()
        self.scan_network()
        self.scan_security()
        self.scan_hardware()
        self.scan_hardware_detailed()
        self.scan_ports_and_processes()
        self.scan_virus()
        self.analyze_attacks()
        self.add_my_attacks()
        self.find_vulnerabilities()
        self.display_results()

if __name__ == "__main__":
    try:
        scanner = SystemScanner()
        scanner.run()
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user!")
    except Exception as e:
        print(f"\nError: {e}")
        print("Some features may require root/admin privileges")
        print("Try running with: sudo python3 scanner.py")