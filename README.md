# port-scanner-python-Xerxes-Bytes
A fast, multi-threaded TCP port scanner built for educational purposes and authorized penetration testing environments.

🔍 Port Scanner — Xerxes Bytes

A fast, multi-threaded TCP port scanner built for educational purposes and authorized penetration testing environments.

Built and developed by Xerxes Bytes — a student-driven cybersecurity group focused on scripting, vulnerability analysis, and hands-on security research.

⚡ Features

Multi-threaded scanning — scan hundreds of ports simultaneously using Python's ThreadPoolExecutor
Banner grabbing — identify running services by reading their response headers
Smart port detection — recognizes 20+ common services (HTTP, SSH, FTP, MySQL, etc.)
Flexible input — single ports, comma-separated lists, or full ranges
Progress bar — real-time scan feedback in the terminal
Color-coded output — instant visual distinction between open, closed, and filtered ports
Interactive mode — run without arguments for a guided experience


🛠️ Requirements
No external libraries needed — built entirely with Python standard library.
bashPython 3.6+

🚀 Usage
Basic scan (common ports)
bashpython3 port_scanner.py 127.0.0.1
Scan specific ports
bashpython3 port_scanner.py 192.168.1.1 -p 80,443,8080
Scan a port range
bashpython3 port_scanner.py 192.168.1.1 -r 1-1024
Full scan with banner grabbing
bashpython3 port_scanner.py 192.168.1.1 -r 1-65535 --threads 200 --grab
Top 20 common ports only
bashpython3 port_scanner.py 192.168.1.1 --top
Interactive mode
bashpython3 port_scanner.py

📋 Arguments
ArgumentDescriptionDefaulttargetIP address or hostname—-p, --portsSpecific ports: 80,443,8080—-r, --rangePort range: 1-1024—-t, --timeoutTimeout per port (seconds)0.5--threadsNumber of concurrent threads100--grabEnable banner grabbingFalse--topScan top 20 common ports onlyFalse

📸 Example Output
  PORT      STATE    SERVICE
  ─────────────────────────────────────────────
  [+] Port    22/tcp  open     SSH
  [+] Port    80/tcp  open     HTTP          ← Apache/2.4.41
  [+] Port   443/tcp  open     HTTPS
  [+] Port  3306/tcp  open     MySQL

  ─────────────────────────────────────────────
  Scan complete: 4 open port(s) found in 2.31s

🧠 How It Works
1. TCP Connect Scan
The scanner attempts a full TCP connection on each port using socket.connect_ex(). This returns 0 if the connection succeeds (port open) or an error code if it fails (port closed/filtered).
pythonsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(timeout)
code = sock.connect_ex((ip, port))   # 0 = open
2. Multi-threading
Instead of scanning ports one by one (slow), we use ThreadPoolExecutor to scan many ports simultaneously — making the scanner up to 100x faster.
pythonwith ThreadPoolExecutor(max_workers=100) as executor:
    futures = {executor.submit(scan_port, ip, port): port for port in ports}
3. Banner Grabbing
When --grab is enabled, the scanner reads the first response bytes from open ports to identify the running service and its version.
4. Port States
StateMeaningopenPort is reachable and a service is listeningclosedPort is reachable but no service is listeningfilteredNo response received — likely blocked by a firewall

🎯 Recommended Practice Environments
This tool is intended for use in authorized environments only:

TryHackMe — beginner-friendly CTF rooms
HackTheBox — intermediate/advanced machines
DVWA — local vulnerable web app
Your own local network / VMs


⚠️ Legal Disclaimer
This tool was created strictly for educational purposes and authorized security testing.
Scanning systems without explicit permission is illegal and unethical.
The authors take no responsibility for any misuse of this software.
Only use on systems you own or have written permission to test.

👥 About Xerxes Bytes
Xerxes Bytes is a student cybersecurity group exploring offensive and defensive security through hands-on projects. We build open-source tools to learn scripting, penetration testing techniques, and vulnerability research in controlled environments.
🔗 GitHub: github.com/zopiros

📄 License
MIT License — free to use, modify, and distribute with attribution.
