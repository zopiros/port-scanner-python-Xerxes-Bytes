#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║           Port Scanner — Xerxes Bytes                ║
║     Educational tool for authorized use only         ║
╚══════════════════════════════════════════════════════╝

USAGE:
  python3 port_scanner.py                    # حالت تعاملی
  python3 port_scanner.py 127.0.0.1          # اسکن localhost
  python3 port_scanner.py 192.168.1.1 -p 80,443,8080
  python3 port_scanner.py 192.168.1.1 -r 1-1024
  python3 port_scanner.py 192.168.1.1 -r 1-65535 --threads 200
"""

import socket
import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


# ─── رنگ‌بندی ترمینال ───────────────────────────────────────────────────────
class Color:
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


# ─── دیکشنری پورت‌های معروف ──────────────────────────────────────────────────
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017:"MongoDB",
}


def banner():
    """نمایش بنر برنامه"""
    print(f"""
{Color.CYAN}{Color.BOLD}
 ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
 ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{Color.RESET}
{Color.YELLOW}                        Xerxes Bytes — Port Scanner v1.0{Color.RESET}
{Color.RED}             ⚠  Only use on systems you own or have permission to test{Color.RESET}
""")


def resolve_host(target: str) -> str:
    """تبدیل hostname به IP"""
    try:
        ip = socket.gethostbyname(target)
        if ip != target:
            print(f"{Color.CYAN}[*] Resolved: {target} → {ip}{Color.RESET}")
        return ip
    except socket.gaierror:
        print(f"{Color.RED}[!] Cannot resolve host: {target}{Color.RESET}")
        sys.exit(1)


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    """
    Banner Grabbing: دریافت اطلاعات سرویس از پورت باز
    بعضی سرویس‌ها وقتی کانکشن برقرار میشه، خودشون رو معرفی می‌کنن
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            # برای HTTP یه request ساده میفرستیم
            if port in (80, 8080, 8000):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            # فقط خط اول رو نشون بده
            return banner.split("\n")[0][:60] if banner else ""
    except Exception:
        return ""


def scan_port(ip: str, port: int, timeout: float, grab: bool) -> dict:
    """
    اسکن یک پورت خاص
    
    چطور کار می‌کنه:
    1. یه socket TCP میسازیم
    2. سعی می‌کنیم به IP:PORT وصل بشیم
    3. اگه وصل شد → پورت باز است
    4. اگه connection refused → پورت بسته است
    5. اگه timeout → پورت فیلتر شده یا هاست جواب نمیده
    """
    result = {
        "port":    port,
        "state":   "closed",
        "service": COMMON_PORTS.get(port, "unknown"),
        "banner":  ""
    }
    
    try:
        # AF_INET = IPv4 | SOCK_STREAM = TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            # connect_ex برعکس connect، به جای exception یه error code برمیگردونه
            # 0 = success (پورت باز) | هر عدد دیگه = خطا (پورت بسته)
            code = sock.connect_ex((ip, port))
            
            if code == 0:
                result["state"] = "open"
                if grab:
                    result["banner"] = grab_banner(ip, port, timeout)
    
    except socket.timeout:
        result["state"] = "filtered"
    except Exception:
        pass
    
    return result


def parse_ports(port_arg: str) -> list:
    """
    پارس کردن آرگومان پورت‌ها
    مثال: "80,443,8080" یا "1-1024"
    """
    ports = []
    
    if "," in port_arg:
        # پورت‌های جداگانه: 80,443,8080
        for p in port_arg.split(","):
            p = p.strip()
            if p.isdigit():
                ports.append(int(p))
    
    elif "-" in port_arg:
        # رنج پورت: 1-1024
        parts = port_arg.split("-")
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            start, end = int(parts[0]), int(parts[1])
            if 1 <= start <= end <= 65535:
                ports = list(range(start, end + 1))
    
    elif port_arg.isdigit():
        ports = [int(port_arg)]
    
    if not ports:
        print(f"{Color.RED}[!] Invalid port format. Use: 80,443 or 1-1024{Color.RESET}")
        sys.exit(1)
    
    return sorted(set(ports))


def print_result(res: dict):
    """چاپ نتیجه یک پورت باز"""
    service = res["service"]
    banner  = f"  ← {res['banner']}" if res["banner"] else ""
    print(
        f"  {Color.GREEN}[+]{Color.RESET} "
        f"Port {Color.BOLD}{res['port']:>5}{Color.RESET}/tcp  "
        f"{Color.GREEN}open{Color.RESET}     "
        f"{Color.CYAN}{service:<12}{Color.RESET}"
        f"{Color.YELLOW}{banner}{Color.RESET}"
    )


def run_scan(ip: str, ports: list, timeout: float, threads: int, grab: bool):
    """اجرای اسکن موازی با ThreadPoolExecutor"""
    
    open_ports = []
    total      = len(ports)
    scanned    = 0
    start_time = time.time()
    
    print(f"\n{Color.CYAN}[*] Scanning {ip} — {total} ports | "
          f"threads={threads} | timeout={timeout}s{Color.RESET}\n")
    
    # ThreadPoolExecutor: اسکن چند پورت همزمان
    # هر thread یه پورت رو اسکن می‌کنه — خیلی سریع‌تر از sequential
    with ThreadPoolExecutor(max_workers=threads) as executor:
        
        # ارسال همه taskها به executor
        futures = {
            executor.submit(scan_port, ip, port, timeout, grab): port
            for port in ports
        }
        
        # دریافت نتایج به محض تموم شدن هر task
        for future in as_completed(futures):
            scanned += 1
            result = future.result()
            
            # نمایش progress
            progress = int((scanned / total) * 30)
            bar = "█" * progress + "░" * (30 - progress)
            print(f"\r  [{bar}] {scanned}/{total}", end="", flush=True)
            
            if result["state"] == "open":
                open_ports.append(result)
    
    elapsed = time.time() - start_time
    print(f"\r  {'─' * 50}")  # پاک کردن progress bar
    
    return open_ports, elapsed


def interactive_mode():
    """حالت تعاملی — وقتی آرگومان داده نشده"""
    print(f"{Color.YELLOW}[?] Enter target IP or hostname:{Color.RESET} ", end="")
    target = input().strip()
    
    print(f"{Color.YELLOW}[?] Port range (e.g. 1-1024, or press Enter for top 20):{Color.RESET} ", end="")
    port_input = input().strip()
    
    if not port_input:
        # پورت‌های معروف
        ports = sorted(COMMON_PORTS.keys())
    else:
        ports = parse_ports(port_input)
    
    return target, ports


def main():
    banner()
    
    parser = argparse.ArgumentParser(
        description="Port Scanner — Xerxes Bytes",
        add_help=True
    )
    parser.add_argument("target",          nargs="?",        help="Target IP or hostname")
    parser.add_argument("-p", "--ports",   type=str,         help="Ports: 80,443 or 80-443")
    parser.add_argument("-r", "--range",   type=str,         help="Port range: 1-1024")
    parser.add_argument("-t", "--timeout", type=float, default=0.5,  help="Timeout per port (default: 0.5s)")
    parser.add_argument("--threads",       type=int,   default=100,  help="Threads (default: 100)")
    parser.add_argument("--grab",          action="store_true",       help="Enable banner grabbing")
    parser.add_argument("--top",           action="store_true",       help="Scan top 20 common ports only")
    
    args = parser.parse_args()
    
    # ─── تعیین target و پورت‌ها ───────────────────────────────────────────────
    if not args.target:
        target, ports = interactive_mode()
    else:
        target = args.target
        
        if args.top:
            ports = sorted(COMMON_PORTS.keys())
        elif args.ports:
            ports = parse_ports(args.ports)
        elif args.range:
            ports = parse_ports(args.range)
        else:
            # پیش‌فرض: پورت‌های معروف
            ports = sorted(COMMON_PORTS.keys())
    
    # ─── resolve و شروع اسکن ─────────────────────────────────────────────────
    ip = resolve_host(target)
    
    print(f"  Target   : {Color.BOLD}{target}{Color.RESET} ({ip})")
    print(f"  Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Ports    : {len(ports)} total")
    
    # ─── اجرای اسکن ──────────────────────────────────────────────────────────
    open_ports, elapsed = run_scan(
        ip       = ip,
        ports    = ports,
        timeout  = args.timeout,
        threads  = args.threads if args.target else 100,
        grab     = args.grab if args.target else False
    )
    
    # ─── نمایش نتایج ─────────────────────────────────────────────────────────
    print(f"\n{Color.BOLD}  PORT      STATE    SERVICE{Color.RESET}")
    print(f"  {'─' * 45}")
    
    if open_ports:
        for res in sorted(open_ports, key=lambda x: x["port"]):
            print_result(res)
    else:
        print(f"  {Color.YELLOW}No open ports found.{Color.RESET}")
    
    print(f"\n  {'─' * 45}")
    print(f"  {Color.CYAN}Scan complete:{Color.RESET} "
          f"{len(open_ports)} open port(s) found in {elapsed:.2f}s\n")


if __name__ == "__main__":
    main()
