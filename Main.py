import requests
import urllib3
import argparse
import random
import time
import sys
import string
import socket
import json
import re
import ssl
import threading
import signal
import os
from urllib.parse import urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Console Colors (ANSI)
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    GRAY = '\033[90m'

# Professional-grade User-Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edge/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0"
]

# Advanced Hacker Banner
HACKER_BANNER = fr"""
{Colors.RED}
██████╗ ██╗      █████╗  ██████╗██╗  ██╗██╗  ██╗ █████╗ ████████╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██║  ██║██╔══██╗╚══██╔══╝
██████╔╝██║     ███████║██║     █████╔╝ ███████║███████║   ██║   
██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██╔══██║██╔══██║   ██║   
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██║  ██║██║  ██║   ██║   
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   
{Colors.END}
{Colors.GRAY} :: Advanced Admin Panel Hunter v5.0 [Ultimate] :: {Colors.END}
{Colors.RED} :: {Colors.BOLD}DEV BY SHIBOSHREE ROY{Colors.END}{Colors.RED} :: {Colors.END}
{Colors.YELLOW} [!] AUTHORIZED USE ONLY - ENCRYPTION: 256-BIT [!]
{Colors.GRAY} ----------------------------------------------------{Colors.END}
"""

# Thread Lock for clean output
print_lock = threading.Lock()
stop_event = threading.Event()
found_entries_global = []

def print_progress(iteration, total, prefix='', suffix='', decimals=1, length=40, fill='█', printEnd="\r"):
    """
    Call in a loop to create terminal progress bar
    """
    if total == 0: total = 1
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    sys.stdout.write(f'\r{Colors.BLUE}{prefix} |{Colors.RED}{bar}{Colors.BLUE}| {percent}% {suffix}{Colors.END}')
    sys.stdout.flush()
    if iteration == total: 
        print()

def fake_initialization():
    """Simulates a complex startup sequence."""
    steps = [
        ("Loading Modules", "Core, Network, Exploits, Recon"),
        ("Initializing Socket", "Secure/256-bit"),
        ("Bypassing Local Firewalls", "Success"),
        ("Routing Traffic", "Proxy Chain Initiated"),
        ("Engaging Target", "Locked On")
    ]
    
    print(HACKER_BANNER)
    time.sleep(0.5)
    
    for step, detail in steps:
        sys.stdout.write(f"{Colors.BLUE}[*] {step}... {Colors.END}")
        sys.stdout.flush()
        time.sleep(random.uniform(0.1, 0.3))
        sys.stdout.write(f"{Colors.GREEN}{detail}{Colors.END}\n")
        time.sleep(0.1)
    print(f"\n{Colors.RED}{Colors.BOLD}[!] SYSTEM READY. INITIATING SCAN.{Colors.END}\n")

def get_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://www.google.com/",
        "DNT": "1",
        "Connection": "keep-alive"
    }

# --- RECONNAISSANCE & RISK ASSESSMENT ---

def get_ip_info(ip_address):
    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,country,countryCode,regionName,city,isp,org,as"
        response = requests.get(url, timeout=4)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return data
    except Exception:
        pass
    return None

def get_ssl_info(hostname, port=443):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((hostname, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()
                return f"{version} | {cipher[0]} ({cipher[2]} bits)"
    except Exception:
        return "SSL Handshake Failed or No SSL"

def grab_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        if port in [80, 8080, 443, 8443]:
            s.send(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        return banner if banner else "No Banner"
    except:
        return "Connection Refused/Timeout"

def get_access_url(ip, port, service_name):
    schema = "tcp"
    service_lower = service_name.lower()
    if port in [80, 8080, 8000, 8008, 8888] or "http" in service_lower: schema = "http"
    elif port in [443, 8443] or "ssl" in service_lower or "https" in service_lower: schema = "https"
    elif port == 21 or "ftp" in service_lower: schema = "ftp"
    elif port == 22 or "ssh" in service_lower: schema = "ssh"
    return f"{schema}://{ip}:{port}"

def analyze_port_risk(port, service_name, banner=""):
    risks = {
        21: "FTP. RISK: Cleartext auth, sniffing.",
        22: "SSH. RISK: Brute-force, weak keys.",
        23: "Telnet. CRITICAL: Unencrypted credentials.",
        80: "HTTP. RISK: Unencrypted traffic.",
        443: "HTTPS. Check SSL validity.",
        3306: "MySQL. RISK: Exposed DB.",
        3389: "RDP. HIGH: BlueKeep, Brute-force."
    }
    risk_desc = risks.get(port, f"Service: {service_name}. Check version.")
    if banner and "vsftpd 2.3.4" in banner.lower(): risk_desc += " [!] BACKDOOR LIKELY."
    return risk_desc

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            try: service = socket.getservbyport(port)
            except: service = "unknown"
            banner = grab_banner(ip, port)
            return port, service, banner
    except:
        pass
    return None

def check_subdomains(domain):
    subdomains = ['admin', 'webmail', 'cpanel', 'dev', 'test', 'staging', 'portal']
    found = []
    print(f" {Colors.GRAY}├─{Colors.END} {Colors.BOLD}ENUMERATING SUBDOMAINS...{Colors.END}")
    for sub in subdomains:
        hostname = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(hostname)
            found.append((hostname, ip))
            print(f"    {Colors.GREEN}[+] FOUND: {hostname} ({ip}){Colors.END}")
        except:
            pass
    return found

def perform_recon(target_url, proxies=None):
    recon_data = {"target": target_url, "timestamp": datetime.now().isoformat()}
    print(f"{Colors.BLUE}{Colors.BOLD}[*] INITIATING DEEP RECONNAISSANCE...{Colors.END}")
    
    try:
        parsed = urlparse(target_url)
        hostname = parsed.netloc.split(':')[0]
        ip_address = socket.gethostbyname(hostname)
        recon_data["ip"] = ip_address
        recon_data["hostname"] = hostname
        print(f" {Colors.GRAY}├─{Colors.END} {Colors.BOLD}TARGET  {Colors.END} : {Colors.WHITE}{hostname} ({ip_address}){Colors.END}")
    except socket.gaierror:
        print(f"{Colors.RED}[!] Failed to resolve hostname.{Colors.END}")
        return None
    
    try:
        resp = requests.head(target_url, verify=False, timeout=5, headers=get_headers(), proxies=proxies)
        print(f" {Colors.GRAY}├─{Colors.END} {Colors.BOLD}SERVER  {Colors.END} : {Colors.WHITE}{resp.headers.get('Server', 'Unknown')}{Colors.END}")
        if target_url.startswith("https"):
             print(f" {Colors.GRAY}├─{Colors.END} {Colors.BOLD}SSL/TLS {Colors.END} : {Colors.CYAN}{get_ssl_info(hostname)}{Colors.END}")
    except:
        pass

    geo_data = get_ip_info(ip_address)
    if geo_data:
        print(f" {Colors.GRAY}├─{Colors.END} {Colors.BOLD}LOCATION{Colors.END} : {Colors.CYAN}{geo_data['country']}{Colors.END}")

    found_subs = check_subdomains(hostname)
    
    print(f" {Colors.GRAY}└─{Colors.END} {Colors.BOLD}PORT SCANNING...{Colors.END}")
    common_ports = [21, 22, 23, 80, 443, 3306, 3389, 8080]
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(scan_port, ip_address, p): p for p in common_ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                port, service, banner = result
                access_url = get_access_url(ip_address, port, service)
                open_ports.append({"port": port, "service": service, "access_url": access_url})
                print(f"    {Colors.GREEN}[+] Port {port} OPEN{Colors.END} -> {access_url}")
    
    recon_data["open_ports"] = open_ports
    print(f"\n{Colors.GRAY}{'-'*60}{Colors.END}\n")
    return recon_data

# --- ADVANCED LOGIC ---

def extract_vectors(content):
    inputs = re.findall(r'<input[^>]+name=["\'](.*?)["\']', str(content), re.IGNORECASE)
    actions = re.findall(r'<form[^>]+action=["\'](.*?)["\']', str(content), re.IGNORECASE)
    return inputs, actions

def get_calibration_response(session, target_url):
    random_path = '/' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    try:
        resp = session.get(f"{target_url.rstrip('/')}{random_path}", headers=get_headers(), verify=False, timeout=5)
        return resp.content, len(resp.content)
    except:
        return None, 0

def generate_recursive_paths(found_path):
    extensions = ['.php', '.html', '']
    sub_paths = ['/users', '/config', '/settings', '/logs', '/db', '/backup', '/upload', '/shell']
    new_paths = []
    base = found_path.rsplit('.', 1)[0]
    for sub in sub_paths:
        for ext in extensions:
            new_paths.append(f"{base}{sub}{ext}")
            new_paths.append(f"{found_path}{sub}{ext}")
    return new_paths

def check_path(session, target_url, path, timeout, proxies, calibration_data):
    if stop_event.is_set(): return None
    
    path_cleaned = path.strip('/')
    full_url = f"{target_url.rstrip('/')}/{path_cleaned}"
    
    try:
        response = session.get(full_url, headers=get_headers(), verify=False, timeout=timeout, allow_redirects=False)
        status = response.status_code
        
        # --- Advanced: 403 Forbidden Deep Fuzzing ---
        bypass_msg = ""
        if status == 403:
            # Header Bypass
            headers = get_headers()
            headers.update({'X-Forwarded-For': '127.0.0.1', 'X-Original-URL': f"/{path_cleaned}"})
            
            # URL Mutation Bypass (Path Poisoning)
            mutations = [
                f"/{path_cleaned}/", 
                f"/{path_cleaned}/.", 
                f"//{path_cleaned}//", 
                f"/./{path_cleaned}/./", 
                f"/{path_cleaned};/", 
                f"/{path_cleaned}..;/"
            ]
            
            # Try headers first
            try:
                bypass = session.get(full_url, headers=headers, verify=False, timeout=timeout)
                if bypass.status_code == 200:
                    status = 200
                    response = bypass
                    bypass_msg = " [Header Bypass]"
            except: pass
            
            # Try mutations if still 403
            if status == 403:
                for mut in mutations:
                    mut_url = f"{target_url.rstrip('/')}{mut}"
                    try:
                        bypass = session.get(mut_url, headers=get_headers(), verify=False, timeout=timeout)
                        if bypass.status_code == 200:
                            status = 200
                            response = bypass
                            full_url = mut_url
                            bypass_msg = f" https://pubmed.ncbi.nlm.nih.gov/8990001/"
                            break
                    except: pass

        # Soft 404
        if status == 200 and calibration_data:
            cal_content, cal_len = calibration_data
            if abs(len(response.content) - cal_len) < (cal_len * 0.05):
                if SequenceMatcher(None, response.content, cal_content).ratio() > 0.90:
                    return None
        
        # Result Processing
        if status in [200, 301, 302, 403, 401]:
            with print_lock:
                sys.stdout.write('\r' + ' ' * 80 + '\r') # Clear progress bar line
                if status == 200:
                    extra = f"{Colors.GREEN}[BYPASS]{Colors.END}" if bypass_msg else ""
                    print(f"{Colors.GREEN}[+] FOUND: {full_url} [200]{extra}{Colors.END}")
                    inputs, actions = extract_vectors(response.content)
                    if inputs: print(f"    {Colors.YELLOW}└── Inputs: {', '.join(inputs[:5])}{Colors.END}")
                elif status in [401, 403]:
                    print(f"{Colors.YELLOW}[!] LOCKED: {full_url} [{status}]{Colors.END}")
                elif status in [301, 302]:
                    print(f"{Colors.CYAN}[~] REDIRECT: {full_url} -> {response.headers.get('Location')}{Colors.END}")
            
            return {"url": full_url, "status": status, "path": path, "bypass": bypass_msg}

    except:
        pass
    return None

def generate_html_report(target_url, recon_data, found_entries, output_file):
    """Generates a professional HTML report."""
    filename = output_file if output_file and output_file.endswith('.html') else f"scan_report_{int(time.time())}.html"
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Scan Report: {target_url}</title>
        <style>
            body {{ font-family: 'Courier New', monospace; background-color: #0d0d0d; color: #00ff00; padding: 20px; }}
            .container {{ max-width: 1000px; margin: auto; border: 1px solid #333; padding: 20px; box-shadow: 0 0 10px #00ff00; }}
            h1, h2 {{ border-bottom: 1px solid #00ff00; padding-bottom: 10px; }}
            .section {{ margin-bottom: 30px; background: #1a1a1a; padding: 15px; border-radius: 5px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th, td {{ border: 1px solid #333; padding: 10px; text-align: left; }}
            th {{ background-color: #333; color: #fff; }}
            tr:nth-child(even) {{ background-color: #111; }}
            .status-200 {{ color: #00ff00; font-weight: bold; }}
            .status-403 {{ color: #ffaa00; }}
            .status-302 {{ color: #00ffff; }}
            .footer {{ margin-top: 50px; font-size: 0.8em; color: #666; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>ADMIN PANEL HUNTER - SCAN REPORT</h1>
            <p><strong>Target:</strong> {target_url}</p>
            <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <div class="section">
                <h2>1. RECONNAISSANCE DATA</h2>
                <p><strong>IP Address:</strong> {recon_data.get('ip', 'N/A')}</p>
                <p><strong>Hostname:</strong> {recon_data.get('hostname', 'N/A')}</p>
                <h3>Open Ports</h3>
                <table>
                    <tr><th>Port</th><th>Service</th><th>Access URL</th></tr>
                    {''.join(f"<tr><td>{p['port']}</td><td>{p['service']}</td><td><a href='{p['access_url']}' style='color:#fff'>{p['access_url']}</a></td></tr>" for p in recon_data.get('open_ports', []))}
                </table>
            </div>

            <div class="section">
                <h2>2. DISCOVERED PATHS</h2>
                <table>
                    <tr><th>Status</th><th>URL</th><th>Details</th></tr>
                    {''.join(f"<tr><td class='status-{e['status']}'>{e['status']}</td><td><a href='{e['url']}' style='color:#fff'>{e['url']}</a></td><td>{e.get('bypass', '')}</td></tr>" for e in found_entries)}
                </table>
            </div>
            
            <div class="footer">
                Generated by Admin Panel Hunter Pro v5.0 | Authorized Use Only
            </div>
        </div>
    </body>
    </html>
    """
    
    try:
        with open(filename, 'w') as f:
            f.write(html_content)
        return filename
    except Exception as e:
        print(f"{Colors.RED}[!] Failed to write HTML report: {e}{Colors.END}")
        return None

def signal_handler(sig, frame):
    """Handles Ctrl+C gracefully."""
    print(f"\n\n{Colors.RED}[!] ABORTING SCAN... SAVING PROGRESS...{Colors.END}")
    stop_event.set()
    # Allow threads to cleanup mostly
    time.sleep(1) 
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def scan_admin_panels(target_url, wordlist_path=None, threads=15, timeout=5, proxy=None, output_file=None):
    fake_initialization()
    
    proxies = {"http": proxy, "https": proxy} if proxy else None
    
    # Step 1: Recon
    recon_data = perform_recon(target_url, proxies) or {}

    # Base Paths
    paths = [
        '/admin', '/administrator', '/wp-admin', '/login', '/cpanel', '/dashboard',
        '/backend', '/manage', '/phpmyadmin', '/vhost', '/cp', '/magento/admin',
        '/ghost', '/strapi/admin', '/umbraco', '/directadmin', '/webmail',
        '/admin_login', '/controlpanel', '/secret-admin', '/master', 
        '/auth', '/user/login', '/system', '/cms', '/panel', '/robots.txt'
    ]
    
    # Add High-Value Targets (Sensitive Files)
    paths.extend([
        '/.env', '/.git/config', '/docker-compose.yml', '/package.json', 
        '/config.php', '/web.config', '/backup.sql', '/database.yml', '/id_rsa'
    ])

    if wordlist_path:
        try:
            with open(wordlist_path, 'r') as f:
                paths.extend([line.strip() for line in f if line.strip()])
        except: print(f"{Colors.RED}[!] Wordlist error.{Colors.END}")

    paths = list(set(paths))
    total_paths = len(paths)
    global found_entries_global
    found_entries_global = []

    print(f"{Colors.BLUE}{Colors.BOLD}[*] STARTING BRUTE-FORCE ENGINE...{Colors.END}")
    print(f"[*] THREADS: {threads} | TOTAL PATHS: {total_paths}\n")
    
    # Calibration
    calibration_data = None
    with requests.Session() as s:
        s.proxies = proxies
        calibration_data = get_calibration_response(s, target_url)

    # Main Scanning Loop with Progress Bar
    start_time = time.time()
    
    with requests.Session() as session:
        session.proxies = proxies
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_path, session, target_url, p, timeout, proxies, calibration_data): p for p in paths}
            
            completed_count = 0
            while completed_count < len(futures) and not stop_event.is_set():
                done_futures = [f for f in futures if f.done()]
                for future in done_futures:
                    result = future.result()
                    path = futures.pop(future)
                    completed_count += 1
                    
                    if result:
                        found_entries_global.append(result)
                        # Recursive logic for directories
                        if result['status'] in [200, 403] and '.' not in path.split('/')[-1]:
                            new_recursive = generate_recursive_paths(result['path'])
                            # In a real tool, we would add these to the queue dynamically
                            
                    print_progress(completed_count, total_paths + len(futures), prefix='Scanning:', suffix='Complete', length=30)
                
                time.sleep(0.05)
    
    sys.stdout.write('\r' + ' ' * 80 + '\r')
    
    duration = time.time() - start_time
    print(f"\n{Colors.BLUE}{'='*60}")
    print(f"[*] SCAN COMPLETE in {duration:.2f}s")
    print(f"[*] FOUND: {len(found_entries_global)} accessible paths")
    
    # Generate HTML Report
    if len(found_entries_global) > 0:
        html_file = generate_html_report(target_url, recon_data, found_entries_global, output_file)
        if html_file:
             print(f"{Colors.GREEN}[*] HTML Report generated: {html_file}{Colors.END}")
    
    if output_file and output_file.endswith('.json'):
        try:
            with open(output_file, 'w') as f:
                json.dump(found_entries_global, f, indent=4)
            print(f"[*] JSON Data saved to {output_file}")
        except: pass
    print(f"{'='*60}{Colors.END}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Blackhat Admin Scanner")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist")
    parser.add_argument("-t", "--threads", type=int, default=15)
    parser.add_argument("-to", "--timeout", type=int, default=7)
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("-o", "--output", help="Output file (e.g., report.html or data.json)")

    args = parser.parse_args()

    if not args.url.startswith("http"):
        print(f"{Colors.RED}[!] Error: Invalid URL. Use http/https.{Colors.END}")
    else:
        scan_admin_panels(args.url, args.wordlist, args.threads, args.timeout, args.proxy, args.output)