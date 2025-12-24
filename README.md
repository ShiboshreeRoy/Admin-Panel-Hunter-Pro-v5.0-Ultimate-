# **🛡️ Admin Panel Hunter Pro v5.0 \[Ultimate\]**

**Advanced Reconnaissance, Infrastructure Analysis, and Admin Panel Discovery Suite.** \> *Developed by Shiboshree Roy*

## **🚨 Legal Disclaimer**

**⚠️ CRITICAL WARNING: FOR AUTHORIZED SECURITY AUDITING ONLY.**

This software is developed for the exclusive use of security professionals, penetration testers, and system administrators. It is designed to identify vulnerabilities within **systems for which you have explicit, written authorization to test**.

* **Unlawful Use:** Using this tool against targets without permission is illegal and violates local and international cyber laws.  
* **Liability:** The developer (**Shiboshree Roy**) assumes **no liability** for misuse, damage, or illegal activities resulting from the use of this software.

## **📖 Overview**

**Admin Panel Hunter Pro v5.0** represents the pinnacle of automated web reconnaissance. Unlike standard directory busters, this tool leverages a **context-aware algorithmic engine** to intelligently map a target's attack surface.

It combines passive OSINT (Open Source Intelligence) with active scanning techniques to discover exposed administrative interfaces, sensitive configuration files, and potential entry points. It features a cinema-grade CLI interface, real-time visual feedback, and generates client-ready HTML reports.

## **🌟 Key Features**

### **🧠 Intelligent Scanning Core**

* **Context-Aware Injection:** Automatically detects the underlying technology (WordPress, Joomla, Laravel, etc.) and prioritizes relevant paths.  
* **Smart Recursion:** Implements logic to "dig deeper." If a directory (e.g., /admin) is found, it automatically generates and scans sub-paths (e.g., /admin/users, /admin/config).  
* **Soft 404 Calibration:** analyzes the target's behavior to distinguish between genuine "Not Found" pages and custom error pages, drastically reducing false positives.  
* **Robots.txt Parser:** Extracts and queues hidden paths defined in the Disallow directives.

### **🛡️ Advanced Evasion & Bypass**

* **403 Forbidden Fuzzing:** When a restricted page is found, the tool attempts to bypass access controls using:  
  * **Header Spoofing:** X-Forwarded-For: 127.0.0.1, X-Original-URL.  
  * **Path Poisoning:** URL mutations like /admin/..;/ and //admin//.  
* **WAF Fingerprinting:** Passive detection of Cloudflare, Akamai, AWS WAF, and ModSecurity.  
* **Stealth Mechanics:** Randomized User-Agent rotation and configurable delay jitter.

### **🌍 Deep Infrastructure Recon**

* **Geo-Location & ISP:** Resolves the physical location and hosting provider of the target.  
* **Subdomain Enumeration:** Probes for common administrative subdomains (dev., staging., api.).  
* **Port & Service Scanning:** Multi-threaded checks for high-risk ports (FTP, SSH, RDP, MySQL) with banner grabbing.  
* **SSL/TLS Audit:** Validates certificate details and encryption strength.

### **📝 Vulnerability Analysis**

* **Sensitive File Hunter:** Scans for .env, .git/config, docker-compose.yml, and backup files (.bak, .zip).  
* **Header Analysis:** Audits for missing security headers (CSP, X-Frame-Options, CORS).  
* **HTML Scraping:** Extracts email addresses, developer comments (\<\!-- TODO \--\>), and form input vectors.

## **📦 Installation**

### **Prerequisites**

* Python 3.6 or higher.  
* Internet connection.

### **Quick Start**

1. **Clone the repository:**  
   git clone \[https://github.com/your-repo/admin-panel-hunter-pro.git\](https://github.com/your-repo/admin-panel-hunter-pro.git)  
   cd admin-panel-hunter-pro

2. **Install dependencies:**  
   pip install requests

## **💻 Usage**

Run the tool using the following syntax:

python admin\_scanner.py \<TARGET\_URL\> \[OPTIONS\]

### **Arguments Table**

| Flag | Long Flag | Description | Default |
| :---- | :---- | :---- | :---- |
| **URL** | url | **(Required)** Target URL (e.g., https://target.com) | N/A |
| \-w | \--wordlist | Path to a custom wordlist file | Internal List |
| \-t | \--threads | Number of concurrent threads | 15 |
| \-to | \--timeout | HTTP request timeout (seconds) | 7 |
| \-p | \--proxy | Proxy URL (e.g., http://127.0.0.1:8080) | None |
| \-o | \--output | Output filename (.html or .json) | None |
| \-d | \--delay | Delay between requests (seconds) | 0 |

## **🧪 Usage Scenarios**

### **1\. The "Quick Scan"**

Perfect for a fast assessment using the built-in optimized wordlist.

python admin\_scanner.py \[https://example.com\](https://example.com)

### **2\. The "Comprehensive Audit"**

Uses a custom large wordlist, increases threads for speed, and saves a detailed HTML report.

python admin\_scanner.py \[https://example.com\](https://example.com) \-w /usr/share/wordlists/dirb/big.txt \-t 50 \-o scan\_report.html

### **3\. The "Stealth/Internal Scan"**

Routes traffic through a local proxy (like Burp Suite or Tor) and adds a delay to evade rate limiting.

python admin\_scanner.py \[https://example.com\](https://example.com) \-p \[http://127.0.0.1:8080\](http://127.0.0.1:8080) \-d 1.5

## **📊 Reporting Formats**

### **📄 HTML Report (-o report.html)**

Generates a visually stunning, self-contained HTML dashboard featuring:

* **Executive Summary:** IP, Hostname, SSL, Location.  
* **Network Map:** Open ports table with clickable access URLs (ssh://, ftp://).  
* **Discovery Grid:** Color-coded findings with status codes, redirects, and bypass success indicators.

### **⚙️ JSON Report (-o data.json)**

Exports structured data for programmatic use or ingestion into SIEM tools.

\[  
  {  
    "url": "\[https://example.com/admin\](https://example.com/admin)",  
    "status": 403,  
    "path": "/admin",  
    "bypass": " \[Header Bypass: X-Forwarded-For\]"  
  }  
\]

## **🛑 Comparison**

| Feature | Standard Scanner | Admin Panel Hunter Pro v5.0 |
| :---- | :---- | :---- |
| **Multi-threading** | ✅ | ✅ |
| **WAF Detection** | ❌ | ✅ |
| **403 Bypass Fuzzing** | ❌ | ✅ |
| **Recursive Scanning** | ❌ | ✅ |
| **HTML Reporting** | ❌ | ✅ |
| **Backup File Mutation** | ❌ | ✅ |
| **Port Scanning** | ❌ | ✅ |

## **👨‍💻 Developer**

**Shiboshree Roy** *Cybersecurity Researcher & Tool Developer*

*Verified for authorized penetration testing environments.*