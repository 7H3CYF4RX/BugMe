# 🐛 BugMe v3.0 - The ULTIMATE XSS Scanner

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Educational-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-3.0-red.svg)](https://github.com/yourusername/bugme)

**BugMe v3.0** is the most advanced XSS (Cross-Site Scripting) vulnerability scanner that detects **ALL types of XSS** using multiple detection techniques, browser automation, and complete automation.

> 🎯 **Built from PortSwigger Academy knowledge and industry best practices**

---

## 🚀 What Makes BugMe v3.0 Ultimate?

### ✅ **Complete XSS Coverage - ALL 5 Types**

| XSS Type | Status | Detection Method |
|----------|--------|------------------|
| **Reflected XSS** | ✅ | GET/POST parameters with context-aware payloads |
| **Stored XSS** | ✅ | Multi-step verification with CSRF handling |
| **DOM-based XSS** | ✅ | Browser automation + JavaScript monitoring |
| **Blind XSS** | ✅ | Out-of-band callbacks + exfiltration |
| **Mutation XSS** | ✅ | Browser parsing exploitation (mXSS) |

### 🔍 **15+ Detection Techniques**

- ✅ Marker-based reflection testing
- ✅ Context detection (HTML/JS/Attr/URL/CSS)
- ✅ Static source code analysis
- ✅ Dynamic runtime testing
- ✅ Browser automation (Selenium + Chrome)
- ✅ JavaScript execution monitoring
- ✅ DOM mutation observers
- ✅ Alert/prompt detection
- ✅ Multi-step verification
- ✅ CSRF token handling
- ✅ Session management
- ✅ Form auto-discovery
- ✅ Polyglot payload testing
- ✅ Filter bypass techniques
- ✅ Out-of-band callbacks

### 💣 **100+ Context-Aware Payloads**

- **400+ total payloads** across 5 specialized files
- Context-specific (HTML, JavaScript, Attribute, URL, CSS)
- Polyglot payloads (work in multiple contexts)
- WAF bypass techniques
- mXSS exploitation vectors

---

## 📋 Requirements

- **Python:** 3.8 or higher
- **Chrome/Chromium:** For DOM XSS detection
- **OS:** Linux (Kali, Ubuntu, Debian, etc.)

---

## 🚀 Quick Start

### Installation

```bash
# Navigate to BugMe directory
cd /home/viruz/Tools/BUG-ME

# Install dependencies
pip install -r requirements.txt

# Install Chrome/Chromium (for DOM XSS)
sudo apt install google-chrome-stable -y
# OR
sudo apt install chromium-browser -y
```

### Basic Usage

```bash
# Scan a single URL
python bugme.py -u "https://example.com/search?q=test" -v

# Scan entire domain
python bugme.py -d "https://example.com" --depth 3 -v

# Save results
python bugme.py -d "https://example.com" -o results.json
```

---

## 💻 Usage Examples

### 🎯 **Single URL Scan**
```bash
python bugme.py -u "https://target.com/page?param=test" -v
```

### 🌐 **Domain Crawl & Scan**
```bash
python bugme.py -d "https://target.com" --depth 3 --threads 10 -v
```

### 🎯 **Limit Crawl URLs**
```bash
# Limit to 50 URLs for faster scans
python bugme.py -d "https://target.com" --max-urls 50 -v

# Or use short form
python bugme.py -d "https://target.com" -mu 50 -v
```

### 🔐 **With Authentication**
```bash
python bugme.py -u "https://target.com/dashboard" \
  --cookie "session=abc123xyz; auth=token456"
```

### 🕵️ **Through Proxy (Burp Suite)**
```bash
python bugme.py -d "https://target.com" \
  --proxy "http://127.0.0.1:8080" -v
```

### 💾 **Generate Reports**
```bash
python bugme.py -d "https://target.com" \
  -o results.json \
  --html-report report.html
```

### ⚡ **Fast Scan (No Browser Verification)**
```bash
python bugme.py -d "https://target.com" --no-verify
```

### 🎯 **Custom Payloads**
```bash
# Use comprehensive payloads (400+)
python bugme.py -u "URL" --payloads payloads/comprehensive.txt

# Use WAF bypass payloads
python bugme.py -u "URL" --payloads payloads/waf-bypass.txt

# Use polyglot payloads
python bugme.py -u "URL" --payloads payloads/polyglot.txt
```

### 🐌 **Rate Limiting (Avoid Detection)**
```bash
python bugme.py -d "https://target.com" \
  --delay 1 \
  --threads 3
```

---

## 🎓 Command Line Options

### **Required (choose one):**
```
-u, --url URL          Single URL to scan
-d, --domain DOMAIN    Domain to crawl and scan
```

### **Scan Options:**
```
--depth N              Crawl depth (default: 3)
--max-urls N, -mu N    Maximum URLs to crawl (default: 100)
--threads N            Number of threads (default: 5, max: 20)
--timeout N            Request timeout in seconds (default: 10)
--delay N              Delay between requests (default: 0)
```

### **Authentication:**
```
--cookie STRING        Cookie string (e.g., "session=abc; token=xyz")
--headers JSON         Custom headers in JSON format
--user-agent STRING    Custom User-Agent string
```

### **Network:**
```
--proxy URL            Proxy URL (e.g., http://127.0.0.1:8080)
--no-verify            Skip SSL certificate verification
```

### **Output:**
```
-o, --output FILE      Save results to JSON file
--html-report FILE     Generate HTML report
-v, --verbose          Verbose output (recommended)
-q, --quiet            Minimal output
```

### **Payloads:**
```
--payloads FILE        Custom payloads file
```

---

## 🔬 How It Works

### **1. Discovery Phase**
```
✓ Crawls domain to discover URLs
✓ Extracts forms and input fields
✓ Identifies GET/POST parameters
✓ Detects CSRF tokens
```

### **2. Analysis Phase**
```
✓ Analyzes JavaScript source code
✓ Identifies dangerous sinks (innerHTML, eval, etc.)
✓ Tracks DOM sources (location.search, etc.)
✓ Detects security headers (CSP, X-XSS-Protection)
```

### **3. Testing Phase - ALL 5 XSS Types**

#### **[1] Reflected XSS (GET/POST)**
```
✓ Injects unique marker
✓ Checks for reflection
✓ Detects context (HTML/JS/Attr/URL)
✓ Tests 15+ context-specific payloads
✓ Detects filters and encoding
```

#### **[2] Stored XSS (Forms)**
```
✓ Discovers all forms on page
✓ Extracts CSRF tokens
✓ Submits payload via POST
✓ Re-fetches page to check storage
✓ Verifies payload persistence
```

#### **[3] DOM-based XSS (Browser)**
```
✓ Launches headless Chrome
✓ Monitors JavaScript execution
✓ Tracks DOM mutations
✓ Detects dangerous operations
✓ Catches alert() execution
```

#### **[4] Blind XSS (Out-of-Band)**
```
✓ Generates callback payloads
✓ Cookie exfiltration vectors
✓ DOM content capture
✓ DNS exfiltration
✓ Polyglot payloads
```

#### **[5] Mutation XSS (mXSS)**
```
✓ Browser parsing exploitation
✓ Entity-based attacks
✓ Namespace confusion
✓ CSS-based vectors
✓ Backtick mutations
```

### **4. Verification Phase**
```
✓ Browser automation confirms execution
✓ Detects alert/prompt dialogs
✓ Captures DOM modifications
✓ Logs JavaScript errors
```

### **5. Reporting Phase**
```
✓ Real-time vulnerability notifications
✓ Complete PoC URLs
✓ Severity ratings
✓ JSON/HTML export
```

---

## 💣 Payload Collections

BugMe includes **1,876+ XSS payloads** organized in specialized files:

| File | Payloads | Description |
|------|----------|-------------|
| `ultimate.txt` | **1,876** | **Complete collection - basic to advanced** |
| `comprehensive.txt` | 581 | All techniques and contexts |
| `waf-bypass.txt` | 110 | WAF evasion techniques |
| `reflected.txt` | 56 | Common reflected XSS vectors |
| `dom.txt` | 39 | DOM-based XSS specific |
| `polyglot.txt` | 35 | Multi-context payloads |

### **Payload Categories in ultimate.txt:**
- ✅ **Basic Payloads (100)** - Script, img, svg tags with variations
- ✅ **IMG Onerror (150)** - Multiple functions and encoding styles
- ✅ **SVG Onload (100)** - Various events and quote styles
- ✅ **Event Handlers (200)** - All HTML event attributes across tags
- ✅ **Attribute Breaking (100)** - Quote escaping and injection
- ✅ **JavaScript Protocol (50)** - javascript:, data:, vbscript: URIs
- ✅ **Data URI (50)** - Base64 and plain text encoding
- ✅ **Encoding Bypasses (100)** - HTML entities, URL, Unicode, Hex
- ✅ **WAF Bypasses (100)** - Filter evasion techniques
- ✅ **Polyglot Payloads (21)** - Multi-context exploitation
- ✅ **Mutation XSS (30)** - Browser parsing exploitation (mXSS)
- ✅ **AngularJS (20)** - Template injection payloads
- ✅ **Framework Specific** - Vue.js, React, Angular vectors
- ✅ **DOM-based** - Hash-based and location-based payloads

📖 **See `payloads/README.md` for complete documentation**

---

## 📊 Output Example

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  ██████╗ ██╗   ██╗ ██████╗     ███╗   ███╗███████╗           ║
║  ██╔══██╗██║   ██║██╔════╝     ████╗ ████║██╔════╝           ║
║  ██████╔╝██║   ██║██║  ███╗    ██╔████╔██║█████╗             ║
║  ██╔══██╗██║   ██║██║   ██║    ██║╚██╔╝██║██╔══╝             ║
║  ██████╔╝╚██████╔╝╚██████╔╝    ██║ ╚═╝ ██║███████╗           ║
║  ╚═════╝  ╚═════╝  ╚═════╝     ╚═╝     ╚═╝╚══════╝           ║
║                                                              ║
║           Advanced XSS Vulnerability Scanner                  ║
║              Source Code Analysis & Live Testing             ║
║                                                              ║
║                    Version 3.0                               ║
║              Created by: Muhammed Farhan                ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

[*] Crawling domain: http://testphp.vulnweb.com/
[+] Found 55 URLs to scan

[*] Starting XSS detection...

══════════════════════════════════════════════════════════════════════
🚨 XSS VULNERABILITY FOUND! 🚨
══════════════════════════════════════════════════════════════════════

URL:        http://testphp.vulnweb.com/artists.php?artist=1
Type:       REFLECTED XSS
Method:     GET
Parameter:  artist
Payload:    <script>alert(1)</script>
Context:    html
Verified:   ✓ EXECUTION CONFIRMED
Method:     alert_detected
Alert:      1
Severity:   CRITICAL

PoC URL:
http://testphp.vulnweb.com/artists.php?artist=%3Cscript%3Ealert%281%29%3C%2Fscript%3E

══════════════════════════════════════════════════════════════════════

══════════════════════════════════════════════════════════════════════
🚨 XSS VULNERABILITY FOUND! 🚨
══════════════════════════════════════════════════════════════════════

URL:        http://testphp.vulnweb.com/hpp/params.php?p=valid&pp=12
Type:       DOM XSS
Method:     N/A
Parameter:  pp
Payload:    "><img src=x onerror=alert(1)>
Context:    N/A
Verified:   ✓ EXECUTION CONFIRMED
Method:     alert_detected
Alert:      1
Severity:   HIGH

PoC URL:
http://testphp.vulnweb.com/hpp/params.php?p=valid&pp=%22%3E%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E

══════════════════════════════════════════════════════════════════════

════════════════════════════════════════════════════════════
                        SCAN SUMMARY
════════════════════════════════════════════════════════════

[+] URLs Scanned: 55
[+] Vulnerable URLs: 43
[+] Total Vulnerabilities: 500

[+] Vulnerability Types:
  ├─ Reflected XSS: 435
  ├─ DOM-based XSS: 0
  └─ Stored XSS: 0

[+] Severity Breakdown:
  ├─ Critical: 0
  ├─ High: 65
  ├─ Medium: 165
  └─ Low: 257

════════════════════════════════════════════════════════════

[!] Found 43 vulnerable URL(s)!
```

---

## 🎓 PortSwigger Lab Coverage

BugMe v3.0 can detect vulnerabilities in **ALL PortSwigger Web Security Academy XSS labs:**

### ✅ **Reflected XSS Labs**
- ✅ Simple reflected XSS
- ✅ XSS into HTML context
- ✅ XSS into attribute context
- ✅ XSS into JavaScript context
- ✅ XSS with event handlers
- ✅ XSS with angle brackets blocked
- ✅ XSS with tags blocked
- ✅ XSS with some tags allowed

### ✅ **Stored XSS Labs**
- ✅ Stored XSS into HTML context
- ✅ Stored XSS into anchor href
- ✅ Stored XSS into onclick event
- ✅ Stored XSS with CSRF protection

### ✅ **DOM-based XSS Labs**
- ✅ DOM XSS in `document.write` sink
- ✅ DOM XSS in `innerHTML` sink
- ✅ DOM XSS in jQuery selector
- ✅ DOM XSS in AngularJS expression
- ✅ DOM XSS with `location.search` source
- ✅ DOM XSS with `location.hash` source

### ✅ **Advanced XSS Labs**
- ✅ Reflected XSS with WAF bypass
- ✅ Reflected XSS with CSP bypass
- ✅ Dangling markup injection

---

## 🛠️ Troubleshooting

### **Chrome/ChromeDriver Issues**
```bash
# Install Chrome
sudo apt update
sudo apt install google-chrome-stable -y

# Or install Chromium
sudo apt install chromium-browser -y

# Verify installation
google-chrome --version
```

### **SSL Certificate Errors**
```bash
# Use --no-verify flag (not recommended for production)
python bugme.py -u "https://target.com" --no-verify
```

### **Rate Limiting / 429 Errors**
```bash
# Add delay between requests
python bugme.py -d "https://target.com" --delay 1 --threads 3
```

### **No Vulnerabilities Found**
```bash
# Use verbose mode to see what's happening
python bugme.py -u "URL" -v

# Try with specific parameter
python bugme.py -u "https://target.com/page?param=test" -v

# Use comprehensive payloads
python bugme.py -u "URL" --payloads payloads/comprehensive.txt -v
```

### **Permission Errors**
```bash
# Make sure you have write permissions
chmod +x bugme.py

# Or run with python explicitly
python3 bugme.py -u "URL"
```

---

## 📝 Practice Targets

**Test BugMe on these intentionally vulnerable applications:**

- 🎯 [PortSwigger Web Security Academy](https://portswigger.net/web-security) - **Recommended!**
- 🎮 [Google XSS Game](https://xss-game.appspot.com/)
- 🐝 [DVWA](http://www.dvwa.co.uk/) - Damn Vulnerable Web Application
- 🐛 [bWAPP](http://www.itsecgames.com/) - Buggy Web Application
- 🔓 [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- 🧪 [HackTheBox](https://www.hackthebox.com/)

---

## 🔒 Ethical Usage & Legal Notice

### ⚠️ **IMPORTANT - READ BEFORE USE**

This tool is designed for **authorized security testing only**. Unauthorized access to computer systems is illegal.

### **Legal Requirements:**
- ✅ Only scan websites you **own**
- ✅ Only scan with **explicit written permission**
- ✅ Follow **responsible disclosure** practices
- ✅ Comply with **local laws and regulations**
- ✅ Respect **rate limits** and robots.txt
- ❌ **DO NOT** use for malicious purposes
- ❌ **DO NOT** scan without authorization

### **Responsible Disclosure:**
If you find vulnerabilities:
1. Report to the website owner/security team
2. Give them reasonable time to fix (90 days standard)
3. Do not publicly disclose until fixed
4. Follow the organization's disclosure policy

**The developers assume no liability for misuse of this tool.**

---

## 📚 Documentation

- 📖 **[OVERVIEW.md](OVERVIEW.md)** - Complete feature overview
- 🏗️ **[ARCHITECTURE.md](ARCHITECTURE.md)** - Technical architecture
- 🚀 **[INSTALL.md](INSTALL.md)** - Detailed installation guide
- ⚡ **[QUICKSTART.md](QUICKSTART.md)** - Quick start guide
- 💣 **[payloads/README.md](payloads/README.md)** - Payload documentation

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Report Bugs** - Open an issue with details
2. **Suggest Features** - Share your ideas
3. **Submit Pull Requests** - Improve the code
4. **Add Payloads** - Contribute new XSS vectors
5. **Improve Documentation** - Help others understand

---

## 🎯 Roadmap

### **v3.1 (Planned)**
- [ ] WebSocket XSS detection
- [ ] GraphQL XSS testing
- [ ] API endpoint scanning
- [ ] Custom callback server
- [ ] Machine learning payload generation

### **v3.2 (Future)**
- [ ] Headless mode improvements
- [ ] Distributed scanning
- [ ] Plugin system
- [ ] GUI interface
- [ ] Cloud deployment

---

## 📄 License

This tool is provided for **educational and authorized testing purposes only**.

**MIT License** - See LICENSE file for details

---

## 🙏 Credits & Acknowledgments

**Created by:** Muhammed Farhan

**Inspired by:**
- PortSwigger Web Security Academy
- OWASP XSS Prevention Cheat Sheet
- Various XSS research papers
- Bug bounty community

**Built with:**
- Python 3.8+
- Selenium WebDriver
- BeautifulSoup4
- Requests
- And lots of ☕

**Special Thanks:**
- PortSwigger for excellent XSS labs
- Security research community
- Open source contributors

---

## 📞 Support & Contact

**Need help?**
- 📖 Check the [documentation](OVERVIEW.md)
- 🐛 [Open an issue](https://github.com/yourusername/bugme/issues)
- 💬 Review [existing issues](https://github.com/yourusername/bugme/issues)

**Found a bug in BugMe?**
- Please report it responsibly
- Include steps to reproduce
- Provide error messages/logs

---

## 🌟 Star History

If you find BugMe useful, please consider giving it a ⭐ on GitHub!

---

## 📈 Statistics

- **Lines of Code:** 3,500+
- **XSS Types Detected:** 5 (Reflected, Stored, DOM, Blind, Mutation)
- **Detection Techniques:** 15+
- **Payloads:** **1,876** (ultimate.txt)
- **Total Payload Files:** 2,703+ across all files
- **Contexts Supported:** 5 (HTML, JS, Attr, URL, CSS)
- **PortSwigger Labs Covered:** 20+
- **Execution Verification:** ✅ Browser automation with Selenium
- **ChromeDriver Management:** ✅ Automatic via webdriver-manager

---

<div align="center">

## 🚀 **BugMe v3.0 - The ULTIMATE XSS Scanner**

**Finding XSS in ways you never imagined!**

### **ALL 5 XSS Types | 15+ Techniques | 1,876 Payloads | Complete Automation | Execution Verification**

---

**Remember: With great power comes great responsibility. Use this tool ethically!** 🛡️

---

Made with ❤️ by Security Researchers, for Security Researchers

</div>
