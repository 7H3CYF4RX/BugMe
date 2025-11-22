# 🚀 BugMe v3.0 - Installation & Setup Guide

## 📋 Prerequisites

### System Requirements
- **OS**: Linux (Kali, Ubuntu, Debian, etc.)
- **Python**: 3.8 or higher
- **Chrome/Chromium**: For DOM XSS detection

---

## 🔧 Installation

### Step 1: Install Chrome/Chromium

```bash
# Kali Linux / Debian / Ubuntu
sudo apt update
sudo apt install chromium-browser -y

# Or Google Chrome
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo dpkg -i google-chrome-stable_current_amd64.deb
sudo apt-get install -f
```

### Step 2: Install Python Dependencies

```bash
cd /home/viruz/Tools/BUG-ME
pip install -r requirements.txt
```

Or install manually:
```bash
pip install requests beautifulsoup4 lxml colorama selenium webdriver-manager urllib3 tqdm pyyaml html5lib
```

### Step 3: Verify Installation

```bash
python bugme.py --help
```

---

## 🎯 Quick Start

### Test on PortSwigger Labs

#### 1. DOM-based XSS Lab
```bash
python bugme.py -u "https://LAB-ID.web-security-academy.net/product?productId=1&storeId=test" -v
```

#### 2. Stored XSS Lab
```bash
python bugme.py -u "https://LAB-ID.web-security-academy.net/post?postId=1" -v
```

#### 3. Reflected XSS Lab
```bash
python bugme.py -u "https://LAB-ID.web-security-academy.net/?search=test" -v
```

#### 4. Full Domain Scan
```bash
python bugme.py -d "https://LAB-ID.web-security-academy.net/" --depth 3 -v
```

---

## 📖 Usage Examples

### Basic Scans

```bash
# Single URL scan
python bugme.py -u "https://target.com/page?param=test"

# Verbose output
python bugme.py -u "https://target.com/page?param=test" -v

# Domain crawl
python bugme.py -d "https://target.com" --depth 3

# Save results
python bugme.py -d "https://target.com" -o results.json
```

### Advanced Scans

```bash
# Multi-threaded scan
python bugme.py -d "https://target.com" --threads 20

# Custom timeout
python bugme.py -u "https://target.com/slow-page" --timeout 30

# With delay (rate limiting)
python bugme.py -d "https://target.com" --delay 1

# Custom payloads
python bugme.py -u "https://target.com" --payloads payloads/comprehensive.txt

# Through proxy (Burp Suite)
python bugme.py -u "https://target.com" --proxy http://127.0.0.1:8080
```

### Complete Command

```bash
python bugme.py \
  -d "https://target.com" \
  --depth 3 \
  --threads 10 \
  --timeout 30 \
  --delay 0.5 \
  -v \
  --output results.json \
  --html-report report.html
```

---

## 🎓 Command Line Options

```
Target Options:
  -u, --url URL              Single URL to scan
  -d, --domain DOMAIN        Domain to crawl and scan

Scan Options:
  --depth DEPTH              Crawl depth (default: 3)
  --threads THREADS          Number of threads (default: 5)
  --timeout TIMEOUT          Request timeout in seconds (default: 10)
  --delay DELAY              Delay between requests (default: 0)

Output Options:
  -v, --verbose              Verbose output
  -q, --quiet                Quiet mode (no progress bar)
  -o, --output FILE          Save results to JSON file
  --html-report FILE         Generate HTML report

Advanced Options:
  --user-agent UA            Custom User-Agent
  --cookie COOKIE            Cookie string
  --headers HEADERS          Custom headers (JSON)
  --proxy PROXY              Proxy URL (e.g., http://127.0.0.1:8080)
  --payloads FILE            Custom payloads file
  --no-verify                Disable SSL verification
```

---

## 🔍 What Gets Tested

### 1. Reflected XSS
- ✅ GET parameters
- ✅ POST parameters
- ✅ URL fragments
- ✅ Headers (future)

### 2. Stored XSS
- ✅ Comment forms
- ✅ Feedback forms
- ✅ Contact forms
- ✅ User profiles
- ✅ Any POST form

### 3. DOM-based XSS
- ✅ location.search
- ✅ location.hash
- ✅ document.URL
- ✅ window.name
- ✅ All DOM sources

### 4. Blind XSS
- ✅ Admin panels
- ✅ Log viewers
- ✅ Email notifications
- ✅ Out-of-band detection

### 5. Mutation XSS
- ✅ Browser parsing differences
- ✅ Entity-based attacks
- ✅ Namespace confusion

---

## 🎯 Detection Techniques

### Marker-Based Detection
```
1. Inject unique marker
2. Check for reflection
3. Detect context
4. Test context-specific payloads
5. Verify execution
```

### Browser Automation
```
1. Load page in headless Chrome
2. Monitor JavaScript execution
3. Track DOM mutations
4. Detect alert() calls
5. Log dangerous operations
```

### Multi-Step Testing
```
1. Submit payload via form
2. Re-fetch original page
3. Check for stored payload
4. Verify execution context
5. Report vulnerability
```

---

## 🐛 Troubleshooting

### Chrome/Chromium Not Found

```bash
# Install Chromium
sudo apt install chromium-browser

# Or install Chrome
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo dpkg -i google-chrome-stable_current_amd64.deb
```

### WebDriver Issues

```bash
# Reinstall webdriver-manager
pip uninstall webdriver-manager
pip install webdriver-manager

# Clear cache
rm -rf ~/.wdm
```

### SSL Certificate Errors

```bash
# Use --no-verify flag
python bugme.py -u "https://target.com" --no-verify
```

### Slow Scans

```bash
# Increase threads
python bugme.py -d "https://target.com" --threads 20

# Reduce timeout
python bugme.py -d "https://target.com" --timeout 5
```

---

## 📊 Output Formats

### Console Output
```
🚨 XSS VULNERABILITY FOUND! 🚨
URL:        https://target.com/page?param=test
Type:       REFLECTED XSS
Method:     GET
Parameter:  param
Payload:    <script>alert(1)</script>
Context:    html
Severity:   HIGH

PoC URL:
https://target.com/page?param=<script>alert(1)</script>
```

### JSON Output
```json
{
  "url": "https://target.com/page",
  "vulnerabilities": [
    {
      "type": "reflected_xss",
      "parameter": "param",
      "payload": "<script>alert(1)</script>",
      "context": "html",
      "severity": "high",
      "poc_url": "https://target.com/page?param=..."
    }
  ]
}
```

---

## 🎓 Tips & Best Practices

### 1. Start with Single URL
```bash
# Test one page first
python bugme.py -u "https://target.com/page?param=test" -v
```

### 2. Use Verbose Mode
```bash
# See what's happening
python bugme.py -u "URL" -v
```

### 3. Save Results
```bash
# Always save your findings
python bugme.py -d "https://target.com" -o results.json
```

### 4. Use Proxy for Manual Testing
```bash
# Send to Burp Suite
python bugme.py -u "URL" --proxy http://127.0.0.1:8080
```

### 5. Test Different Contexts
```bash
# Test various pages
python bugme.py -u "https://target.com/search?q=test"
python bugme.py -u "https://target.com/product?id=1"
python bugme.py -u "https://target.com/post?postId=1"
```

---

## 🚀 Performance Tuning

### Fast Scan (Quick Check)
```bash
python bugme.py -d "https://target.com" \
  --depth 2 \
  --threads 20 \
  --timeout 5
```

### Thorough Scan (Complete Coverage)
```bash
python bugme.py -d "https://target.com" \
  --depth 5 \
  --threads 5 \
  --timeout 30 \
  --delay 1 \
  -v
```

### Stealth Scan (Avoid Detection)
```bash
python bugme.py -d "https://target.com" \
  --threads 1 \
  --delay 2 \
  --user-agent "Mozilla/5.0..."
```

---

## 📚 Additional Resources

### Payload Files
- `payloads/comprehensive.txt` - 400+ payloads
- `payloads/reflected.txt` - Reflected XSS payloads
- `payloads/dom.txt` - DOM XSS payloads
- `payloads/polyglot.txt` - Polyglot payloads
- `payloads/waf-bypass.txt` - WAF bypass payloads

### Documentation
- `V3_ULTIMATE.md` - Complete feature guide
- `V2_ENHANCEMENTS.md` - v2.0 changelog
- `PORTSWIGGER_GUIDE.md` - PortSwigger lab guide
- `README.md` - Main documentation

---

## ✅ Verification

### Test Installation
```bash
# Run help
python bugme.py --help

# Test on safe site
python bugme.py -u "http://testphp.vulnweb.com/search.php?test=query" -v
```

### Expected Output
```
[*] Initializing BugMe Scanner...
[*] Scanning single URL: ...
[1] Testing Reflected XSS (GET)
[2] Testing Stored XSS (POST forms)
[3] Testing DOM-based XSS
[4] Testing Blind XSS
[5] Testing Mutation XSS (mXSS)
```

---

## 🎉 You're Ready!

**BugMe v3.0 is now installed and ready to find ALL types of XSS vulnerabilities!**

Start with:
```bash
python bugme.py -u "YOUR-TARGET-URL" -v
```

**Happy Hunting! 🚀**
