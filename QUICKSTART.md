# 🚀 BugMe Quick Start Guide

## Installation (5 minutes)

### Step 1: Install Dependencies
```bash
cd /home/viruz/Tools/BUG-ME
pip install -r requirements.txt
```

### Step 2: Verify Installation
```bash
python bugme.py --help
```

You should see the help menu with all available options.

---

## Basic Usage

### 1. Scan a Single URL
```bash
python bugme.py -u "http://testphp.vulnweb.com/search.php?test=query"
```

**What happens:**
- Scans only the provided URL
- Tests all parameters (in this case: `test`)
- Generates context-aware payloads
- Verifies with browser automation
- Shows live results

### 2. Crawl and Scan a Domain
```bash
python bugme.py -d "http://testphp.vulnweb.com"
```

**What happens:**
- Crawls the entire domain (depth: 3)
- Discovers all URLs with parameters
- Tests each URL for XSS
- Shows progress bar
- Displays summary at the end

### 3. Fast Scan (No Browser Verification)
```bash
python bugme.py -u "http://testphp.vulnweb.com/search.php?test=query" --no-verify
```

**Use when:**
- You want faster results
- Browser automation is not available
- You'll manually verify findings

### 4. Generate Reports
```bash
python bugme.py -d "http://testphp.vulnweb.com" \
  -o results.json \
  --html-report report.html
```

**Output:**
- `results.json` - Machine-readable JSON
- `report.html` - Beautiful HTML report (open in browser)

---

## Common Scenarios

### Scenario 1: Testing with Authentication
```bash
python bugme.py -d "https://example.com" \
  --cookie "session=abc123; user=admin"
```

### Scenario 2: Using with Burp Suite
```bash
python bugme.py -u "https://example.com/page.php?id=1" \
  --proxy "http://127.0.0.1:8080"
```

### Scenario 3: Custom Payloads
```bash
# Create custom_payloads.txt with your payloads
python bugme.py -u "https://example.com/search.php?q=test" \
  --payloads custom_payloads.txt
```

### Scenario 4: Deep Crawl with More Threads
```bash
python bugme.py -d "https://example.com" \
  --depth 5 \
  --threads 10 \
  --timeout 15
```

### Scenario 5: Quiet Mode (Only Show Vulnerabilities)
```bash
python bugme.py -d "https://example.com" -q
```

---

## Understanding the Output

### Color Codes
- 🔵 **CYAN** `[*]` - Information/Progress
- 🟢 **GREEN** `[+]` - Success/Found
- 🟡 **YELLOW** `[!]` - Warning
- 🔴 **RED** `[-]` - Error
- 🔴 **RED BOLD** `[V]` - Vulnerability Found!

### Vulnerability Output
```
════════════════════════════════════════════════════════════
[V] XSS VULNERABILITY FOUND!
════════════════════════════════════════════════════════════

[U] URL: https://example.com/search.php
[P] Parameter: q
[P] Payload: <img src=x onerror=alert(1)>
[P] Context: html
[+] Verified: YES (Browser execution confirmed)

[P] Proof of Concept:
https://example.com/search.php?q=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E

[!] Severity: HIGH
```

**What this means:**
- **URL**: The vulnerable page
- **Parameter**: Which parameter is vulnerable
- **Payload**: The XSS payload that worked
- **Context**: Where the injection occurs (html/js/attribute/url)
- **Verified**: Whether browser confirmed execution
- **PoC**: Ready-to-use exploit URL
- **Severity**: Risk level (Critical/High/Medium/Low)

---

## Testing Targets (Practice)

### Safe, Legal Testing Targets:

1. **DVWA** (Damn Vulnerable Web Application)
   ```bash
   # Install locally first
   python bugme.py -d "http://localhost/dvwa" \
     --cookie "security=low; PHPSESSID=your_session"
   ```

2. **bWAPP** (Buggy Web Application)
   ```bash
   python bugme.py -d "http://localhost/bWAPP"
   ```

3. **Test PHP Vulnweb** (Public test site)
   ```bash
   python bugme.py -d "http://testphp.vulnweb.com"
   ```

4. **Google XSS Game**
   ```bash
   python bugme.py -u "https://xss-game.appspot.com/level1/frame?query=test"
   ```

---

## Troubleshooting

### Problem: "ChromeDriver not found"
**Solution:**
```bash
# Option 1: Install Chrome/Chromium
sudo apt-get install chromium-browser

# Option 2: Use --no-verify flag
python bugme.py -u "URL" --no-verify
```

### Problem: "Connection timeout"
**Solution:**
```bash
# Increase timeout
python bugme.py -u "URL" --timeout 30
```

### Problem: "Too many requests / Rate limited"
**Solution:**
```bash
# Add delay and reduce threads
python bugme.py -d "URL" --delay 1 --threads 3
```

### Problem: "SSL Certificate Error"
**Solution:**
```bash
# Tool handles SSL automatically
# If using proxy, configure proxy SSL settings
```

---

## Tips for Better Results

### 1. Start Small
- Test single URLs first before full domain crawls
- Use `--no-verify` for initial reconnaissance
- Then verify interesting findings with browser

### 2. Adjust Performance
- **Fast scan**: `--threads 10 --no-verify`
- **Thorough scan**: `--threads 3 --delay 1 --depth 5`
- **Balanced**: Default settings

### 3. Use Reports
- Always save JSON for records: `-o results.json`
- Generate HTML for stakeholders: `--html-report report.html`
- Use verbose mode for debugging: `-v`

### 4. Combine with Other Tools
- Use with Burp Suite: `--proxy http://127.0.0.1:8080`
- Export results and import to other tools
- Use custom payloads from other sources

---

## Next Steps

1. ✅ **Install and test** with safe targets
2. ✅ **Read the full README** for advanced features
3. ✅ **Practice** on intentionally vulnerable apps
4. ✅ **Get authorization** before testing real targets
5. ✅ **Report findings** responsibly

---

## Quick Reference

### Most Common Commands

```bash
# Single URL
python bugme.py -u "URL"

# Domain crawl
python bugme.py -d "DOMAIN"

# With reports
python bugme.py -d "DOMAIN" -o results.json --html-report report.html

# Fast mode
python bugme.py -d "DOMAIN" --no-verify --threads 10

# With authentication
python bugme.py -d "DOMAIN" --cookie "session=xyz"

# Through proxy
python bugme.py -u "URL" --proxy "http://127.0.0.1:8080"

# Verbose output
python bugme.py -u "URL" -v

# Help
python bugme.py --help
```

---

## Support

- 📖 **Full Documentation**: See `README.md`
- 🔧 **Implementation Details**: See `IMPLEMENTATION_PLAN.md`
- 🐛 **Issues**: Check existing issues or create new one
- 💡 **Questions**: Review documentation first

---

**Happy (Ethical) Hacking! 🛡️**

Remember: Only test systems you own or have explicit permission to test!
