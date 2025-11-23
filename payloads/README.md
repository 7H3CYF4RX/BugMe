# BugMe XSS Payloads Collection

This directory contains comprehensive XSS payload collections for various testing scenarios.

---

## 📁 Available Payload Files

### 1. **comprehensive.txt** (300+ payloads)
**The complete collection** - All payloads from basic to advanced with evasion techniques.

**Sections included:**
- Basic payloads
- Event handlers
- Attribute breaking
- JavaScript context
- URL context
- Case variation evasion
- Null byte injection
- Comment injection
- Encoding evasion
- Filter bypass
- Advanced vectors
- Polyglot payloads
- WAF bypass techniques
- Mutation XSS (mXSS)
- DOM-based XSS
- Advanced evasion
- Protocol handlers
- Less common tags
- CSS-based XSS
- Browser-specific
- Obfuscation techniques
- CSP bypass attempts
- Breaking out of tags
- Advanced filter bypass
- Exotic vectors
- Context-specific payloads
- Real-world scenarios
- Shortest payloads

**Usage:**
```bash
python bugme.py -u "URL" --payloads payloads/comprehensive.txt
```

---

### 2. **reflected.txt** (40+ payloads)
**Focused on reflected XSS** - Most common and effective payloads for reflected XSS.

**Categories:**
- Basic script tags
- Image-based vectors
- SVG-based vectors
- Event handlers
- Attribute breaking
- Case variation
- Encoding techniques
- Filter bypass
- URL context
- Advanced vectors

**Usage:**
```bash
python bugme.py -u "URL" --payloads payloads/reflected.txt
```

---

### 3. **dom.txt** (20+ payloads)
**DOM-based XSS specific** - Payloads targeting DOM manipulation vulnerabilities.

**Categories:**
- Location-based
- document.write exploitation
- innerHTML exploitation
- eval-based
- setTimeout/setInterval
- Function constructor
- Location manipulation
- postMessage
- localStorage/sessionStorage

**Usage:**
```bash
python bugme.py -u "URL#payload" --payloads payloads/dom.txt
```

---

### 4. **polyglot.txt** (15+ payloads)
**Multi-context payloads** - Payloads that work across multiple contexts.

**Features:**
- Short polyglots
- Medium polyglots
- Advanced polyglots
- Super polyglots
- Context-agnostic
- Multi-browser compatible
- Universal polyglots

**Usage:**
```bash
python bugme.py -u "URL" --payloads payloads/polyglot.txt
```

---

### 5. **waf-bypass.txt** (50+ payloads)
**WAF evasion techniques** - Payloads designed to bypass Web Application Firewalls.

**WAF-specific bypasses:**
- Cloudflare bypass
- ModSecurity bypass
- Akamai bypass
- Imperva bypass
- AWS WAF bypass
- Generic WAF bypass techniques

**Techniques:**
- Unicode encoding
- Hex encoding
- Octal encoding
- Base64 encoding
- String concatenation
- Character code
- Comment injection
- Nested tags
- Case variation
- Null byte
- Tab/newline
- No space
- Backticks
- Template strings
- Indirect eval
- Function constructor

**Usage:**
```bash
python bugme.py -u "URL" --payloads payloads/waf-bypass.txt
```

---

## 🎯 Choosing the Right Payload File

### Quick Decision Guide

| Scenario | Recommended File | Why |
|----------|-----------------|-----|
| Initial testing | `reflected.txt` | Fast, common vectors |
| Comprehensive scan | `comprehensive.txt` | All techniques covered |
| DOM XSS suspected | `dom.txt` | Specialized for DOM |
| WAF detected | `waf-bypass.txt` | Evasion techniques |
| Unknown context | `polyglot.txt` | Works everywhere |
| Time-limited | `reflected.txt` | Quick and effective |
| Thorough audit | `comprehensive.txt` | Nothing missed |

---

## 💡 Usage Examples

### Example 1: Quick Test with Reflected Payloads
```bash
python bugme.py -u "https://example.com/search.php?q=test" \
  --payloads payloads/reflected.txt
```

### Example 2: Comprehensive Scan
```bash
python bugme.py -d "https://example.com" \
  --payloads payloads/comprehensive.txt \
  --threads 5
```

### Example 3: WAF Bypass Testing
```bash
python bugme.py -u "https://example.com/page.php?id=1" \
  --payloads payloads/waf-bypass.txt \
  --delay 1
```

### Example 4: DOM XSS Testing
```bash
python bugme.py -u "https://example.com/page.html#test" \
  --payloads payloads/dom.txt
```

### Example 5: Polyglot Testing
```bash
python bugme.py -u "https://example.com/search?q=test" \
  --payloads payloads/polyglot.txt \
  -v
```

---

## 📊 Payload Statistics

| File | Payloads | Size | Best For |
|------|----------|------|----------|
| comprehensive.txt | 300+ | ~25KB | Complete testing |
| reflected.txt | 40+ | ~2KB | Quick scans |
| dom.txt | 20+ | ~1KB | DOM XSS |
| polyglot.txt | 15+ | ~2KB | Unknown context |
| waf-bypass.txt | 50+ | ~4KB | WAF evasion |

---

## 🔧 Creating Custom Payloads

### Format
Each payload should be on a new line:
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### Comments
Use `#` for comments:
```
# This is a comment
<script>alert(1)</script>  # This payload works in HTML context
```

### Example Custom File
```bash
# Create custom.txt
cat > payloads/custom.txt << 'EOF'
# My custom payloads
<script>alert('Custom')</script>
<img src=x onerror=alert('Custom')>
EOF

# Use it
python bugme.py -u "URL" --payloads payloads/custom.txt
```

---

## 🎓 Understanding Payload Types

### 1. Basic Payloads
Simple, straightforward XSS vectors:
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
```

### 2. Context-Aware Payloads
Designed for specific injection contexts:
```html
HTML Context: <script>alert(1)</script>
Attribute Context: " onfocus=alert(1) autofocus="
JavaScript Context: '; alert(1); //
URL Context: javascript:alert(1)
```

### 3. Evasion Payloads
Bypass filters and WAFs:
```html
Case Variation: <ScRiPt>alert(1)</ScRiPt>
Encoding: <script>alert(String.fromCharCode(88,83,83))</script>
Obfuscation: <img src=x onerror=eval(atob('YWxlcnQoMSk='))>
```

### 4. Polyglot Payloads
Work in multiple contexts:
```html
'"><img src=x onerror=alert(1)>
```

---

## ⚠️ Important Notes

### Legal & Ethical
- **Only use on authorized targets**
- Get explicit permission before testing
- Follow responsible disclosure
- Comply with local laws

### Best Practices
1. **Start with reflected.txt** for quick testing
2. **Use comprehensive.txt** for thorough audits
3. **Try waf-bypass.txt** if payloads are blocked
4. **Use polyglot.txt** when context is unknown
5. **Create custom files** for specific scenarios

### Performance Tips
- Smaller payload files = faster scans
- Use `--no-verify` for initial testing
- Add `--delay` to avoid rate limiting
- Reduce `--threads` if server is slow

---

## 🔍 Payload Testing Workflow

### Step 1: Initial Test
```bash
python bugme.py -u "URL" --payloads payloads/reflected.txt --no-verify
```

### Step 2: If Blocked
```bash
python bugme.py -u "URL" --payloads payloads/waf-bypass.txt
```

### Step 3: Comprehensive
```bash
python bugme.py -u "URL" --payloads payloads/comprehensive.txt
```

### Step 4: Verify
```bash
python bugme.py -u "URL" --payloads payloads/reflected.txt -v
```

---

## 📚 Additional Resources

### Learning
- OWASP XSS Guide
- PortSwigger XSS Cheat Sheet
- HackerOne XSS Reports
- PayloadsAllTheThings

### Testing Targets
- DVWA (Damn Vulnerable Web Application)
- bWAPP (Buggy Web Application)
- Google XSS Game
- PortSwigger Web Security Academy

---

## 🤝 Contributing Payloads

### Found a new payload?
1. Test it thoroughly
2. Add to appropriate file
3. Document the context
4. Add comments explaining usage

### Payload Submission Format
```
# Description of payload
# Context: HTML/JS/Attribute/URL
# Bypasses: Filter/WAF name
<your-payload-here>
```

---

## 📞 Support

For questions about payloads:
- Check the main README.md
- Review QUICKSTART.md
- See IMPLEMENTATION_PLAN.md

---

**Remember: Use these payloads responsibly and ethically!** 🛡️

*BugMe Payload Collection - Comprehensive XSS Testing*
