"""
Source code analyzer to identify sinks, sources, and contexts
"""
from utils.parser import HTMLParser, JSParser
import re

class SourceAnalyzer:
    """Analyze source code for XSS vulnerabilities"""
    
    def __init__(self, config):
        self.config = config
    
    def analyze(self, html, url):
        """Analyze HTML source code"""
        soup = HTMLParser.parse(html)
        
        analysis = {
            'url': url,
            'sinks': [],
            'sources': [],
            'contexts': [],
            'security_headers': {},
            'scripts': [],
            'forms': []
        }
        
        # Extract and analyze scripts
        scripts = HTMLParser.extract_scripts(soup)
        for script in scripts:
            if isinstance(script, str) and not script.startswith('http'):
                # Inline script
                sinks = JSParser.find_sinks(script)
                sources = JSParser.find_sources(script)
                
                analysis['sinks'].extend(sinks)
                analysis['sources'].extend(sources)
                analysis['scripts'].append({
                    'type': 'inline',
                    'content': script[:200],
                    'sinks': sinks,
                    'sources': sources
                })
        
        # Extract forms
        forms = HTMLParser.extract_forms(soup, url)
        analysis['forms'] = forms
        
        return analysis
    
    def detect_context(self, html, marker):
        """Detect the context where input is reflected"""
        if marker not in html:
            return 'not_reflected'
        
        soup = HTMLParser.parse(html)
        reflections = HTMLParser.find_reflection(html, marker)
        
        if not reflections:
            return 'unknown'
        
        # Determine primary context
        contexts = [r['location'] for r in reflections]
        
        if 'text' in contexts:
            # Check if inside script tag
            if re.search(rf'<script[^>]*>.*{re.escape(marker)}.*</script>', html, re.DOTALL | re.IGNORECASE):
                return 'javascript'
            return 'html'
        
        if 'attribute' in contexts:
            # Check which attribute
            for reflection in reflections:
                if reflection['location'] == 'attribute':
                    context_info = reflection['context']
                    if 'href' in context_info or 'src' in context_info:
                        return 'url'
                    if 'on' in context_info:  # Event handlers
                        return 'javascript'
                    return 'attribute'
        
        return 'html'
    
    def detect_filters(self, original_payload, reflected_payload):
        """Detect what filters are applied"""
        filters = []
        
        if original_payload == reflected_payload:
            return filters
        
        # Check for HTML encoding
        if '&lt;' in reflected_payload or '&gt;' in reflected_payload:
            filters.append('html_encode')
        
        # Check for quote escaping
        if '\\"' in reflected_payload or "\\'" in reflected_payload:
            filters.append('quote_escape')
        
        # Check for script tag removal
        if '<script>' in original_payload.lower() and '<script>' not in reflected_payload.lower():
            filters.append('script_removal')
        
        # Check for event handler removal
        if 'onerror' in original_payload.lower() and 'onerror' not in reflected_payload.lower():
            filters.append('event_handler_removal')
        
        # Check for URL encoding
        if '%' in reflected_payload and '%' not in original_payload:
            filters.append('url_encode')
        
        return filters
    
    def analyze_csp(self, headers):
        """Analyze Content Security Policy"""
        csp = headers.get('Content-Security-Policy', '')
        
        if not csp:
            return {
                'present': False,
                'strict': False,
                'allows_inline': True,
                'allows_eval': True
            }
        
        return {
            'present': True,
            'strict': 'strict-dynamic' in csp,
            'allows_inline': "'unsafe-inline'" in csp,
            'allows_eval': "'unsafe-eval'" in csp,
            'policy': csp
        }
    
    def check_security_headers(self, headers):
        """Check for security headers"""
        security_headers = {}
        
        # X-XSS-Protection
        xss_protection = headers.get('X-XSS-Protection', '')
        security_headers['xss_protection'] = {
            'present': bool(xss_protection),
            'enabled': '1' in xss_protection,
            'mode': 'block' if 'mode=block' in xss_protection else 'filter'
        }
        
        # Content-Security-Policy
        security_headers['csp'] = self.analyze_csp(headers)
        
        # X-Content-Type-Options
        security_headers['content_type_options'] = {
            'present': 'X-Content-Type-Options' in headers,
            'nosniff': headers.get('X-Content-Type-Options', '').lower() == 'nosniff'
        }
        
        return security_headers
