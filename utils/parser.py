"""
HTML and JavaScript parsing utilities
"""
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import re
import warnings

# Suppress XML parsing warnings when crawling feeds
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

class HTMLParser:
    """Parse HTML content and extract information"""
    
    @staticmethod
    def parse(html):
        """Parse HTML content (handles both HTML and XML feeds)"""
        # Try to detect if it's XML/RSS feed
        if html.strip().startswith('<?xml') or '<rss' in html[:200] or '<feed' in html[:200]:
            try:
                return BeautifulSoup(html, 'lxml-xml')
            except:
                # Fallback to HTML parser
                return BeautifulSoup(html, 'lxml')
        return BeautifulSoup(html, 'lxml')
    
    @staticmethod
    def extract_links(soup, base_url):
        """Extract all links from HTML"""
        links = set()
        
        for tag in soup.find_all(['a', 'link']):
            href = tag.get('href')
            if href:
                absolute_url = urljoin(base_url, href)
                links.add(absolute_url)
        
        return list(links)
    
    @staticmethod
    def extract_forms(soup, base_url):
        """Extract all forms from HTML"""
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name'),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                }
                if input_data['name']:
                    form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return forms
    
    @staticmethod
    def extract_scripts(soup):
        """Extract all script tags"""
        scripts = []
        
        for script in soup.find_all('script'):
            if script.string:
                scripts.append(script.string)
            elif script.get('src'):
                scripts.append(script.get('src'))
        
        return scripts
    
    @staticmethod
    def find_reflection(html, marker):
        """Find where a marker is reflected in HTML"""
        reflections = []
        
        if marker not in html:
            return reflections
        
        # Find all occurrences
        soup = BeautifulSoup(html, 'lxml')
        
        # Check in text content
        for text in soup.find_all(text=True):
            if marker in text:
                parent = text.parent
                reflections.append({
                    'location': 'text',
                    'context': parent.name if parent else 'unknown',
                    'snippet': str(text)[:100]
                })
        
        # Check in attributes
        for tag in soup.find_all():
            for attr, value in tag.attrs.items():
                if isinstance(value, str) and marker in value:
                    reflections.append({
                        'location': 'attribute',
                        'context': f'{tag.name}[{attr}]',
                        'snippet': value[:100]
                    })
        
        return reflections

class JSParser:
    """Parse JavaScript code and extract information"""
    
    @staticmethod
    def extract_endpoints(js_code):
        """Extract API endpoints from JavaScript"""
        endpoints = set()
        
        # Common patterns for URLs in JavaScript
        patterns = [
            r'["\']((https?:)?//[^"\']+)["\']',
            r'url\s*:\s*["\']([^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'ajax\(["\']([^"\']+)["\']',
            r'\.get\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_code, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if match and not match.startswith('data:'):
                    endpoints.add(match)
        
        return list(endpoints)
    
    @staticmethod
    def find_sinks(js_code):
        """Find dangerous JavaScript sinks"""
        sinks = []
        
        dangerous_functions = [
            'eval', 'innerHTML', 'outerHTML', 'document.write',
            'document.writeln', 'insertAdjacentHTML', 'setTimeout',
            'setInterval', 'Function', 'execScript'
        ]
        
        for func in dangerous_functions:
            if func in js_code:
                sinks.append(func)
        
        return sinks
    
    @staticmethod
    def find_sources(js_code):
        """Find user input sources in JavaScript"""
        sources = []
        
        input_sources = [
            'location.href', 'location.search', 'location.hash',
            'document.URL', 'document.documentURI', 'document.referrer',
            'window.name', 'postMessage', 'localStorage', 'sessionStorage'
        ]
        
        for source in input_sources:
            if source in js_code:
                sources.append(source)
        
        return sources

class URLParser:
    """Parse and manipulate URLs"""
    
    @staticmethod
    def parse(url):
        """Parse URL into components"""
        return urlparse(url)
    
    @staticmethod
    def get_parameters(url):
        """Extract parameters from URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] if len(v) == 1 else v for k, v in params.items()}
    
    @staticmethod
    def add_parameter(url, param, value):
        """Add or update a parameter in URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        
        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
    
    @staticmethod
    def is_same_domain(url1, url2):
        """Check if two URLs are from the same domain"""
        domain1 = urlparse(url1).netloc
        domain2 = urlparse(url2).netloc
        return domain1 == domain2
