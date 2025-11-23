"""
HTTP client with retry logic and error handling
"""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import time
from colorama import Fore, Style

class HTTPClient:
    """HTTP client with advanced features"""
    
    def __init__(self, config):
        self.config = config
        self.session = self._create_session()
        
    def _create_session(self):
        """Create requests session with retry logic"""
        session = requests.Session()
        
        # Retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default headers
        session.headers.update({
            'User-Agent': self.config.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        # Add custom headers
        if self.config.headers:
            session.headers.update(self.config.headers)
        
        # Add cookies (parse from string)
        if self.config.cookies:
            for cookie in self.config.cookies.split(';'):
                cookie = cookie.strip()
                if '=' in cookie:
                    name, value = cookie.split('=', 1)
                    session.cookies.set(name.strip(), value.strip())
        
        # Set proxy
        if self.config.proxy:
            session.proxies = {
                'http': self.config.proxy,
                'https': self.config.proxy
            }
        
        return session
    
    def get(self, url, **kwargs):
        """Perform GET request"""
        try:
            if self.config.delay > 0:
                time.sleep(self.config.delay)
            
            response = self.session.get(
                url,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
                allow_redirects=True,
                **kwargs
            )
            return response
        except requests.exceptions.RequestException as e:
            if self.config.verbose:
                print(f"{Fore.RED}[-] Request error for {url}: {str(e)}{Style.RESET_ALL}")
            return None
    
    def post(self, url, data=None, **kwargs):
        """Perform POST request"""
        try:
            if self.config.delay > 0:
                time.sleep(self.config.delay)
            
            if self.config.verbose:
                print(f"{Fore.CYAN}                [HTTP] POST to {url} with {len(data) if data else 0} fields{Style.RESET_ALL}")
            
            response = self.session.post(
                url,
                data=data,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
                allow_redirects=True,
                **kwargs
            )
            
            if self.config.verbose:
                print(f"{Fore.GREEN}                [HTTP] POST response: {response.status_code}{Style.RESET_ALL}")
            
            return response
        except requests.exceptions.RequestException as e:
            if self.config.verbose:
                print(f"{Fore.RED}[-] Request error for {url}: {str(e)}{Style.RESET_ALL}")
            return None
    
    def close(self):
        """Close the session"""
        self.session.close()
