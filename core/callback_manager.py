"""
Callback Server Manager for Blind XSS Detection
Supports multiple callback providers:
- Interactsh (https://github.com/projectdiscovery/interactsh)
- Burp Collaborator
- XSS Hunter
- Custom callback servers
"""
import requests
import time
import json
import hashlib
from colorama import Fore, Style
from urllib.parse import urlparse

class CallbackManager:
    """Manage callback servers for blind XSS detection"""
    
    def __init__(self, config):
        self.config = config
        self.provider = config.callback_provider if hasattr(config, 'callback_provider') else None
        self.callback_domain = config.callback_domain if hasattr(config, 'callback_domain') else None
        self.callback_token = config.callback_token if hasattr(config, 'callback_token') else None
        self.interactsh_session = None
        self.callbacks_received = {}
        
        # Initialize provider
        if self.provider:
            self._initialize_provider()
    
    def _initialize_provider(self):
        """Initialize the callback provider"""
        if self.provider == 'interactsh':
            self._init_interactsh()
        elif self.provider == 'burp':
            self._init_burp_collaborator()
        elif self.provider == 'xsshunter':
            self._init_xsshunter()
        elif self.provider == 'custom':
            self._init_custom()
        else:
            if self.config.verbose:
                print(f"{Fore.YELLOW}[!] Unknown callback provider: {self.provider}{Style.RESET_ALL}")
    
    def _init_interactsh(self):
        """Initialize Interactsh client"""
        try:
            # Use public Interactsh server or custom
            server_url = self.callback_domain if self.callback_domain else "https://interact.sh"
            
            if self.config.verbose:
                print(f"{Fore.CYAN}[*] Initializing Interactsh client...{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[*] Server: {server_url}{Style.RESET_ALL}")
            
            # Register with Interactsh
            response = requests.post(
                f"{server_url}/register",
                json={},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.interactsh_session = {
                    'server': server_url,
                    'correlation_id': data.get('correlation_id'),
                    'secret': data.get('secret'),
                    'domain': data.get('domain')
                }
                
                if self.config.verbose:
                    print(f"{Fore.GREEN}[+] Interactsh initialized successfully!{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Callback domain: {data.get('domain')}{Style.RESET_ALL}")
                
                # Update callback domain
                self.callback_domain = data.get('domain')
                return True
            else:
                if self.config.verbose:
                    print(f"{Fore.RED}[-] Failed to initialize Interactsh: {response.status_code}{Style.RESET_ALL}")
                return False
                
        except Exception as e:
            if self.config.verbose:
                print(f"{Fore.RED}[-] Interactsh initialization error: {str(e)}{Style.RESET_ALL}")
            return False
    
    def _init_burp_collaborator(self):
        """Initialize Burp Collaborator"""
        if not self.callback_domain:
            if self.config.verbose:
                print(f"{Fore.YELLOW}[!] Burp Collaborator requires --callback-domain{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] Example: --callback-domain abc123.burpcollaborator.net{Style.RESET_ALL}")
            return False
        
        if self.config.verbose:
            print(f"{Fore.CYAN}[*] Using Burp Collaborator: {self.callback_domain}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Note: Check Burp Suite for callbacks manually{Style.RESET_ALL}")
        
        return True
    
    def _init_xsshunter(self):
        """Initialize XSS Hunter"""
        if not self.callback_domain:
            if self.config.verbose:
                print(f"{Fore.YELLOW}[!] XSS Hunter requires --callback-domain{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] Example: --callback-domain your-id.xss.ht{Style.RESET_ALL}")
            return False
        
        if self.config.verbose:
            print(f"{Fore.CYAN}[*] Using XSS Hunter: {self.callback_domain}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Note: Check XSS Hunter dashboard for callbacks{Style.RESET_ALL}")
        
        return True
    
    def _init_custom(self):
        """Initialize custom callback server"""
        if not self.callback_domain:
            if self.config.verbose:
                print(f"{Fore.YELLOW}[!] Custom server requires --callback-domain{Style.RESET_ALL}")
            return False
        
        if self.config.verbose:
            print(f"{Fore.CYAN}[*] Using custom callback server: {self.callback_domain}{Style.RESET_ALL}")
        
        return True
    
    def generate_callback_url(self, identifier):
        """Generate a callback URL for a specific test"""
        if not self.callback_domain:
            return None
        
        # Format: https://domain.com/identifier or subdomain-based
        if self.provider == 'interactsh':
            # Interactsh uses subdomain format
            return f"https://{identifier}.{self.callback_domain}"
        else:
            # Others use path-based
            return f"https://{self.callback_domain}/{identifier}"
    
    def check_callbacks(self, identifier=None, wait_time=0):
        """Check for received callbacks"""
        if wait_time > 0:
            if self.config.verbose:
                print(f"{Fore.CYAN}[*] Waiting {wait_time}s for callbacks...{Style.RESET_ALL}")
            time.sleep(wait_time)
        
        if self.provider == 'interactsh':
            return self._check_interactsh_callbacks(identifier)
        elif self.provider == 'burp':
            return self._check_burp_callbacks(identifier)
        elif self.provider == 'xsshunter':
            return self._check_xsshunter_callbacks(identifier)
        elif self.provider == 'custom':
            return self._check_custom_callbacks(identifier)
        else:
            return {'received': False, 'callbacks': []}
    
    def _check_interactsh_callbacks(self, identifier=None):
        """Check Interactsh for callbacks"""
        if not self.interactsh_session:
            return {'received': False, 'callbacks': []}
        
        try:
            response = requests.get(
                f"{self.interactsh_session['server']}/poll",
                params={
                    'id': self.interactsh_session['correlation_id'],
                    'secret': self.interactsh_session['secret']
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                interactions = data.get('data', [])
                
                if interactions:
                    # Filter by identifier if provided
                    if identifier:
                        filtered = [i for i in interactions if identifier in i.get('full-id', '')]
                        return {
                            'received': len(filtered) > 0,
                            'callbacks': filtered,
                            'count': len(filtered)
                        }
                    else:
                        return {
                            'received': len(interactions) > 0,
                            'callbacks': interactions,
                            'count': len(interactions)
                        }
                
        except Exception as e:
            if self.config.verbose:
                print(f"{Fore.RED}[-] Error checking Interactsh callbacks: {str(e)}{Style.RESET_ALL}")
        
        return {'received': False, 'callbacks': [], 'count': 0}
    
    def _check_burp_callbacks(self, identifier=None):
        """Burp Collaborator callbacks (manual check)"""
        # Burp Collaborator doesn't have API access
        # Users need to check Burp Suite manually
        return {
            'received': False,
            'callbacks': [],
            'note': 'Check Burp Suite Collaborator tab manually'
        }
    
    def _check_xsshunter_callbacks(self, identifier=None):
        """XSS Hunter callbacks (manual check)"""
        # XSS Hunter requires checking the dashboard
        return {
            'received': False,
            'callbacks': [],
            'note': 'Check XSS Hunter dashboard manually'
        }
    
    def _check_custom_callbacks(self, identifier=None):
        """Check custom callback server"""
        if not self.callback_domain or not self.callback_token:
            return {'received': False, 'callbacks': []}
        
        try:
            # Attempt to query custom server API
            # Format: GET https://domain.com/api/callbacks?token=xxx&id=identifier
            response = requests.get(
                f"https://{self.callback_domain}/api/callbacks",
                params={
                    'token': self.callback_token,
                    'id': identifier if identifier else 'all'
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'received': data.get('count', 0) > 0,
                    'callbacks': data.get('callbacks', []),
                    'count': data.get('count', 0)
                }
        except Exception as e:
            if self.config.verbose:
                print(f"{Fore.RED}[-] Error checking custom callbacks: {str(e)}{Style.RESET_ALL}")
        
        return {'received': False, 'callbacks': [], 'count': 0}
    
    def cleanup(self):
        """Cleanup callback session"""
        if self.provider == 'interactsh' and self.interactsh_session:
            try:
                # Deregister from Interactsh
                requests.post(
                    f"{self.interactsh_session['server']}/deregister",
                    json={
                        'correlation_id': self.interactsh_session['correlation_id'],
                        'secret': self.interactsh_session['secret']
                    },
                    timeout=5
                )
                if self.config.verbose:
                    print(f"{Fore.CYAN}[*] Interactsh session closed{Style.RESET_ALL}")
            except:
                pass
    
    def is_enabled(self):
        """Check if callback server is enabled and configured"""
        return self.provider is not None and self.callback_domain is not None
    
    def get_status(self):
        """Get callback manager status"""
        return {
            'enabled': self.is_enabled(),
            'provider': self.provider,
            'domain': self.callback_domain,
            'session_active': self.interactsh_session is not None if self.provider == 'interactsh' else None
        }
