"""
Live XSS verification using browser automation
"""
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
from webdriver_manager.chrome import ChromeDriverManager
import time
from colorama import Fore, Style
from rich.console import Console
from rich.spinner import Spinner
from rich.live import Live

console = Console()

class XSSVerifier:
    """Verify XSS vulnerabilities using browser automation"""
    
    def __init__(self, config):
        self.config = config
        self.driver = None
    
    def setup_browser(self):
        """Setup headless Chrome browser"""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument(f'user-agent={self.config.user_agent}')
            
            # Suppress logging
            chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
            chrome_options.set_capability('goog:loggingPrefs', {'browser': 'ALL'})
            
            # Use webdriver-manager to automatically download and manage ChromeDriver
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            self.driver.set_page_load_timeout(self.config.timeout)
            return True
        except Exception as e:
            if self.config.verbose:
                print(f"{Fore.YELLOW}[!] Could not setup browser: {str(e)}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] Install Chrome: sudo apt install google-chrome-stable{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] Live verification will be skipped{Style.RESET_ALL}")
            return False
    
    def verify(self, url):
        """Verify if XSS payload executes"""
        if not self.driver:
            if not self.setup_browser():
                return {
                    'verified': False,
                    'method': 'browser',
                    'error': 'Browser setup failed'
                }
        
        # Show progress indicator
        spinner = Spinner("dots", text="[cyan]🔍 Verifying execution with browser...[/cyan]")
        
        try:
            with Live(spinner, console=console, transient=True):
                # Add cookies if configured
                if self.config.cookies:
                    spinner.update(text="[cyan]🍪 Setting up cookies...[/cyan]")
                    # First navigate to the domain to set cookies
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    base_url = f"{parsed.scheme}://{parsed.netloc}"
                    self.driver.get(base_url)
                    
                    # Add each cookie
                    for cookie_string in self.config.cookies.split(';'):
                        cookie_string = cookie_string.strip()
                        if '=' in cookie_string:
                            name, value = cookie_string.split('=', 1)
                            self.driver.add_cookie({
                                'name': name.strip(),
                                'value': value.strip(),
                                'domain': parsed.netloc
                            })
                
                # Load the URL
                spinner.update(text="[cyan]🌐 Loading payload URL...[/cyan]")
                self.driver.get(url)
                
                # Wait a bit for JavaScript to execute
                spinner.update(text="[cyan]⏳ Waiting for JavaScript execution...[/cyan]")
                time.sleep(2)
                
                # Check for alert
                spinner.update(text="[cyan]🔔 Checking for alert...[/cyan]")
                try:
                    WebDriverWait(self.driver, 3).until(EC.alert_is_present())
                    alert = self.driver.switch_to.alert
                    alert_text = alert.text
                    alert.accept()
                    
                    if self.config.verbose:
                        console.print(f"[green]    ✓ EXECUTION CONFIRMED! Alert: {alert_text}[/green]")
                    
                    return {
                        'verified': True,
                        'method': 'alert_detected',
                        'alert_text': alert_text
                    }
                except TimeoutException:
                    pass
            
            # Check for DOM modifications (common XSS indicators)
            try:
                # Check if any script tags were injected
                scripts = self.driver.execute_script(
                    "return document.getElementsByTagName('script').length"
                )
                
                # Check console for errors or XSS indicators
                logs = self.driver.get_log('browser')
                for log in logs:
                    if 'alert' in log.get('message', '').lower():
                        if self.config.verbose:
                            console.print(f"[green]    ✓ EXECUTION CONFIRMED via console log[/green]")
                        return {
                            'verified': True,
                            'method': 'console_log',
                            'details': log.get('message', '')
                        }
                
            except Exception:
                pass
            
            if self.config.verbose:
                console.print(f"[yellow]    ✗ Reflected but not executed (filtered or encoded)[/yellow]")
            
            return {
                'verified': False,
                'method': 'browser',
                'error': 'No execution detected'
            }
            
        except UnexpectedAlertPresentException:
            # Alert appeared during page load
            try:
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                return {
                    'verified': True,
                    'method': 'alert_on_load',
                    'alert_text': alert_text
                }
            except Exception:
                return {
                    'verified': True,
                    'method': 'alert_detected',
                    'alert_text': 'unknown'
                }
        
        except Exception as e:
            if self.config.verbose:
                print(f"{Fore.YELLOW}[!] Verification error: {str(e)}{Style.RESET_ALL}")
            return {
                'verified': False,
                'method': 'browser',
                'error': str(e)
            }
    
    def close(self):
        """Close the browser"""
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
