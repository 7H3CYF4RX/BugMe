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
        
        try:
            # Load the URL
            self.driver.get(url)
            
            # Wait a bit for JavaScript to execute
            time.sleep(2)
            
            # Check for alert
            try:
                WebDriverWait(self.driver, 3).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                
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
                        return {
                            'verified': True,
                            'method': 'console_log',
                            'details': log.get('message', '')
                        }
                
            except Exception:
                pass
            
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
