"""
Web crawler module for discovering URLs
"""
from urllib.parse import urljoin, urlparse
from collections import deque
from colorama import Fore, Style
from utils.http_client import HTTPClient
from utils.parser import HTMLParser, URLParser
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
import time

console = Console()

class Crawler:
    """Web crawler to discover URLs for testing"""
    
    def __init__(self, config):
        self.config = config
        self.http_client = HTTPClient(config)
        self.visited = set()
        self.to_visit = deque()
        self.found_urls = []
        
    def crawl(self, start_url):
        """Crawl website starting from start_url"""
        self.to_visit.append((start_url, 0))
        base_domain = urlparse(start_url).netloc
        
        # Create progress bar for crawling
        if not self.config.quiet:
            progress = Progress(
                SpinnerColumn(spinner_name="dots"),
                TextColumn("[bold cyan]🕷️  Crawling..."),
                BarColumn(complete_style="cyan"),
                TaskProgressColumn(),
                TextColumn("•"),
                TextColumn("[cyan]{task.completed} URLs"),
                console=console,
                transient=False
            )
            progress.start()
            task = progress.add_task("Crawling", total=self.config.max_urls)
        else:
            progress = None
            task = None
        
        while self.to_visit:
            current_url, depth = self.to_visit.popleft()
            
            # Skip if already visited
            if current_url in self.visited:
                continue
            
            # Stop if max URLs reached
            if len(self.visited) >= self.config.max_urls:
                if self.config.verbose:
                    print(f"{Fore.YELLOW}[!] Reached maximum URL limit ({self.config.max_urls}){Style.RESET_ALL}")
                break
            
            # Skip if depth exceeded
            if depth > self.config.depth:
                continue
            
            # Mark as visited
            self.visited.add(current_url)
            
            # Update progress
            if not self.config.quiet and progress:
                progress.update(task, advance=1, description=f"[bold cyan]🕷️  Crawling: [white]{current_url[:50]}...")
            # Removed verbose output to keep it clean
            
            response = self.http_client.get(current_url)
            
            if not response or response.status_code != 200:
                continue
            
            # Add to found URLs if it has parameters or is a form action
            if '?' in current_url or '=' in current_url:
                self.found_urls.append(current_url)
            
            # Parse HTML
            try:
                soup = HTMLParser.parse(response.text)
                
                # Extract links
                links = HTMLParser.extract_links(soup, current_url)
                
                for link in links:
                    # Only crawl same domain
                    if URLParser.is_same_domain(link, start_url):
                        # Remove fragment
                        link = link.split('#')[0]
                        
                        if link not in self.visited:
                            self.to_visit.append((link, depth + 1))
                
                # Extract forms
                forms = HTMLParser.extract_forms(soup, current_url)
                for form in forms:
                    form_url = form['action']
                    if form_url and URLParser.is_same_domain(form_url, start_url):
                        if form_url not in self.visited:
                            self.found_urls.append(form_url)
                
            except Exception as e:
                if self.config.verbose:
                    print(f"{Fore.RED}[-] Error parsing {current_url}: {str(e)}{Style.RESET_ALL}")
        
        # Stop progress bar
        if not self.config.quiet and progress:
            progress.stop()
        
        # If no URLs with parameters found, add all crawled URLs
        if not self.found_urls:
            self.found_urls = list(self.visited)
        
        return self.found_urls
    
    def close(self):
        """Close HTTP client"""
        self.http_client.close()
