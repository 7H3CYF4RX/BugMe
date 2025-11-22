#!/usr/bin/env python3
"""
BugMe - Advanced XSS Vulnerability Scanner
Analyzes source code and execution patterns to find XSS vectors
"""

import argparse
import sys
from colorama import init, Fore, Style
from core.crawler import Crawler
from core.ultimate_xss_detector import UltimateXSSDetector
from core.reporter import Reporter
from core.config import Config
from utils.banner import print_banner
from utils.logger import setup_logger

# Initialize colorama for cross-platform colored output
init(autoreset=True)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='BugMe v3.0 - The ULTIMATE XSS Vulnerability Scanner\n'
                    'Detects ALL 5 XSS types: Reflected, Stored, DOM, Blind, Mutation\n'
                    'Uses 15+ detection techniques with browser automation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Single URL scan:
    python bugme.py -u https://example.com/page.php?id=1 -v
  
  Full domain crawl:
    python bugme.py -d https://example.com --depth 3 -v
  
  Limit URLs for faster scan:
    python bugme.py -d https://example.com --max-urls 50 -v
  
  With authentication:
    python bugme.py -u https://example.com/page?id=1 --cookie "session=abc123" -v
  
  Through proxy (Burp Suite):
    python bugme.py -d https://example.com --proxy http://127.0.0.1:8080 -v
  
  Save results:
    python bugme.py -d https://example.com -o results.json --html-report report.html
  
  Fast scan (skip browser verification):
    python bugme.py -d https://example.com --no-verify --max-urls 30
  
  Note: Browser verification is ENABLED by default for accurate results
  
  Custom payloads:
    python bugme.py -u https://example.com/page?q=test --payloads payloads/waf-bypass.txt -v

XSS Types Detected:
  [1] Reflected XSS  - GET/POST parameters with context-aware payloads
  [2] Stored XSS     - Multi-step verification with CSRF handling
  [3] DOM-based XSS  - Browser automation + JavaScript monitoring
  [4] Blind XSS      - Out-of-band callbacks + exfiltration
  [5] Mutation XSS   - Browser parsing exploitation (mXSS)

Detection Features:
  ✓ 15+ detection techniques
  ✓ 400+ context-aware payloads
  ✓ Browser automation (Selenium)
  ✓ Execution verification
  ✓ CSRF token handling
  ✓ Multi-threaded scanning
  ✓ Real-time reporting

For more information: https://github.com/7H3CYF4RX/BugMe
        """
    )
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-u', '--url', help='Single URL to scan')
    target_group.add_argument('-d', '--domain', help='Domain to crawl and scan')
    
    parser.add_argument('--depth', type=int, default=3, help='Crawl depth (default: 3)')
    parser.add_argument('--max-urls', '-mu', type=int, default=100, help='Maximum URLs to crawl (default: 100)')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--delay', type=float, default=0, help='Delay between requests in seconds (default: 0)')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('--cookie', help='Cookie string to use')
    parser.add_argument('--headers', help='Custom headers (JSON format)')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--output', '-o', help='Output file for results (JSON format)')
    parser.add_argument('--html-report', help='Generate HTML report')
    parser.add_argument('--no-verify', action='store_true', help='Skip live verification (browser execution testing is enabled by default)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--quiet', '-q', action='store_true', help='Minimal output')
    parser.add_argument('--payloads', help='Custom payloads file')
    
    return parser.parse_args()

def main():
    """Main execution function"""
    args = parse_arguments()
    
    # Setup logger
    logger = setup_logger(args.verbose)
    
    # Print banner
    if not args.quiet:
        print_banner()
    
    # Initialize configuration
    config = Config(args)
    
    try:
        # Initialize components
        print(f"\n{Fore.CYAN}[*] Initializing BugMe Scanner...{Style.RESET_ALL}")
        
        crawler = Crawler(config)
        detector = UltimateXSSDetector(config)
        reporter = Reporter(config)
        
        # Crawl or scan single URL
        if args.url:
            print(f"{Fore.CYAN}[*] Scanning single URL: {Fore.WHITE}{args.url}{Style.RESET_ALL}")
            urls = [args.url]
        else:
            print(f"{Fore.CYAN}[*] Crawling domain: {Fore.WHITE}{args.domain}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Crawl depth: {Fore.WHITE}{args.depth}{Style.RESET_ALL}")
            urls = crawler.crawl(args.domain)
            print(f"\n{Fore.GREEN}[+] Found {len(urls)} URLs to scan{Style.RESET_ALL}")
        
        # Scan for XSS vulnerabilities
        print(f"\n{Fore.CYAN}[*] Starting XSS detection...{Style.RESET_ALL}\n")
        results = detector.scan_urls(urls)
        
        # Generate reports
        print(f"\n{Fore.CYAN}[*] Generating reports...{Style.RESET_ALL}")
        reporter.print_summary(results)
        
        if args.output:
            reporter.save_json(results, args.output)
            print(f"{Fore.GREEN}[+] JSON report saved to: {args.output}{Style.RESET_ALL}")
        
        if args.html_report:
            reporter.save_html(results, args.html_report)
            print(f"{Fore.GREEN}[+] HTML report saved to: {args.html_report}{Style.RESET_ALL}")
        
        # Exit with appropriate code
        vulnerable_count = sum(1 for r in results if r['vulnerabilities'])
        if vulnerable_count > 0:
            print(f"\n{Fore.RED}[!] Found {vulnerable_count} vulnerable URL(s)!{Style.RESET_ALL}")
            sys.exit(1)
        else:
            print(f"\n{Fore.GREEN}[+] No vulnerabilities found.{Style.RESET_ALL}")
            sys.exit(0)
            
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
