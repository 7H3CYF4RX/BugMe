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
  
  Only show verified/executed XSS (no reflection-only):
    python bugme.py -d https://example.com --verified-only -v
  
  Note: Browser verification is ENABLED by default for accurate results
  
  Custom payloads:
    python bugme.py -u https://example.com/page?q=test --payloads payloads/waf-bypass.txt -v
  
  Scan multiple URLs/domains from file:
    python bugme.py -l targets.txt --verified-only -v
    
    File format (targets.txt):
      https://example.com/page.php?id=1
      https://test.com/search?q=test
      https://subdomain.example.com/
      https://api.example.com
  
  Blind XSS with callback servers:
    python bugme.py -d https://example.com --callback-provider interactsh -v
    python bugme.py -d https://example.com --callback-provider burp --callback-domain abc123.burpcollaborator.net -v
    python bugme.py -d https://example.com --callback-provider xsshunter --callback-domain your-id.xss.ht -v

XSS Types Detected:
  [1] Reflected XSS  - GET/POST parameters with context-aware payloads
  [2] Stored XSS     - Multi-step verification with CSRF handling
  [3] DOM-based XSS  - Browser automation + JavaScript monitoring
  [4] Blind XSS      - Out-of-band callbacks + exfiltration
  [5] Mutation XSS   - Browser parsing exploitation (mXSS)

Detection Features:
  ✓ 15+ detection techniques
  ✓ 1,876+ context-aware payloads
  ✓ Browser automation (Selenium)
  ✓ Execution verification
  ✓ CSRF token handling
  ✓ Multi-threaded scanning
  ✓ Real-time reporting
  ✓ Callback server integration (Interactsh, Burp, XSS Hunter)

For more information: https://github.com/7H3CYF4RX/BugMe
        """
    )
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-u', '--url', help='Single URL to scan')
    target_group.add_argument('-d', '--domain', help='Domain to crawl and scan')
    target_group.add_argument('-l', '--list', help='File containing list of URLs or domains (one per line)')
    
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
    parser.add_argument('--verified-only', action='store_true', help='Show only verified/executed XSS (filter out reflection-only findings)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--quiet', '-q', action='store_true', help='Minimal output')
    parser.add_argument('--payloads', help='Custom payloads file')
    
    # Blind XSS / Callback server options
    parser.add_argument('--callback-provider', choices=['interactsh', 'burp', 'xsshunter', 'custom'], 
                        help='Callback server provider for blind XSS detection')
    parser.add_argument('--callback-domain', help='Callback domain (e.g., abc123.burpcollaborator.net, your-id.xss.ht)')
    parser.add_argument('--callback-token', help='API token for custom callback server')
    parser.add_argument('--callback-wait', type=int, default=5, help='Seconds to wait for callbacks after scan (default: 5)')
    
    return parser.parse_args()

def probe_url(domain):
    """Probe domain to determine if it's http or https"""
    import requests
    import urllib3
    from urllib.parse import urlparse
    
    # Suppress SSL warnings for probing
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # If already has protocol, return as-is
    if domain.startswith('http://') or domain.startswith('https://'):
        return domain
    
    # Try HTTPS first (more common and secure)
    try:
        response = requests.get(f'https://{domain}', timeout=5, verify=False, allow_redirects=True)
        if response.status_code < 500:  # Any non-server-error response means it's accessible
            return f'https://{domain}'
    except:
        pass
    
    # Try HTTP as fallback
    try:
        response = requests.get(f'http://{domain}', timeout=5, allow_redirects=True)
        if response.status_code < 500:
            return f'http://{domain}'
    except:
        pass
    
    # Default to HTTPS if both fail (let the scanner handle the error)
    return f'https://{domain}'

def main():
    """Main execution function"""
    import warnings
    import sys
    import signal
    import os
    
    # Suppress threading warnings on exit
    warnings.filterwarnings("ignore", category=RuntimeWarning, module="threading")
    
    # Handle Ctrl+C cleanly
    def signal_handler(sig, frame):
        print("\n" * 2)
        print(f"{Fore.YELLOW}╔══════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}║                                                      ║{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}║  ⚠️  SCAN INTERRUPTED BY USER (Ctrl+C)              ║{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}║                                                      ║{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}║  Partial results may have been found.                ║{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}║  Check output above for any vulnerabilities.         ║{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}║                                                      ║{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        print()
        os._exit(130)  # Force exit without cleanup
    
    signal.signal(signal.SIGINT, signal_handler)
    
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
        
        # Crawl or scan single URL or list
        if args.url:
            # Probe URL if no protocol specified
            target_url = probe_url(args.url)
            if target_url != args.url:
                print(f"{Fore.CYAN}[*] Auto-detected protocol: {Fore.WHITE}{target_url}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Scanning single URL: {Fore.WHITE}{target_url}{Style.RESET_ALL}")
            urls = [target_url]
        elif args.list:
            print(f"{Fore.CYAN}[*] Loading URLs from file: {Fore.WHITE}{args.list}{Style.RESET_ALL}")
            try:
                with open(args.list, 'r') as f:
                    lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
                urls = []
                domains_to_crawl = []
                
                # Separate URLs and domains, and probe for protocols
                needs_probing = [line for line in lines if not line.startswith('http')]
                
                if needs_probing and not args.quiet:
                    print(f"{Fore.CYAN}[*] Auto-detecting protocols for {len(needs_probing)} domain(s)...{Style.RESET_ALL}")
                
                for i, line in enumerate(lines, 1):
                    # Probe for protocol if not present
                    if not line.startswith('http'):
                        if not args.quiet:
                            print(f"{Fore.CYAN}  [{i}/{len(lines)}] Probing {line}...{Style.RESET_ALL}", end=' ', flush=True)
                        probed_line = probe_url(line)
                        if not args.quiet:
                            protocol = probed_line.split('://')[0]
                            print(f"{Fore.GREEN}✓ {protocol.upper()}{Style.RESET_ALL}")
                    else:
                        probed_line = line
                    
                    # Check if it's a full URL (has parameters or path)
                    if '?' in probed_line or probed_line.count('/') > 3:
                        urls.append(probed_line)
                    else:
                        # It's a domain, needs crawling
                        domains_to_crawl.append(probed_line)
                
                if needs_probing and not args.quiet:
                    print()
                
                # Crawl domains if any
                if domains_to_crawl:
                    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TaskProgressColumn
                    from rich.console import Console
                    
                    console = Console()
                    print(f"{Fore.CYAN}[*] Crawling {len(domains_to_crawl)} domain(s)... (max {args.max_urls} URLs per domain){Style.RESET_ALL}\n")
                    
                    # Create a progress bar for all domains
                    with Progress(
                        SpinnerColumn(spinner_name="dots"),
                        TextColumn("[bold cyan]{task.description}"),
                        BarColumn(complete_style="cyan"),
                        TaskProgressColumn(),
                        TextColumn("•"),
                        TextColumn("[cyan]{task.fields[current_domain]}"),
                        console=console
                    ) as progress:
                        task = progress.add_task(
                            "🕷️  Crawling domains...",
                            total=len(domains_to_crawl),
                            current_domain=""
                        )
                        
                        # Temporarily enable quiet mode to suppress individual progress bars
                        original_quiet = config.quiet
                        config.quiet = True
                        
                        for i, domain in enumerate(domains_to_crawl, 1):
                            # Update progress with current domain
                            progress.update(
                                task,
                                current_domain=f"[{i}/{len(domains_to_crawl)}] {domain}"
                            )
                            
                            crawled_urls = crawler.crawl(domain)
                            urls.extend(crawled_urls)
                            
                            # Update progress
                            progress.update(task, advance=1)
                        
                        # Restore original quiet setting
                        config.quiet = original_quiet
                    
                    print()
                
                print(f"\n{Fore.GREEN}[+] Loaded {len(lines)} entries from file{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] Total {len(urls)} URLs to scan{Style.RESET_ALL}")
                
            except FileNotFoundError:
                print(f"{Fore.RED}[!] Error: File not found: {args.list}{Style.RESET_ALL}")
                sys.exit(1)
            except Exception as e:
                print(f"{Fore.RED}[!] Error reading file: {str(e)}{Style.RESET_ALL}")
                sys.exit(1)
        else:
            # Probe domain if no protocol specified
            target_domain = probe_url(args.domain)
            if target_domain != args.domain:
                print(f"{Fore.CYAN}[*] Auto-detected protocol: {Fore.WHITE}{target_domain}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Crawling domain: {Fore.WHITE}{target_domain}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Crawl depth: {Fore.WHITE}{args.depth}{Style.RESET_ALL}")
            urls = crawler.crawl(target_domain)
            print(f"\n{Fore.GREEN}[+] Found {len(urls)} URLs to scan{Style.RESET_ALL}")
        
        # Scan for XSS vulnerabilities
        print(f"\n{Fore.CYAN}[*] Starting XSS detection...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Testing {len(urls)} URL(s) with 5 XSS types{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Techniques: Reflected, Stored, DOM, Blind, Mutation{Style.RESET_ALL}")
        if config.verify_live:
            print(f"{Fore.GREEN}[*] Browser verification: ENABLED{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[*] Browser verification: DISABLED (use --no-verify to skip){Style.RESET_ALL}")
        if config.verified_only:
            print(f"{Fore.YELLOW}[*] Filter mode: VERIFIED ONLY (hiding reflection-only findings){Style.RESET_ALL}")
        print()
        results = detector.scan_urls(urls)
        
        # Check for blind XSS callbacks if enabled
        if detector.blind_detector and detector.blind_detector.callback_manager.is_enabled():
            print(f"\n{Fore.CYAN}[*] Checking for blind XSS callbacks...{Style.RESET_ALL}")
            blind_vulns = detector.blind_detector.check_all_callbacks(wait_time=config.callback_wait)
            
            if blind_vulns:
                print(f"\n{Fore.GREEN}[+] BLIND XSS CONFIRMED! {len(blind_vulns)} callback(s) received!{Style.RESET_ALL}")
                
                # Add blind XSS findings to results
                for vuln in blind_vulns:
                    payload_info = vuln['payload_info']
                    # Find or create result entry for this URL
                    url_result = next((r for r in results if r['url'] == payload_info['url']), None)
                    if url_result:
                        url_result['vulnerabilities'].append({
                            'type': 'blind_xss',
                            'parameter': payload_info['parameter'],
                            'payload': payload_info['payloads'][0] if payload_info['payloads'] else 'N/A',
                            'verified': True,
                            'callback': vuln['callback'],
                            'severity': 'critical',
                            'identifier': vuln['identifier']
                        })
                    else:
                        results.append({
                            'url': payload_info['url'],
                            'vulnerabilities': [{
                                'type': 'blind_xss',
                                'parameter': payload_info['parameter'],
                                'payload': payload_info['payloads'][0] if payload_info['payloads'] else 'N/A',
                                'verified': True,
                                'callback': vuln['callback'],
                                'severity': 'critical',
                                'identifier': vuln['identifier']
                            }]
                        })
                
                # Print blind XSS findings
                for vuln in blind_vulns:
                    payload_info = vuln['payload_info']
                    print(f"\n{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
                    print(f"{Fore.RED}[!] BLIND XSS DETECTED!{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}  URL: {Fore.WHITE}{payload_info['url']}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}  Parameter: {Fore.WHITE}{payload_info['parameter']}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}  Identifier: {Fore.WHITE}{vuln['identifier']}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}  Status: EXECUTION CONFIRMED{Style.RESET_ALL}")
                    print(f"{Fore.RED}{'═' * 60}{Style.RESET_ALL}")
            
            # Cleanup callback session
            detector.blind_detector.cleanup()
        
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
        # This should not be reached due to signal handler, but keep as fallback
        pass
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
