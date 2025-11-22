"""
Configuration management for BugMe
"""
import json

class Config:
    """Configuration class for BugMe scanner"""
    
    def __init__(self, args):
        """Initialize configuration from command line arguments"""
        self.target_url = args.url
        self.target_domain = args.domain
        self.depth = args.depth
        self.max_urls = args.max_urls if hasattr(args, 'max_urls') else 100
        self.threads = args.threads
        self.timeout = args.timeout
        self.delay = args.delay
        self.user_agent = args.user_agent or 'BugMe/1.0 (XSS Scanner)'
        self.proxy = args.proxy
        self.output_file = args.output
        self.html_report = args.html_report
        self.verify_live = not args.no_verify
        self.verbose = args.verbose
        self.quiet = args.quiet
        self.custom_payloads = args.payloads
        self.verify_ssl = True
        
        # Parse headers if provided
        self.headers = {}
        if args.headers:
            try:
                self.headers = json.loads(args.headers)
            except json.JSONDecodeError:
                print("Warning: Invalid JSON for headers, ignoring...")
        
        # Parse cookies if provided
        self.cookies = {}
        if args.cookie:
            for cookie in args.cookie.split(';'):
                if '=' in cookie:
                    key, value = cookie.strip().split('=', 1)
                    self.cookies[key] = value
