"""
Configuration management for BugMe
"""
import json

class Config:
    """Configuration class for BugMe scanner"""
    
    def __init__(self, args):
        """Initialize configuration from command line arguments"""
        self.target_url = args.url if hasattr(args, 'url') else None
        self.target_domain = args.domain if hasattr(args, 'domain') else None
        self.target_list = args.list if hasattr(args, 'list') else None
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
        self.verified_only = args.verified_only if hasattr(args, 'verified_only') else False
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
        
        # Store cookies as string (used by Selenium)
        self.cookies = args.cookie if args.cookie else None
        
        # Callback server configuration for blind XSS
        self.callback_provider = args.callback_provider if hasattr(args, 'callback_provider') else None
        self.callback_domain = args.callback_domain if hasattr(args, 'callback_domain') else None
        self.callback_token = args.callback_token if hasattr(args, 'callback_token') else None
        self.callback_wait = args.callback_wait if hasattr(args, 'callback_wait') else 5
