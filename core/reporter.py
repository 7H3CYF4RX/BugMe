"""
Results reporting module
"""
import json
from datetime import datetime
from colorama import Fore, Style
import os

class Reporter:
    """Generate reports in various formats"""
    
    def __init__(self, config):
        self.config = config
    
    def print_summary(self, results):
        """Print summary of scan results"""
        print(f"\n{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{Style.BRIGHT}{'SCAN SUMMARY':^60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}\n")
        
        total_urls = len(results)
        vulnerable_urls = sum(1 for r in results if r['vulnerabilities'])
        total_vulns = sum(len(r['vulnerabilities']) for r in results)
        
        # Count by type
        reflected = sum(
            sum(1 for v in r['vulnerabilities'] if v['type'] == 'reflected_xss')
            for r in results
        )
        dom_xss = sum(
            sum(1 for v in r['vulnerabilities'] if v['type'] == 'dom_xss')
            for r in results
        )
        stored = sum(
            sum(1 for v in r['vulnerabilities'] if v['type'] == 'stored_xss')
            for r in results
        )
        blind = sum(
            sum(1 for v in r['vulnerabilities'] if v['type'] == 'blind_xss')
            for r in results
        )
        mutation = sum(
            sum(1 for v in r['vulnerabilities'] if v['type'] == 'mutation_xss')
            for r in results
        )
        
        # Count by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for result in results:
            for vuln in result['vulnerabilities']:
                severity = vuln.get('severity', 'medium')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print(f"{Fore.GREEN}[+] URLs Scanned: {Fore.WHITE}{total_urls}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Vulnerable URLs: {Fore.WHITE}{vulnerable_urls}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Total Vulnerabilities: {Fore.WHITE}{total_vulns}{Style.RESET_ALL}")
        
        if total_vulns > 0:
            print(f"\n{Fore.YELLOW}[+] Vulnerability Types:{Style.RESET_ALL}")
            print(f"  ├─ Reflected XSS: {Fore.WHITE}{reflected}{Style.RESET_ALL}")
            print(f"  ├─ DOM-based XSS: {Fore.WHITE}{dom_xss}{Style.RESET_ALL}")
            print(f"  ├─ Stored XSS: {Fore.WHITE}{stored}{Style.RESET_ALL}")
            print(f"  ├─ Blind XSS: {Fore.WHITE}{blind}{Style.RESET_ALL}")
            print(f"  └─ Mutation XSS: {Fore.WHITE}{mutation}{Style.RESET_ALL}")
            
            print(f"\n{Fore.YELLOW}[+] Severity Breakdown:{Style.RESET_ALL}")
            print(f"  ├─ Critical: {Fore.RED}{severity_counts['critical']}{Style.RESET_ALL}")
            print(f"  ├─ High: {Fore.RED}{severity_counts['high']}{Style.RESET_ALL}")
            print(f"  ├─ Medium: {Fore.YELLOW}{severity_counts['medium']}{Style.RESET_ALL}")
            print(f"  └─ Low: {Fore.GREEN}{severity_counts['low']}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}⚠️  DISCLAIMER:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}This is an automated scanner and may produce false positives{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}or miss certain vulnerabilities. Always verify findings manually{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}before reporting. Use responsibly on authorized systems only.{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}\n")
    
    def save_json(self, results, output_file):
        """Save results as JSON with comprehensive details"""
        # Calculate detailed statistics
        reflected = sum(sum(1 for v in r['vulnerabilities'] if v['type'] == 'reflected_xss') for r in results)
        dom_xss = sum(sum(1 for v in r['vulnerabilities'] if v['type'] == 'dom_xss') for r in results)
        stored = sum(sum(1 for v in r['vulnerabilities'] if v['type'] == 'stored_xss') for r in results)
        blind = sum(sum(1 for v in r['vulnerabilities'] if v['type'] == 'blind_xss') for r in results)
        mutation = sum(sum(1 for v in r['vulnerabilities'] if v['type'] == 'mutation_xss') for r in results)
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        verified_count = 0
        
        for result in results:
            for vuln in result['vulnerabilities']:
                severity = vuln.get('severity', 'medium')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                if vuln.get('verified', False):
                    verified_count += 1
        
        report = {
            'disclaimer': 'This is an automated scanner and may produce false positives or miss certain vulnerabilities. Always verify findings manually before reporting. Use this tool responsibly and only on systems you have permission to test.',
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'tool': 'BugMe v3.0',
                'tool_version': '3.0',
                'target': self.config.target_url or self.config.target_domain or self.config.target_list,
                'scan_type': 'single_url' if self.config.target_url else ('domain_crawl' if self.config.target_domain else 'list_scan'),
                'configuration': {
                    'threads': self.config.threads,
                    'timeout': self.config.timeout,
                    'depth': self.config.depth if hasattr(self.config, 'depth') else None,
                    'max_urls': self.config.max_urls if hasattr(self.config, 'max_urls') else None,
                    'browser_verification': self.config.verify_live,
                    'verified_only_filter': self.config.verified_only,
                    'callback_provider': self.config.callback_provider if hasattr(self.config, 'callback_provider') else None,
                    'callback_domain': self.config.callback_domain if hasattr(self.config, 'callback_domain') else None
                }
            },
            'summary': {
                'total_urls_scanned': len(results),
                'vulnerable_urls': sum(1 for r in results if r['vulnerabilities']),
                'total_vulnerabilities': sum(len(r['vulnerabilities']) for r in results),
                'verified_vulnerabilities': verified_count,
                'vulnerability_types': {
                    'reflected_xss': reflected,
                    'dom_based_xss': dom_xss,
                    'stored_xss': stored,
                    'blind_xss': blind,
                    'mutation_xss': mutation
                },
                'severity_breakdown': severity_counts
            },
            'vulnerabilities': results
        }
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
    
    def save_html(self, results, output_file):
        """Save results as HTML report"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BugMe v3.0 - XSS Scan Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }}
        .header {{
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 3px solid #d32f2f;
        }}
        h1 {{
            color: #d32f2f;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .tool-version {{
            color: #666;
            font-size: 1.1em;
            font-weight: 500;
        }}
        .timestamp {{
            color: #888;
            font-size: 0.9em;
            margin-top: 10px;
        }}
        .summary {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin: 30px 0;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }}
        .summary h2 {{
            margin-bottom: 20px;
            font-size: 1.8em;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .summary-item {{
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 6px;
            backdrop-filter: blur(10px);
        }}
        .summary-item strong {{
            display: block;
            font-size: 0.9em;
            margin-bottom: 5px;
            opacity: 0.9;
        }}
        .summary-item span {{
            font-size: 1.8em;
            font-weight: bold;
        }}
        .stats-section {{
            margin: 30px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .stat-card {{
            background: white;
            padding: 15px;
            border-radius: 6px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }}
        .stat-card .label {{
            font-size: 0.85em;
            color: #666;
            margin-bottom: 5px;
        }}
        .stat-card .value {{
            font-size: 1.5em;
            font-weight: bold;
            color: #333;
        }}
        .vulnerability {{
            background: white;
            border-left: 5px solid #ff9800;
            padding: 25px;
            margin: 20px 0;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .vulnerability:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 20px rgba(0,0,0,0.12);
        }}
        .vulnerability.critical {{
            border-left-color: #b71c1c;
            background: #ffebee;
        }}
        .vulnerability.high {{
            border-left-color: #d32f2f;
            background: #ffebee;
        }}
        .vulnerability.medium {{
            border-left-color: #ff9800;
            background: #fff3e0;
        }}
        .vulnerability.low {{
            border-left-color: #4caf50;
            background: #e8f5e9;
        }}
        .vulnerability h3 {{
            color: #333;
            margin-bottom: 15px;
            font-size: 1.4em;
        }}
        .vulnerability p {{
            margin: 10px 0;
        }}
        .poc {{
            background: #263238;
            color: #aed581;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            word-break: break-all;
            margin: 15px 0;
            overflow-x: auto;
        }}
        .poc a {{
            color: #81d4fa;
            text-decoration: none;
        }}
        .poc a:hover {{
            text-decoration: underline;
        }}
        .badge {{
            display: inline-block;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.75em;
            font-weight: bold;
            margin: 3px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .badge.critical {{ background: #b71c1c; color: white; }}
        .badge.high {{ background: #d32f2f; color: white; }}
        .badge.medium {{ background: #ff9800; color: white; }}
        .badge.low {{ background: #4caf50; color: white; }}
        .badge.verified {{ background: #2196f3; color: white; }}
        .info-box {{
            background: #e8f5e9;
            border: 1px solid #4caf50;
            padding: 15px;
            border-radius: 6px;
            margin: 15px 0;
        }}
        .info-box.blind-xss {{
            background: #fff3e0;
            border-color: #ff9800;
        }}
        .info-box strong {{
            display: block;
            margin-bottom: 8px;
            color: #333;
        }}
        .footer {{
            text-align: center;
            margin-top: 50px;
            padding-top: 20px;
            border-top: 2px solid #eee;
            color: #666;
        }}
        code {{
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        a {{
            color: #2196f3;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🐛 BugMe XSS Scan Report</h1>
            <p class="tool-version">BugMe v3.0 - The Ultimate XSS Scanner</p>
            <p class="timestamp">Generated: {timestamp}</p>
        </div>
        
        <div class="summary">
            <h2>📊 Scan Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <strong>Target</strong>
                    <span>{target}</span>
                </div>
                <div class="summary-item">
                    <strong>URLs Scanned</strong>
                    <span>{total_urls}</span>
                </div>
                <div class="summary-item">
                    <strong>Vulnerable URLs</strong>
                    <span>{vulnerable_urls}</span>
                </div>
                <div class="summary-item">
                    <strong>Total Vulnerabilities</strong>
                    <span>{total_vulns}</span>
                </div>
                <div class="summary-item">
                    <strong>Verified</strong>
                    <span>{verified_count}</span>
                </div>
            </div>
        </div>
        
        <div class="stats-section">
            <h2>🎯 Vulnerability Types</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="label">Reflected XSS</div>
                    <div class="value">{reflected_count}</div>
                </div>
                <div class="stat-card">
                    <div class="label">DOM-based XSS</div>
                    <div class="value">{dom_count}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Stored XSS</div>
                    <div class="value">{stored_count}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Blind XSS</div>
                    <div class="value">{blind_count}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Mutation XSS</div>
                    <div class="value">{mutation_count}</div>
                </div>
            </div>
        </div>
        
        <div class="stats-section">
            <h2>⚠️ Severity Breakdown</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="label">Critical</div>
                    <div class="value" style="color: #b71c1c;">{critical_count}</div>
                </div>
                <div class="stat-card">
                    <div class="label">High</div>
                    <div class="value" style="color: #d32f2f;">{high_count}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Medium</div>
                    <div class="value" style="color: #ff9800;">{medium_count}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Low</div>
                    <div class="value" style="color: #4caf50;">{low_count}</div>
                </div>
            </div>
        </div>
        
        <h2 style="margin-top: 40px; margin-bottom: 20px;">🔍 Detailed Findings</h2>
        {vulnerabilities_html}
        
        <div class="footer">
            <p><strong>BugMe v3.0</strong> - Advanced XSS Vulnerability Scanner</p>
            <p>Detects ALL 5 XSS types with browser verification and callback support</p>
            
            <div style="background: #fff3cd; border: 2px solid #ffc107; padding: 15px; border-radius: 8px; margin: 20px 0; text-align: left;">
                <p style="margin: 0; color: #856404;"><strong>⚠️ Important Disclaimer:</strong></p>
                <p style="margin: 10px 0 0 0; color: #856404;">
                    This is an automated scanner and may produce false positives or miss certain vulnerabilities. 
                    <strong>Always verify findings manually</strong> before reporting. Use this tool responsibly and only 
                    on systems you have permission to test.
                </p>
            </div>
            
            <p style="margin-top: 10px; font-size: 0.9em;">
                <a href="https://github.com/7H3CYF4RX/BugMe" target="_blank">GitHub Repository</a>
            </p>
        </div>
    </div>
</body>
</html>
"""
        
        vulnerabilities_html = ""
        
        for result in results:
            if not result['vulnerabilities']:
                continue
            
            for vuln in result['vulnerabilities']:
                severity = vuln.get('severity', 'medium')
                verified_badge = '<span class="badge verified">VERIFIED</span>' if vuln.get('verified') else ''
                
                # Build vulnerability details
                vuln_type = vuln.get('type', 'unknown').replace('_', ' ').title()
                parameter = vuln.get('parameter', 'N/A')
                payload = vuln.get('payload', 'N/A')
                context = vuln.get('context', 'N/A')
                poc_url = vuln.get('poc_url', 'N/A')
                filters = vuln.get('filters', [])
                method = vuln.get('method', 'GET')
                verification_method = vuln.get('verification_method', 'N/A')
                alert_text = vuln.get('alert_text', '')
                
                # Blind XSS specific details
                callback_info = ''
                if vuln.get('type') == 'blind_xss':
                    identifier = vuln.get('identifier', 'N/A')
                    callback_data = vuln.get('callback', {})
                    callback_info = f"""
                    <div style="background: #e8f5e9; padding: 10px; border-radius: 4px; margin: 10px 0;">
                        <p><strong>🎯 Blind XSS Confirmed!</strong></p>
                        <p><strong>Identifier:</strong> {identifier}</p>
                        <p><strong>Callback Received:</strong> Yes ✓</p>
                        <p><strong>Callback Data:</strong> <code>{str(callback_data)}</code></p>
                    </div>
                    """
                
                # Verification details
                verification_info = ''
                if vuln.get('verified'):
                    verification_info = f"""
                    <div style="background: #e8f5e9; padding: 10px; border-radius: 4px; margin: 10px 0;">
                        <p><strong>✅ Execution Verified</strong></p>
                        <p><strong>Method:</strong> {verification_method}</p>
                        {f'<p><strong>Alert Text:</strong> {alert_text}</p>' if alert_text else ''}
                    </div>
                    """
                
                vuln_html = f"""
                <div class="vulnerability {severity}">
                    <h3>🔍 {vuln_type}</h3>
                    <p><strong>URL:</strong> <a href="{result['url']}" target="_blank">{result['url']}</a></p>
                    <p>
                        <span class="badge {severity}">{severity.upper()}</span>
                        {verified_badge}
                        <span class="badge" style="background: #607d8b; color: white;">{vuln_type}</span>
                    </p>
                    <p><strong>Parameter:</strong> <code>{parameter}</code></p>
                    <p><strong>Method:</strong> {method}</p>
                    <p><strong>Payload:</strong></p>
                    <div class="poc"><code>{payload}</code></div>
                    <p><strong>Context:</strong> {context}</p>
                    {callback_info}
                    {verification_info}
                    <p><strong>Proof of Concept URL:</strong></p>
                    <div class="poc"><a href="{poc_url}" target="_blank">{poc_url}</a></div>
                    {f"<p><strong>🛡️ Filters Detected:</strong> {', '.join(filters)}</p>" if filters else ''}
                </div>
                """
                vulnerabilities_html += vuln_html
        
        if not vulnerabilities_html:
            vulnerabilities_html = "<p>No vulnerabilities found.</p>"
        
        # Calculate all statistics for HTML template
        reflected = sum(sum(1 for v in r['vulnerabilities'] if v['type'] == 'reflected_xss') for r in results)
        dom_xss = sum(sum(1 for v in r['vulnerabilities'] if v['type'] == 'dom_xss') for r in results)
        stored = sum(sum(1 for v in r['vulnerabilities'] if v['type'] == 'stored_xss') for r in results)
        blind = sum(sum(1 for v in r['vulnerabilities'] if v['type'] == 'blind_xss') for r in results)
        mutation = sum(sum(1 for v in r['vulnerabilities'] if v['type'] == 'mutation_xss') for r in results)
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        verified_count = 0
        for result in results:
            for vuln in result['vulnerabilities']:
                severity = vuln.get('severity', 'medium')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                if vuln.get('verified', False):
                    verified_count += 1
        
        html_content = html_template.format(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            target=self.config.target_url or self.config.target_domain or self.config.target_list or 'Multiple Targets',
            total_urls=len(results),
            vulnerable_urls=sum(1 for r in results if r['vulnerabilities']),
            total_vulns=sum(len(r['vulnerabilities']) for r in results),
            verified_count=verified_count,
            reflected_count=reflected,
            dom_count=dom_xss,
            stored_count=stored,
            blind_count=blind,
            mutation_count=mutation,
            critical_count=severity_counts.get('critical', 0),
            high_count=severity_counts.get('high', 0),
            medium_count=severity_counts.get('medium', 0),
            low_count=severity_counts.get('low', 0),
            vulnerabilities_html=vulnerabilities_html
        )
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
        
        with open(output_file, 'w') as f:
            f.write(html_content)
