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
            print(f"  ├─ DOM-based XSS: {Fore.WHITE}0{Style.RESET_ALL}")
            print(f"  └─ Stored XSS: {Fore.WHITE}0{Style.RESET_ALL}")
            
            print(f"\n{Fore.YELLOW}[+] Severity Breakdown:{Style.RESET_ALL}")
            print(f"  ├─ Critical: {Fore.RED}{severity_counts['critical']}{Style.RESET_ALL}")
            print(f"  ├─ High: {Fore.RED}{severity_counts['high']}{Style.RESET_ALL}")
            print(f"  ├─ Medium: {Fore.YELLOW}{severity_counts['medium']}{Style.RESET_ALL}")
            print(f"  └─ Low: {Fore.GREEN}{severity_counts['low']}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}\n")
    
    def save_json(self, results, output_file):
        """Save results as JSON"""
        report = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'tool': 'BugMe v1.0',
                'target': self.config.target_url or self.config.target_domain
            },
            'summary': {
                'total_urls': len(results),
                'vulnerable_urls': sum(1 for r in results if r['vulnerabilities']),
                'total_vulnerabilities': sum(len(r['vulnerabilities']) for r in results)
            },
            'results': results
        }
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
    
    def save_html(self, results, output_file):
        """Save results as HTML report"""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>BugMe XSS Scan Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #d32f2f;
            border-bottom: 3px solid #d32f2f;
            padding-bottom: 10px;
        }}
        .summary {{
            background: #e3f2fd;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .vulnerability {{
            background: #fff3e0;
            border-left: 4px solid #ff9800;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }}
        .vulnerability.high {{
            background: #ffebee;
            border-left-color: #d32f2f;
        }}
        .vulnerability.medium {{
            background: #fff3e0;
            border-left-color: #ff9800;
        }}
        .vulnerability.low {{
            background: #e8f5e9;
            border-left-color: #4caf50;
        }}
        .poc {{
            background: #f5f5f5;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            word-break: break-all;
            margin: 10px 0;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
            margin: 2px;
        }}
        .badge.high {{ background: #d32f2f; color: white; }}
        .badge.medium {{ background: #ff9800; color: white; }}
        .badge.low {{ background: #4caf50; color: white; }}
        .badge.verified {{ background: #2196f3; color: white; }}
        .timestamp {{
            color: #666;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🐛 BugMe XSS Scan Report</h1>
        <p class="timestamp">Generated: {timestamp}</p>
        
        <div class="summary">
            <h2>Summary</h2>
            <p><strong>Target:</strong> {target}</p>
            <p><strong>URLs Scanned:</strong> {total_urls}</p>
            <p><strong>Vulnerable URLs:</strong> {vulnerable_urls}</p>
            <p><strong>Total Vulnerabilities:</strong> {total_vulns}</p>
        </div>
        
        <h2>Vulnerabilities</h2>
        {vulnerabilities_html}
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
                
                vuln_html = f"""
                <div class="vulnerability {severity}">
                    <h3>{result['url']}</h3>
                    <p>
                        <span class="badge {severity}">{severity.upper()}</span>
                        {verified_badge}
                    </p>
                    <p><strong>Parameter:</strong> {vuln['parameter']}</p>
                    <p><strong>Payload:</strong> <code>{vuln['payload']}</code></p>
                    <p><strong>Context:</strong> {vuln['context']}</p>
                    <p><strong>Proof of Concept:</strong></p>
                    <div class="poc">{vuln['poc_url']}</div>
                    {f"<p><strong>Filters Detected:</strong> {', '.join(vuln['filters'])}</p>" if vuln['filters'] else ''}
                </div>
                """
                vulnerabilities_html += vuln_html
        
        if not vulnerabilities_html:
            vulnerabilities_html = "<p>No vulnerabilities found.</p>"
        
        html_content = html_template.format(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            target=self.config.target_url or self.config.target_domain,
            total_urls=len(results),
            vulnerable_urls=sum(1 for r in results if r['vulnerabilities']),
            total_vulns=sum(len(r['vulnerabilities']) for r in results),
            vulnerabilities_html=vulnerabilities_html
        )
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
        
        with open(output_file, 'w') as f:
            f.write(html_content)
