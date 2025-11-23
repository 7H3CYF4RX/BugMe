"""
Enhanced Terminal UI with animations and progress bars
"""
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich import box
import time

console = Console()

class BugMeUI:
    """Enhanced UI for BugMe scanner"""
    
    @staticmethod
    def show_scan_config(config, url_count):
        """Display scan configuration in a beautiful panel"""
        table = Table(show_header=False, box=box.ROUNDED, border_style="cyan")
        table.add_column("Setting", style="cyan bold")
        table.add_column("Value", style="white")
        
        table.add_row("🎯 Target URLs", f"{url_count}")
        table.add_row("🔍 XSS Types", "5 (Reflected, Stored, DOM, Blind, Mutation)")
        table.add_row("⚡ Techniques", "15+ detection methods")
        table.add_row("💣 Payloads", "1,876+ (ultimate.txt)")
        table.add_row("🌐 Browser Verification", "✅ ENABLED" if config.verify_live else "❌ DISABLED")
        
        if config.verified_only:
            table.add_row("🎯 Filter Mode", "✅ VERIFIED ONLY")
        
        table.add_row("🧵 Threads", f"{config.threads}")
        table.add_row("⏱️  Timeout", f"{config.timeout}s")
        
        panel = Panel(
            table,
            title="[bold cyan]⚙️  Scan Configuration[/bold cyan]",
            border_style="cyan",
            padding=(1, 2)
        )
        console.print(panel)
    
    @staticmethod
    def create_scan_progress():
        """Create a beautiful progress bar for scanning"""
        return Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(complete_style="green", finished_style="bold green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("•"),
            TextColumn("[cyan]{task.completed}/{task.total}"),
            TextColumn("•"),
            TimeElapsedColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=console,
            expand=True
        )
    
    @staticmethod
    def show_phase_banner(phase_num, phase_name, icon="🔍"):
        """Show animated phase banner"""
        text = Text()
        text.append(f"\n{icon} ", style="bold yellow")
        text.append(f"[{phase_num}/5] ", style="bold cyan")
        text.append(phase_name, style="bold white")
        console.print(text)
    
    @staticmethod
    def show_vulnerability(vuln_data):
        """Show vulnerability found with full details"""
        severity_colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "cyan"
        }
        
        severity = vuln_data.get('severity', 'UNKNOWN').upper()
        color = severity_colors.get(severity, "white")
        
        # Create detailed table
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Label", style="cyan bold", no_wrap=True)
        table.add_column("Value", style="white", overflow="fold")
        
        table.add_row("🌐 URL:", vuln_data.get('url', 'N/A'))
        table.add_row("🎯 Type:", vuln_data.get('type', 'N/A').upper().replace('_', ' '))
        
        if vuln_data.get('parameter'):
            table.add_row("📝 Parameter:", vuln_data.get('parameter'))
        
        if vuln_data.get('payload'):
            payload = vuln_data.get('payload', '')
            table.add_row("💣 Payload:", payload[:100] + "..." if len(payload) > 100 else payload)
        
        # Verification status
        verified = vuln_data.get('verified', False)
        if verified:
            table.add_row("✅ Verified:", f"[green]EXECUTION CONFIRMED[/green]")
            if vuln_data.get('alert_text'):
                table.add_row("🔔 Alert:", vuln_data.get('alert_text'))
        else:
            table.add_row("⚠️  Verified:", "[yellow]Reflection only (not confirmed)[/yellow]")
        
        table.add_row("🎯 Severity:", f"[{color}]{severity}[/{color}]")
        
        if vuln_data.get('poc_url'):
            table.add_row("🔗 PoC URL:", vuln_data.get('poc_url'))
        
        panel = Panel(
            table,
            title=f"[{color}]🚨 XSS VULNERABILITY FOUND[/{color}]",
            border_style=color,
            box=box.DOUBLE,
            padding=(0, 1)
        )
        console.print(panel)
        
        # Print full PoC URL separately for easy copying (more prominent)
        if vuln_data.get('poc_url'):
            console.print(f"\n[bold cyan]📋 COPY POC URL:[/bold cyan]")
            console.print(f"[white]{vuln_data.get('poc_url')}[/white]\n")
    
    @staticmethod
    def show_dom_patterns_summary(url, pattern_count):
        """Show DOM XSS patterns summary"""
        # Create a compact table for DOM patterns
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Label", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("🌐 URL:", url)
        table.add_row("🔍 Type:", "DOM XSS PATTERN (Static Analysis)")
        table.add_row("📊 Patterns:", f"{pattern_count} potentially dangerous data flows")
        table.add_row("⚠️  Verified:", "❌ Not confirmed (requires manual testing)")
        table.add_row("🎯 Severity:", "[yellow]MEDIUM[/yellow]")
        
        panel = Panel(
            table,
            title="[bold yellow]⚠️  DOM XSS PATTERNS DETECTED[/bold yellow]",
            border_style="yellow",
            box=box.ROUNDED,
            padding=(0, 1)
        )
        console.print(panel)
    
    @staticmethod
    def show_scan_summary(stats):
        """Show final scan summary with beautiful formatting"""
        table = Table(title="[bold cyan]📊 Scan Summary[/bold cyan]", box=box.DOUBLE_EDGE, border_style="cyan")
        table.add_column("Metric", style="cyan bold", justify="left")
        table.add_column("Count", style="white bold", justify="right")
        
        table.add_row("URLs Scanned", f"{stats['urls_scanned']}")
        table.add_row("Vulnerable URLs", f"[red]{stats['vulnerable_urls']}[/red]")
        table.add_row("Total Vulnerabilities", f"[red bold]{stats['total_vulns']}[/red bold]")
        
        console.print("\n")
        console.print(table)
        
        # Vulnerability types
        if stats.get('vuln_types'):
            type_table = Table(title="[bold yellow]🎯 Vulnerability Types[/bold yellow]", box=box.ROUNDED, border_style="yellow")
            type_table.add_column("Type", style="yellow")
            type_table.add_column("Count", style="white bold", justify="right")
            
            for vtype, count in stats['vuln_types'].items():
                type_table.add_row(vtype, str(count))
            
            console.print(type_table)
        
        # Severity breakdown
        if stats.get('severity'):
            sev_table = Table(title="[bold red]⚠️  Severity Breakdown[/bold red]", box=box.ROUNDED, border_style="red")
            sev_table.add_column("Severity", style="red")
            sev_table.add_column("Count", style="white bold", justify="right")
            
            for severity, count in stats['severity'].items():
                color = {"Critical": "bold red", "High": "red", "Medium": "yellow", "Low": "blue"}.get(severity, "white")
                sev_table.add_row(f"[{color}]{severity}[/{color}]", str(count))
            
            console.print(sev_table)
    
    @staticmethod
    def show_crawl_progress(current, total, url):
        """Show crawling progress"""
        console.print(f"[cyan]  ├─ Crawling:[/cyan] [white]{url[:80]}...[/white]", end="\r")
    
    @staticmethod
    def show_success(message):
        """Show success message"""
        console.print(f"[bold green]✅ {message}[/bold green]")
    
    @staticmethod
    def show_warning(message):
        """Show warning message"""
        console.print(f"[bold yellow]⚠️  {message}[/bold yellow]")
    
    @staticmethod
    def show_error(message):
        """Show error message"""
        console.print(f"[bold red]❌ {message}[/bold red]")
    
    @staticmethod
    def show_info(message):
        """Show info message"""
        console.print(f"[cyan]ℹ️  {message}[/cyan]")
