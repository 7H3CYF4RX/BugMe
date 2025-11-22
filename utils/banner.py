"""
Banner and ASCII art for BugMe
"""
from colorama import Fore, Style

def print_banner():
    """Print the BugMe banner"""
    banner = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  {Fore.YELLOW}██████╗ ██╗   ██╗ ██████╗     ███╗   ███╗███████╗{Fore.RED}           ║
║  {Fore.YELLOW}██╔══██╗██║   ██║██╔════╝     ████╗ ████║██╔════╝{Fore.RED}           ║
║  {Fore.YELLOW}██████╔╝██║   ██║██║  ███╗    ██╔████╔██║█████╗{Fore.RED}             ║
║  {Fore.YELLOW}██╔══██╗██║   ██║██║   ██║    ██║╚██╔╝██║██╔══╝{Fore.RED}             ║
║  {Fore.YELLOW}██████╔╝╚██████╔╝╚██████╔╝    ██║ ╚═╝ ██║███████╗{Fore.RED}           ║
║  {Fore.YELLOW}╚═════╝  ╚═════╝  ╚═════╝     ╚═╝     ╚═╝╚══════╝{Fore.RED}           ║
║                                                              ║
║           {Fore.CYAN}Advanced XSS Vulnerability Scanner{Fore.RED}                  ║
║              {Fore.GREEN}Source Code Analysis & Live Testing{Fore.RED}             ║
║                                                              ║
║                    {Fore.WHITE}Version 3.0{Fore.RED}                               ║
║              {Fore.MAGENTA}Created by: Muhammed Farhan{Fore.RED}                ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)
