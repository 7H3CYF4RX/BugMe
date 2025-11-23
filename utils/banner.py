"""
Banner and ASCII art for BugMe
"""
from colorama import Fore, Style

def print_banner():
    """Print the BugMe banner"""
    banner = f"""
{Fore.YELLOW}
  ██████╗ ██╗   ██╗ ██████╗     ███╗   ███╗███████╗
  ██╔══██╗██║   ██║██╔════╝     ████╗ ████║██╔════╝
  ██████╔╝██║   ██║██║  ███╗    ██╔████╔██║█████╗  
  ██╔══██╗██║   ██║██║   ██║    ██║╚██╔╝██║██╔══╝  
  ██████╔╝╚██████╔╝╚██████╔╝    ██║ ╚═╝ ██║███████╗
  ╚═════╝  ╚═════╝  ╚═════╝     ╚═╝     ╚═╝╚══════╝
{Style.RESET_ALL}
           {Fore.CYAN}Advanced XSS Vulnerability Scanner{Style.RESET_ALL}
              {Fore.GREEN}Source Code Analysis & Live Testing{Style.RESET_ALL}

                    {Fore.WHITE}Version 3.0{Style.RESET_ALL}
              {Fore.MAGENTA}Created by: Muhammed Farhan{Style.RESET_ALL}
"""
    print(banner)
