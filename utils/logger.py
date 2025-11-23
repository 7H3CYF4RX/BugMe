"""
Logging utilities for BugMe
"""
import logging
from colorama import Fore, Style

def setup_logger(verbose=False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    
    # Create logger
    logger = logging.getLogger('bugme')
    logger.setLevel(level)
    
    # Create console handler with custom formatter
    ch = logging.StreamHandler()
    ch.setLevel(level)
    
    # Custom formatter
    class ColoredFormatter(logging.Formatter):
        COLORS = {
            'DEBUG': Fore.BLUE,
            'INFO': Fore.CYAN,
            'WARNING': Fore.YELLOW,
            'ERROR': Fore.RED,
            'CRITICAL': Fore.RED + Style.BRIGHT
        }
        
        def format(self, record):
            color = self.COLORS.get(record.levelname, '')
            record.levelname = f"{color}[{record.levelname}]{Style.RESET_ALL}"
            return super().format(record)
    
    formatter = ColoredFormatter('%(levelname)s %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    
    return logger
