# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025

import logging
import sys


class COLORS:
    """ANSI color codes for terminal output"""
    reset = "\033[0m"
    red = "\033[31m"
    green_code = "\033[32m"
    yellow_code = "\033[33m"
    blue = "\033[34m"
    magenta = "\033[35m"
    cyan = "\033[36m"
    white = "\033[37m"
    bold = "\033[1m"
    
    @staticmethod
    def intense_red(text):
        return f"\033[91m{text}\033[0m"
    
    @staticmethod
    def intense_blue(text):
        return f"\033[94m{text}\033[0m"
    
    @staticmethod
    def intense_green(text):
        return f"\033[92m{text}\033[0m"
    
    @staticmethod
    def green(text):
        return f"\033[32m{text}\033[0m"
    
    @staticmethod
    def yellow(text):
        return f"\033[33m{text}\033[0m"


def get_logger(name, color=COLORS.white):
    """Get a colored logger instance"""
    logger = logging.getLogger(name)
    
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            f'{color}%(asctime)s - %(name)s - %(levelname)s{COLORS.reset} - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    
    return logger 