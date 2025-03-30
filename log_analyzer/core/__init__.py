# -*- coding: utf-8 -*-
"""Core module public API exports"""

# Terminal color configuration (see config.py)
from .config import Colors

# Main log parsing entry point (see detection.py)
from .detection import parse_log_file

# Explicit exports control
__all__ = ['Colors', 'parse_log_file']