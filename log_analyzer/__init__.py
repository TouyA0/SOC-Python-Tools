"""
SOC Log Analyzer Package

Exposes:
- parse_log_file(): Analyze log files for suspicious activity
- generate_report(): Create CSV reports from analysis results
"""

from .log_analyzer import parse_log_file, generate_report

__all__ = ['parse_log_file', 'generate_report']