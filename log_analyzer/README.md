# Log Analyzer

## Features
- Detect brute force attacks (multiple 403/401)
- Identify port scanners (request spikes)
- Highlight suspicious user agents
- Export to CSV for SIEM integration

## Quick Start
```bash
# Install
pip install -e .[dev]

## Usage
```bash
log-analyzer <log_file> [options]

Key                     Options
Option	                Description
-h, --help              Show the help message and exit
-t, --threshold	        Request threshold to flag IPs (default: 100)
-tw, --timewindow	    Analysis time window in hours (default: 1.0)
-o, --output	        Output CSV file (default: suspicious_ips_report.csv)