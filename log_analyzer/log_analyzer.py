#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Apache Log Analyzer - SOC Tool
Version: 2.0
Author: TouyA0
"""

import re
from collections import defaultdict
import csv
from datetime import datetime, timedelta
import argparse  # New import for CLI argument parsing


def parse_log_file(log_path, threshold=100, time_window_hours=1):
    """
    Analyzes Apache log files and detects suspicious IPs
    
    Expected log format:
    '127.0.0.1 - - [01/Jan/2023:12:00:00 +0000] "GET / HTTP/1.1" 200 1234'
    (IP - identity - user [timestamp] "request" status bytes)

    Args:
        log_path (str): Path to the log file
        threshold (int): Request threshold to consider an IP as suspicious
        time_window_hours (int): Analysis time window in hours
    
    Returns:
        dict: Dictionary of suspicious IPs with their statistics
    """
    # Regex patterns for data extraction
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    date_pattern = r'\[(.*?)\]'
    status_pattern = r'" (\d{3}) '
    request_pattern = r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS) (.+?) HTTP'

    # Create a special dictionary to track IP activity
    # defaultdict automatically handles missing keys by creating new entries
    ip_activity = defaultdict(lambda: {
        'count': 0, # Total request count for this IP
        'status_codes': defaultdict(int), # Sub-dictionary to count occurrences of each HTTP status code - Format: {'200': 5, '404': 2, '403': 3}
        'requests': defaultdict(int), # Sub-dictionary to count request types - Format: {'GET /': 10, 'POST /login': 2}
        'first_seen': None, # Timestamp of first request from this IP
        'last_seen': None # Timestamp of most recent request from this IP
    })

    # Open the log file in read mode with UTF-8 encoding
    with open(log_path, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                # Data extraction with regex
                ip = re.search(ip_pattern, line).group()
                date_str = re.search(date_pattern, line).group(1)
                status = re.search(status_pattern, line).group(1)
                method, path = re.search(request_pattern, line).groups()
                
                # Date conversion string -> datetime object
                log_date = datetime.strptime(date_str.split()[0], '%d/%b/%Y:%H:%M:%S')
                
                # Update IP statistics
                ip_data = ip_activity[ip] # Get or create the tracking dictionary for this IP
                ip_data['count'] += 1 # Increment total request count for this IP
                ip_data['status_codes'][status] += 1 # Increment count for this specific status code
                ip_data['requests'][f"{method} {path}"] += 1 # Increment count for this specific request type (method + path)
                
                # Update first_seen if this is the earliest request from this IP
                if ip_data['first_seen'] is None or log_date < ip_data['first_seen']:
                    ip_data['first_seen'] = log_date
                # Update last_seen if this is the most recent request from this IP
                if ip_data['last_seen'] is None or log_date > ip_data['last_seen']:
                    ip_data['last_seen'] = log_date
            
            # Handle potential errors that might occur during parsing
            except (AttributeError, ValueError) as e:
                print(f"Parsing error on line: {line.strip()} - {str(e)}") # Print error message showing the problematic line and error details
                continue # Skip to next line if current line fails to parse
    
    # Filter suspicious IPs
    suspicious_ips = {} # Initialize an empty dictionary to store suspicious IPs and their activity data
    for ip, data in ip_activity.items(): # Iterate through all IPs and their activity data in the ip_activity dictionary
        duration = data['last_seen'] - data['first_seen'] # Calculate the time duration between first and last request from this IP
        if duration <= timedelta(hours=time_window_hours) and data['count'] > threshold:
            suspicious_ips[ip] = data
    return suspicious_ips


def generate_report(suspicious_ips, output_file='suspicious_ips_report.csv'):
    """
    Generates a CSV report of suspicious IPs
    
    Args:
        suspicious_ips (dict): Dictionary of suspicious IPs
        output_file (str): Output CSV file
    """
    # Open the output CSV file in write mode with UTF-8 encoding - 'newline=""' prevents extra blank lines in output (Windows compatibility)
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        # Define column headers for our CSV report
        fieldnames = ['IP', 'Total Requests', 'First Seen', 'Last Seen', 
                     'Top Status Code', 'Top Request', 'Status Codes', 'Request Types']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames) # Create a DictWriter object configured with our column headers
        writer.writeheader() # Write the header row to the CSV file

        # Process each suspicious IP and its activity data
        for ip, data in suspicious_ips.items():
            top_status = max(data['status_codes'].items(), key=lambda x: x[1])[0] # Find the most common status code for this IP - lambda extracts the count
            top_request = max(data['requests'].items(), key=lambda x: x[1])[0] # Find the most frequent request (method + path) for this IP
            
            # Write a formatted row for this IP
            writer.writerow({
                'IP': ip,
                'Total Requests': data['count'],
                'First Seen': data['first_seen'],
                'Last Seen': data['last_seen'],
                'Top Status Code': top_status,
                'Top Request': top_request,
                'Status Codes': ', '.join(f"{k}({v})" for k, v in data['status_codes'].items()), # Format all status codes as "CODE(COUNT), CODE(COUNT)"
                'Request Types': ', '.join(f"{k}({v})" for k, v in data['requests'].items()) # Format all request types as "METHOD PATH(COUNT), METHOD PATH(COUNT)"
            })


def main():
    """
    Main CLI entry point with professional argument parsing
    Handles command line interface and executes the log analysis
    """
    # Initialize argument parser with SOC-specific help information
    parser = argparse.ArgumentParser(
        description="SOC Log Analyzer - Detect suspicious IP activity in web server logs",
        epilog="Example: log-analyzer /var/log/apache2/access.log --threshold 50 --timewindow 0.5"
    )
    
    # Required positional argument for log file path
    parser.add_argument(
        'log_file',
        help="Path to the log file (e.g. /var/log/apache2/access.log)"
    )
    
    # Optional arguments with default values
    parser.add_argument(
        '-t', '--threshold',
        type=int,
        default=100,
        help="Minimum requests to flag as suspicious (default: 100)"
    )
    
    parser.add_argument(
        '-tw', '--timewindow',
        type=float,
        default=1.0,
        help="Analysis time window in hours (e.g. 0.5 for 30min, default: 1h)"
    )
    
    parser.add_argument(
        '-o', '--output',
        default='suspicious_ips_report.csv',
        help="Output CSV file path (default: suspicious_ips_report.csv)"
    )
    
    # Parse command line arguments
    args = parser.parse_args()
    
    # Execute log analysis with provided parameters
    print(f"🔍 Analyzing {args.log_file} (threshold: {args.threshold}, time window: {args.timewindow}h)...")
    suspicious = parse_log_file(args.log_file, args.threshold, args.timewindow)
    
    # Display and save results
    if suspicious:
        print(f"🚨 {len(suspicious)} suspicious IP(s) detected:")
        for ip in suspicious:
            print(f"- {ip}: {suspicious[ip]['count']} requests")
        
        generate_report(suspicious, args.output)
        print(f"📊 Report saved to {args.output}")
    else:
        print("✅ No suspicious IPs detected.")


if __name__ == "__main__":
    main()