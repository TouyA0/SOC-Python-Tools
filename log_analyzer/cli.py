import argparse
import os
import sys
from pathlib import Path
from datetime import datetime

from log_analyzer.core.detection import parse_log_file
from log_analyzer.core.watch import watch_log_file
from log_analyzer.core.config import Colors, MIN_ANALYSIS_INTERVAL
from log_analyzer.core.utils import colorize, load_whitelist
from log_analyzer.core.reporting import generate_reports

def main():
    """
    EN: Command-line interface entry point
    FR: Point d'entrée de l'interface en ligne de commande
    """
    parser = create_parser()
    args = parser.parse_args()
    
    # EN: Initialize Windows color support | FR: Initialisation du support couleur pour Windows
    if os.name == 'nt':
        Colors.init_windows_support()
    
    # EN: Validate log file existence | FR: Vérification de l'existence du fichier log
    log_path = Path(args.log_file).resolve()
    if not log_path.exists():
        exit_with_error(f"Log file not found: {log_path}", Colors.RED)

    # EN: Build analysis configuration | FR: Construction de la configuration d'analyse
    config = {
        'log_path': log_path,
        'threshold': args.threshold,
        'time_window': args.timewindow,
        'ignore_internal': args.ignore_internal,
        'ignore_whitelisted': not args.no_whitelist,
        'whitelist': load_whitelist(args.whitelist) if not args.no_whitelist else set(),
        'output': args.output
    }

    # EN: Execute selected mode | FR: Exécution du mode sélectionné
    if args.watch:
        handle_watch_mode(config)
    else:
        handle_single_run(config)

def create_parser() -> argparse.ArgumentParser:
    """
    EN: Create CLI argument parser with analysis options
    FR: Crée le parser d'arguments pour les options d'analyse
    """
    parser = argparse.ArgumentParser(
        description=colorize("SOC Log Analyzer with Whitelist Support", Colors.BLUE),
        epilog=colorize("Example: log-analyzer access.log -w whitelist.txt", Colors.GRAY),
        formatter_class=argparse.RawTextHelpFormatter
    )

    # EN: Main log file argument | FR: Argument principal du fichier log
    parser.add_argument(
        'log_file',
        help="Path to the log file (e.g. /var/log/apache2/access.log)"
    )

    # EN: Analysis parameters group | FR: Groupe des paramètres d'analyse
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
        help="Analysis time window in hours (default: 1.0)"
    )

    # EN: Filtering options group | FR: Groupe des options de filtrage
    parser.add_argument(
        '-i', '--ignore-internal',
        action='store_true',
        help='Exclude private IP addresses from analysis'
    )
    
    parser.add_argument(
        '-w', '--whitelist',
        metavar='FILE',
        default='data/whitelist.txt',
        help="Path to whitelist file (default: data/whitelist.txt)"
    )
    
    parser.add_argument(
        '--no-whitelist',
        action='store_true',
        help="Disable whitelist filtering"
    )

    # EN: Output control group | FR: Groupe de contrôle de sortie
    parser.add_argument(
        '-o', '--output',
        default='suspicious_ips_report',
        help="Output file base name (default: suspicious_ips_report)"
    )

    # EN: Watch mode group | FR: Groupe du mode surveillance
    parser.add_argument(
        '--watch',
        action='store_true',
        help='Enable real-time log monitoring'
    )
    
    parser.add_argument(
        '--min-interval',
        type=int,
        default=MIN_ANALYSIS_INTERVAL,
        help=f"Minimum analysis interval in seconds (default: {MIN_ANALYSIS_INTERVAL})"
    )

    return parser

def handle_watch_mode(config: dict):
    """
    EN: Handle continuous log monitoring
    FR: Gère la surveillance continue du fichier log
    """
    print(colorize("\n👀 Starting real-time monitoring...", Colors.BLUE))
    print(colorize("   Press Ctrl+C to stop\n", Colors.GRAY))
    
    # EN: Pass validated config to watch system | FR: Passe la configuration validée au système de surveillance
    watch_log_file({
        'log_path': config['log_path'],
        'threshold': config['threshold'],
        'time_window': config['time_window'],
        'ignore_internal': config['ignore_internal'],
        'ignore_whitelisted': config['ignore_whitelisted'],
        'whitelist': config['whitelist'],
        'output': config['output']
    })

def handle_single_run(config: dict):
    """
    EN: Handle one-time log analysis
    FR: Gère une analyse unique du fichier log
    """
    print(colorize(f"\n🔍 Analyzing {config['log_path'].name}", Colors.BLUE) +
          colorize(f" [Threshold: {config['threshold']} requests]", Colors.CYAN))
    
    # EN: Run core detection algorithm | FR: Exécute l'algorithme principal de détection
    suspicious = parse_log_file(
        config['log_path'],
        config['threshold'],
        config['time_window'],
        config['ignore_internal'],
        config['ignore_whitelisted'],
        config['whitelist']
    )

    if suspicious:
        print_results(suspicious)
        generate_reports(suspicious, config['output'])
    else:
        print(colorize("\n✅ No suspicious activity detected", Colors.GREEN))

def print_results(suspicious: dict):
    """
    EN: Format and display analysis results
    FR: Formate et affiche les résultats d'analyse
    """
    # EN: Calculate threat statistics | FR: Calcule les statistiques de menace
    critical = sum(1 for ip in suspicious if suspicious[ip]['threat_score'] >= 70)
    total = len(suspicious)
    
    print(colorize(f"\n🚨 {total} suspicious IP(s) detected", Colors.RED) +
          colorize(f" ({critical} critical)", Colors.RED + Colors.BOLD))
    
    # EN: Sort by threat score descending | FR: Tri par score de menace décroissant
    for ip, data in sorted(
        suspicious.items(),
        key=lambda x: x[1]['threat_score'],
        reverse=True
    ):
        # EN: Determine color based on threat level | FR: Détermine la couleur selon le niveau de menace
        color = Colors.RED if data['threat_score'] >= 70 else \
                Colors.ORANGE if data['threat_score'] >= 40 else \
                Colors.YELLOW
        
        # EN: Format threat types | FR: Formate les types de menaces
        threats = " | ".join(
            colorize(t[0], color) for t in data.get('threats', [])
        ) or colorize("Suspicious behavior", Colors.YELLOW)
        
        print(f" - {colorize(ip, Colors.BOLD)}: "
              f"{data['count']} requests "
              f"(Score: {colorize(data['threat_score'], color)}) {threats}")

def exit_with_error(message: str, color: str = Colors.RED):
    """
    EN: Print error message and exit with code 1
    FR: Affiche un message d'erreur et quitte avec le code 1
    """
    print(colorize(f"\n❌ Error: {message}", color))
    sys.exit(1)

if __name__ == "__main__":
    main()