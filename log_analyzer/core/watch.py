import time
from datetime import datetime
from pathlib import Path
from typing import Dict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from .detection import parse_log_file
from .reporting import generate_reports
from .config import Colors
from .utils import colorize

# ======================================================================
# WATCH MODE COMPONENTS / COMPOSANTS DU MODE SURVEILLANCE
# ======================================================================

class LogFileHandler(FileSystemEventHandler):
    """
    EN: Monitor log file changes and trigger analysis
    FR: Surveille les modifications de fichier log et déclenche l'analyse
    """
    
    def __init__(self, config: Dict):
        """
        EN: Initialize watchdog configuration
        FR: Initialiser la configuration de surveillance
        
        Args/Paramètres:
            config: EN: Analysis parameters dictionary | FR: Dictionnaire de paramètres d'analyse
        """
        super().__init__()
        self.config = config
        self.all_suspicious = {} # EN: Cumulative threat data | FR: Données de menace cumulées
        self.last_report_time = time.time() # EN: Last report timestamp | FR: Horodatage dernier rapport
        self.last_position = 0 # EN: Last read position in log | FR: Dernière position lue dans le log
        self.output_base = Path(self.config['output']).stem # EN: Base output name | FR: Nom de base des sorties

    def on_modified(self, event):
        """
        EN: Triggered on file modification events
        FR: Déclenché sur les événements de modification de fichier
        """
        if event.src_path == str(self.config['log_path']):
            self._process_changes()

    def _process_changes(self):
        """
        EN: Detect and process new log entries
        FR: Détecter et traiter les nouvelles entrées de log
        """
        try:
            current_size = self.config['log_path'].stat().st_size

            # EN: Handle log rotation | FR: Gérer la rotation des logs
            if current_size < self.last_position:
                print(colorize("⚠️ Log file rotated - resetting position", Colors.YELLOW))
                self.last_position = 0

            if current_size > self.last_position:
                # EN: Read new content | FR: Lire le nouveau contenu
                with open(self.config['log_path'], 'r', encoding='utf-8') as f:
                    f.seek(self.last_position)
                    new_lines = f.readlines()
                    self.last_position = f.tell()

                if new_lines:
                    print(colorize(f"\n🔄 New entries: {len(new_lines)} lines", Colors.CYAN))
                    self._analyze_new_lines(new_lines)

        except Exception as e:
            print(colorize(f"⚠️ Watch error: {str(e)}", Colors.RED))

    def _analyze_new_lines(self, lines: list):
        """
        EN: Analyze new log entries in temporary file
        FR: Analyser les nouvelles entrées dans un fichier temporaire
        
        Args/Paramètres:
            lines: EN: List of new log lines | FR: Liste des nouvelles lignes de log
        """
        temp_file = self.config['log_path'].with_suffix('.tmp')
        try:
            # EN: Write to temp file for parsing | FR: Écrire dans fichier temp pour l'analyse
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.writelines(lines)

            # EN: Run threat detection | FR: Exécuter la détection de menaces
            suspicious = parse_log_file(
                temp_file,
                self.config['threshold'],
                self.config['time_window'],
                self.config['ignore_internal'],
                self.config['ignore_whitelisted'],
                self.config['whitelist']
            )

            if suspicious:
                self._update_suspicious_ips(suspicious)
                self._print_alerts(suspicious)

            temp_file.unlink()
            
        except Exception as e:
            print(colorize(f"⚠️ Analysis failed: {str(e)}", Colors.RED))
            if temp_file.exists():
                temp_file.unlink()

    def _update_suspicious_ips(self, new_suspicious: Dict):
        """
        EN: Merge new findings with historical data
        FR: Fusionner nouvelles détections avec données historiques
        
        Args/Paramètres:
            new_suspicious: EN: Newly detected threats | FR: Nouvelles menaces détectées
        """
        for ip, data in new_suspicious.items():
            if ip in self.all_suspicious:
                # EN: Update existing IP metrics | FR: Mettre à jour les métriques existantes
                existing = self.all_suspicious[ip]
                existing['count'] += data['count']
                existing['threat_score'] = max(
                    existing['threat_score'], 
                    data['threat_score']
                )
                # EN: Merge threat types | FR: Fusionner les types de menaces
                existing_threats = {t[0] for t in existing.get('threats', [])}
                for threat in data.get('threats', []):
                    if threat[0] not in existing_threats:
                        existing['threats'].append(threat)
            else:
                self.all_suspicious[ip] = data

    def _print_alerts(self, suspicious: Dict):
        """
        EN: Display real-time alerts in console
        FR: Afficher les alertes en temps réel dans la console
        
        Args/Paramètres:
            suspicious: EN: New suspicious IPs | FR: Nouvelles IPs suspectes
        """
        for ip, data in suspicious.items():
            # EN: Color coding by threat level | FR: Codage couleur par niveau de menace
            color = Colors.RED if data['threat_score'] >= 70 else \
                    Colors.ORANGE if data['threat_score'] >= 40 else \
                    Colors.YELLOW
                    
            # EN: Format threat descriptions | FR: Formater les descriptions de menaces
            threats = " | ".join(
                f"{colorize(t[0], color)} ({t[1]})" 
                for t in data.get('threats', [])
            ) or colorize("Suspicious behavior", Colors.YELLOW)

            alert_msg = (
                f"{colorize('🚨 ALERT:', Colors.RED)} "
                f"{colorize(ip, Colors.BOLD)} "
                f"(Score: {colorize(data['threat_score'], color)}) - {threats}"
            )
            print(alert_msg)

def watch_log_file(config: Dict):
    """
    EN: Start continuous log file monitoring
    FR: Démarrer la surveillance continue du fichier log
    
    Args/Paramètres:
        config: EN: Monitoring configuration | FR: Configuration de surveillance
    """
    event_handler = LogFileHandler(config)
    observer = Observer()
    observer.schedule(
        event_handler,
        path=str(config['log_path'].parent),
        recursive=False
    )
    
    print(colorize("\n👀 Starting real-time monitoring...", Colors.BLUE))
    print("   Press Ctrl+C to stop\n", Colors.GRAY)
    
    try:
        observer.start()
        # EN: Main monitoring loop | FR: Boucle principale de surveillance
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print(colorize("\n🛑 Monitoring stopped", Colors.RED))
        
        if event_handler.all_suspicious:
            print(colorize("📊 Generating final reports...", Colors.BLUE))
            generate_reports(
                event_handler.all_suspicious,
                event_handler.output_base
            )
            
    observer.join()