import re
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from collections import defaultdict

from .config import THREAT_CONFIG, STATUS_SCORES
from .utils import load_whitelist, is_whitelisted, is_internal_ip, colorize
from .config import Colors

# ======================================================================
# THREAT DETECTION FUNCTIONS / FONCTIONS DE DÉTECTION DE MENACES
# ======================================================================

def parse_log_file(log_path, threshold=100, time_window_hours=1, 
                  ignore_internal=False, ignore_whitelisted=True,
                  whitelist_file=None):
    """
    EN: Analyze log file for suspicious activity with configurable thresholds
    FR: Analyse un fichier log pour détecter des activités suspectes avec seuils configurables
    """
    # EN: Load approved IP list if enabled | FR: Charger la liste blanche si activé
    whitelist = load_whitelist(whitelist_file) if ignore_whitelisted else set()
    
    # EN: Regex patterns for log parsing | FR: Modèles regex pour l'analyse des logs
    ip_pattern = r'^(\S+)' # EN: Extract client IP | FR: Extraction IP client
    date_pattern = r'\[([^\]]+)\]' # EN: Timestamp extraction | FR: Extraction horodatage
    status_pattern = r'" (\d{3}) ' # EN: HTTP status code | FR: Code statut HTTP
    request_pattern = r'"(\S+) (\S+)' # EN: Method + path | FR: Méthode + chemin

    # EN: Data structure for IP activity tracking | FR: Structure de suivi d'activité par IP
    ip_activity = defaultdict(lambda: {
        'count': 0, # EN: Total requests | FR: Requêtes totales
        'status_codes': defaultdict(int), # EN: Status code frequency | FR: Fréquence codes statut
        'requests': defaultdict(int), # EN: Request path frequency | FR: Fréquence requêtes
        'first_seen': None, # EN: Initial request time | FR: Première requête
        'last_seen': None, # EN: Latest request time | FR: Dernière requête
        'user_agents': set() # EN: Unique user agents | FR: Agents utilisateurs uniques
    })

    with open(log_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line: # EN: Skip empty lines | FR: Ignorer lignes vides
                continue

            try:
                # EN: Extract key log components | FR: Extraction composants clés
                ip = re.search(ip_pattern, line).group(1)

                # EN: Filtering logic | FR: Logique de filtrage
                if ignore_whitelisted and is_whitelisted(ip, whitelist):
                    continue # EN: Skip whitelisted IPs | FR: Ignorer IPs autorisées

                if ignore_internal and is_internal_ip(ip):
                    continue # EN: Skip internal IPs | FR: Ignorer IPs internes

                # EN: Extract request details | FR: Extraction détails requête
                date_str = re.search(date_pattern, line).group(1)
                status = re.search(status_pattern, line).group(1)
                request_match = re.search(request_pattern, line)
                if not request_match: # EN: Skip malformed requests | FR: Ignorer requêtes incomplètes
                    continue
                method, path = request_match.groups()

                # EN: Convert log timestamp | FR: Conversion horodatage
                log_date = datetime.strptime(date_str.split()[0], '%d/%b/%Y:%H:%M:%S')
                
                # EN: Update IP activity metrics | FR: Mise à jour métriques IP
                ip_data = ip_activity[ip]
                ip_data['count'] += 1
                ip_data['status_codes'][status] += 1
                ip_data['requests'][f"{method} {path}"] += 1
                
                # EN: Update time boundaries | FR: Mise à jour des bornes temporelles
                if ip_data['first_seen'] is None or log_date < ip_data['first_seen']:
                    ip_data['first_seen'] = log_date
                if ip_data['last_seen'] is None or log_date > ip_data['last_seen']:
                    ip_data['last_seen'] = log_date
            
            except (AttributeError, ValueError) as e:
                # EN: Error handling for malformed entries | FR: Gestion des entrées corrompues
                print(colorize(f"Line {line_num}: Parsing error - {str(e)} - {line[:50]}...", Colors.YELLOW))
                continue

    # EN: Threat detection phase | FR: Phase de détection de menaces
    suspicious_ips = {}
    for ip, data in ip_activity.items():
        duration = data['last_seen'] - data['first_seen']

        # EN: Time-concentrated activity check | FR: Vérification activité concentrée
        if duration <= timedelta(hours=time_window_hours) and data['count'] > threshold:
            data['threats'] = detect_specific_threats(data) # EN: Pattern detection | FR: Détection motifs
            data['threat_score'] = calculate_threat_score(data) # EN: Risk scoring | FR: Calcul risque
            suspicious_ips[ip] = data

    return suspicious_ips

def detect_specific_threats(ip_data: Dict) -> List[Tuple[str, str]]:
    """EN: Detect brute force and port scan patterns | FR: Détecte force brute et scan de port"""
    threats = []
    
    # EN: BRUTE FORCE detection | FR: Détection force brute
    brute_config = THREAT_CONFIG['BRUTE_FORCE']
    if any(path in req for req in ip_data['requests'] 
           for path in brute_config['paths']):
        # EN: Count authentication failures | FR: Comptage échecs authentification
        auth_failures = sum(
            ip_data['status_codes'].get(code, 0) 
            for code in brute_config['status_codes']
        )
        if auth_failures >= brute_config['threshold']:
            threats.append(('BRUTE_FORCE', f'{auth_failures} auth failures'))
    
    # EN: PORT SCAN detection | FR: Détection scan de port
    port_scan_config = THREAT_CONFIG['PORT_SCAN']
    scan_attempts = sum(
        ip_data['status_codes'].get(code, 0) 
        for code in port_scan_config['status_codes']
    )
    unique_paths = len(ip_data['requests'])

    if (scan_attempts >= port_scan_config['request_threshold'] or
        unique_paths >= port_scan_config['unique_paths_threshold']):
        threats.append(('PORT_SCAN', f'{scan_attempts} errors, {unique_paths} unique paths'))
    
    return threats

def detect_sql_injection(requests_list: List[str]) -> bool:
    """EN: Detect SQL injection patterns | FR: Détecte motifs d'injection SQL"""
    patterns = THREAT_CONFIG['SQL_INJECTION']['patterns']
    return any(
        re.search(pattern, request, re.IGNORECASE)
        for request in requests_list
        for pattern in patterns
    )

def detect_ddos(ip_data: Dict, time_window_minutes: int = 1) -> bool:
    """EN: Detect DDoS patterns by request rate | FR: Détecte DDoS par taux de requêtes"""
    if ip_data['first_seen'] == ip_data['last_seen']: # EN: Single request case | FR: Requête unique
        return False
    
    time_window = timedelta(minutes=time_window_minutes)
    window_seconds = time_window.total_seconds()
    
    if window_seconds == 0: # EN: Prevent division by zero | FR: Éviter division par zéro
        return False
        
    # EN: Calculate requests per minute | FR: Calcul requêtes par minute
    request_rate = ip_data['count'] / (
        ip_data['last_seen'] - ip_data['first_seen']
    ).total_seconds() * 60
    
    return request_rate > THREAT_CONFIG['DDoS']['request_threshold']

def calculate_threat_score(data: Dict) -> int:
    """EN: Calculate composite threat score | FR: Calcule score de menace composite"""
    score = 0

    # EN: Add weights for detected threat types | FR: Ajout poids types de menace
    for threat_type, _ in data.get('threats', []):
        score += THREAT_CONFIG[threat_type]['score_weight']

    # EN: Add status code severity scores | FR: Ajout scores sévérité codes statut
    for code, count in data['status_codes'].items():
        score += STATUS_SCORES.get(code, 0) * count

    # EN: SQL injection bonus score | FR: Score bonus injection SQL
    if 'requests' in data and detect_sql_injection(data['requests']):
        score += THREAT_CONFIG['SQL_INJECTION']['score_weight']
        if 'threats' not in data:
            data['threats'] = []
        data['threats'].append(('SQL_INJECTION', 'SQL pattern detected'))

    # EN: DDoS bonus score | FR: Score bonus DDoS
    if detect_ddos(data):
        score += THREAT_CONFIG['DDoS']['score_weight']
        if 'threats' not in data:
            data['threats'] = []
        data['threats'].append(('DDoS', f"{data['count']} req/min"))

    return min(score, 100) # EN: Cap score at 100 | FR: Score maximal 100