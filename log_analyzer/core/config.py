import os
from pathlib import Path

# ======================================================================
# THREAT DETECTION CONFIGURATION / CONFIGURATION DE DÉTECTION DE MENACES
# ======================================================================

# EN: Threat detection rules with scoring weights
# FR: Règles de détection de menaces avec pondération des scores
THREAT_CONFIG = {
    'BRUTE_FORCE': {
        'status_codes': ['401', '403'], # EN: Suspicious response codes | FR: Codes de réponse suspects
        'paths': ['/login', '/wp-login.php', '/admin'], # EN: Targeted endpoints | FR: Points de terminaison ciblés
        'threshold': 10, # EN: Minimum requests to trigger alert | FR: Requêtes minimum pour alerter
        'score_weight': 15 # EN: Score impact per detection | FR: Impact sur le score par détection
    },
    'PORT_SCAN': {
        'status_codes': ['404', '400'],
        'request_threshold': 50,
        'unique_paths_threshold': 20,
        'score_weight': 10
    },
    'SUSPICIOUS_UA': {
        'user_agents': ['sqlmap', 'nikto', 'metasploit', 'hydra'],
        'threshold': 1,
        'score_weight': 20
    },
    'SQL_INJECTION': {
        'patterns': [r'UNION.*SELECT', r'SELECT.*FROM', r'1=1', r'DROP TABLE'],
        'score_weight': 30
    },
    'DDoS': {
        'request_threshold': 500,
        'score_weight': 40
    }
}

# EN: Severity scoring for HTTP status codes
# FR: Score de sévérité pour codes statut HTTP
STATUS_SCORES = {
    '403': 3,  # Forbidden/Interdit
    '401': 2,  # Unauthorized/Non autorisé
    '404': 1,  # Not Found/Introuvable
    '400': 1   # Bad Request/Mauvaise requête
}

# ======================================================================
# PATHS CONFIGURATION / CONFIGURATION DES CHEMINS
# ======================================================================

# EN: Base project directory and key file paths
# FR: Répertoire du projet et chemins des fichiers clés
PROJECT_ROOT = Path(__file__).parent.parent.parent
WHITELIST_FILE = PROJECT_ROOT / 'data' / 'whitelist.txt' # EN: Approved IP list | FR: Liste d'IP approuvées
DEFAULT_SAMPLE_LOG = PROJECT_ROOT / 'data' / 'sample.log' # EN: Test log file | FR: Fichier log de test

# ======================================================================
# RUNTIME CONSTANTS / CONSTANTES D'EXÉCUTION
# ======================================================================

MIN_ANALYSIS_INTERVAL = 5  # EN: Seconds between analyses (watch mode) | FR: Secondes entre analyses (mode surveillance)
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / 'outputs' # EN: Default report location | FR: Emplacement par défaut des rapports

# ======================================================================
# COLOR CONFIGURATION / CONFIGURATION DES COULEURS
# ======================================================================

class Colors:
    # EN: Color code constants | FR: Constantes de codes couleur
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    ORANGE = '\033[33m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

    # EN: Platform-specific initialization | FR: Initialisation spécifique par plateforme
    @classmethod
    def init_windows_support(cls):
        # EN: Enable color support for Windows | FR: Activer le support couleur pour Windows
        if os.name == 'nt':
            try:
                import colorama
                colorama.init() # EN: Windows color emulation | FR: Émulation couleur pour Windows
            except ImportError:
                cls.disable_colors() # EN: Fallback to no colors | FR: Désactiver les couleurs

    @classmethod
    def disable_colors(cls):
        # EN: Disable all color codes | FR: Désactiver tous les codes couleur
        for attr in dir(cls):
            if attr.isupper() and attr != 'END':
                setattr(cls, attr, '')