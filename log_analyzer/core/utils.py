import os
import re
from datetime import datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Set, Optional

from .config import Colors, PROJECT_ROOT

# ======================================================================
# IP ADDRESS HANDLING / GESTION DES ADRESSES IP
# ======================================================================

def is_internal_ip(ip_str: str) -> bool:
    """
    EN: Check if IP belongs to private/internal network ranges
    FR: Vérifie si l'IP appartient aux plages réseau privées/internes
    
    Args/Paramètres:
        ip_str: EN: IP address to check | FR: Adresse IP à vérifier
    
    Returns/Retourne:
        bool: EN: True if private IP | FR: True si IP privée
    """
    try:
        ip = ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False

def load_whitelist(file_path: Optional[Path] = None) -> Set[str]:
    """
    EN: Load IP/CIDR whitelist from file
    FR: Charge la liste blanche d'IP/CIDR depuis un fichier
    
    Args/Paramètres:
        file_path: EN: Custom whitelist file path | FR: Chemin personnalisé du fichier
    
    Returns/Retourne:
        Set[str]: EN: Set of whitelisted entries | FR: Ensemble des entrées autorisées
    """
    file_path = file_path or PROJECT_ROOT / 'data' / 'whitelist.txt'
    whitelist = set()
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_number, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    # EN: Validate entry format | FR: Validation du format
                    try:
                        if '/' in line:
                            ip_network(line, strict=False)
                        else:
                            ip_address(line)
                        whitelist.add(line)
                    except ValueError:
                        print(colorize(
                            f"Line  {line_number}: Invalid entry ignored - '{line}'", 
                            Colors.YELLOW
                        ))
    except FileNotFoundError:
        print(colorize(f"⚠️ Whitelist file not found: {file_path}", Colors.YELLOW))
    
    return whitelist

def is_whitelisted(ip_str: str, whitelist: Set[str]) -> bool:
    """
    EN: Check if IP matches any whitelist entry (exact or CIDR range)
    FR: Vérifie si l'IP correspond à une entrée de la liste blanche (exacte ou plage CIDR)
    
    Args/Paramètres:
        ip_str: EN: IP to check | FR: IP à vérifier
        whitelist: EN: Set of allowed IPs/CIDRs | FR: Ensemble d'IPs/CIDRs autorisés
    
    Returns/Retourne:
        bool: EN: True if whitelisted | FR: True si autorisé
    """
    try:
        # EN: Handle potential interface identifiers | FR: Gestion des identifiants d'interface
        clean_ip = ip_str.split('%')[0].split(' ')[0]
        ip = ip_address(clean_ip)
        
        for entry in whitelist:
            try:
                if '/' in entry:
                    # EN: Check CIDR membership | FR: Vérification plage CIDR
                    network = ip_network(entry, strict=False)
                    if ip.version == network.version and ip in network:
                        return True
                else:
                    # EN: Check exact match | FR: Vérification correspondance exacte
                    if ip == ip_address(entry):
                        return True
            except ValueError:
                continue
        return False
    except ValueError:
        return False

# ======================================================================
# OUTPUT FORMATTING / FORMATAGE DE SORTIE
# ======================================================================

def colorize(text: str, color: str) -> str:
    """
    EN: Apply ANSI color codes to terminal text (Windows compatible)
    FR: Applique des codes couleur ANSI au texte terminal (compatible Windows)
    
    Args/Paramètres:
        text: EN: Text to colorize | FR: Texte à colorer
        color: EN: ANSI color code | FR: Code couleur ANSI
    
    Returns/Retourne:
        str: EN: Colored text string | FR: Texte coloré
    """
    return f"{color}{text}{Colors.END}"

# ======================================================================
# INPUT VALIDATION / VALIDATION D'ENTRÉE
# ======================================================================

def validate_ip(ip_str: str) -> bool:
    """
    EN: Validate IP address format
    FR: Valide le format d'une adresse IP
    
    Args/Paramètres:
        ip_str: EN: IP address to validate | FR: IP à valider
    
    Returns/Retourne:
        bool: EN: True if valid IP | FR: True si IP valide
    """
    try:
        ip_address(ip_str)
        return True
    except ValueError:
        return False

def safe_filename(filename: str) -> str:
    """
    EN: Sanitize filename by replacing special characters
    FR: Nettoie un nom de fichier en remplaçant les caractères spéciaux
    
    Args/Paramètres:
        filename: EN: Original filename | FR: Nom de fichier original
    
    Returns/Retourne:
        str: EN: Sanitized filename | FR: Nom de fichier nettoyé
    """
    # EN: Replace non-alphanumeric characters except ._- | FR: Remplace caractères non alphanumériques sauf ._- 
    sanitized = re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)
    # EN: Trim to 255 characters for filesystem safety | FR: Tronque à 255 caractères pour sécurité système
    return sanitized[:255]

# ======================================================================
# ERROR HANDLING / GESTION DES ERREURS
# ======================================================================

def log_error(error: Exception, context: str = "") -> None:
    """
    Log errors with timestamp and context
    Loggue les erreurs avec horodatage et contexte
    
    Args:
        error: Exception object - Objet exception
        context: Error context message - Message de contexte
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    error_msg = f"[{timestamp}] ERROR: {str(error)}"
    if context:
        error_msg += f" | Context: {context}"
    print(colorize(error_msg, Colors.RED))