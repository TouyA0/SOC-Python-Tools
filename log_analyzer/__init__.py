"""SOC Log Analyzer Package"""

# EN: Package metadata | FR: Métadonnées du package
__version__ = "2.0"
__author__ = "TouyA0"

import os
if os.name == 'nt': # EN: Check if Windows | FR: Vérifie si Windows
    from .core.config import Colors
    # EN: Initialize color support for Windows terminals | FR: Initialise le support couleur pour les terminaux Windows
    Colors.init_windows_support() 