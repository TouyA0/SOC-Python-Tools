import csv
import os
from datetime import datetime
from pathlib import Path
from typing import Dict
from jinja2 import Template
from pkg_resources import resource_filename

from .config import Colors, PROJECT_ROOT, DEFAULT_OUTPUT_DIR
from collections import defaultdict

# ======================================================================
# REPORT GENERATION / GÉNÉRATION DE RAPPORTS
# ======================================================================

def generate_reports(suspicious_ips: Dict, base_name: str = 'suspicious_ips') -> None:
    """
    EN: Main report generation workflow
    FR: Flux principal de génération de rapports
    
    Args/Paramètres:
        suspicious_ips: EN: Analyzed IP threat data | FR: Données d'analyse des IP suspectes
        base_name: EN: Base name for output files | FR: Nom de base des fichiers de sortie
    """
    # EN: Ensure output directory exists | FR: Vérifier l'existence du dossier de sortie
    output_dir = DEFAULT_OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # EN: Generate file paths with timestamp | FR: Générer les chemins avec horodatage
    csv_path = output_dir / f"{base_name}.csv"
    html_path = output_dir / f"{base_name}.html"
    
    # EN: Generate both report formats | FR: Générer les deux formats de rapport
    _generate_csv_report(suspicious_ips, csv_path)
    _generate_html_report(suspicious_ips, html_path)
    
    # EN: Print generation confirmation | FR: Afficher la confirmation de génération
    print(colorize(f"📊 Reports generated:", Colors.BLUE))
    print(f"  - CSV: {csv_path}")
    print(f"  - HTML: {html_path}")

def _generate_csv_report(suspicious_ips: Dict, output_path: Path) -> None:
    """
    EN: Generate machine-readable CSV report
    FR: Générer un rapport CSV pour analyse automatique
    
    Args/Paramètres:
        suspicious_ips: EN: Dictionary of IP analysis data | FR: Dictionnaire des données analysées
        output_path: EN: CSV file destination | FR: Destination du fichier CSV
    """
    # EN: CSV column definitions | FR: Définition des colonnes CSV
    fieldnames = [
        'IP Address', 'Threat Score', 'Total Requests',
        'First Seen', 'Last Seen', 'Main Status Code',
        'Most Frequent Request', 'Detected Threats',
        'Status Code Counts', 'Request Counts'
    ]
    
    with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        # EN: Sort IPs by threat score (descending) | FR: Trier les IPs par score (décroissant)
        for ip, data in sorted(
            suspicious_ips.items(),
            key=lambda x: x[1]['threat_score'],
            reverse=True
        ):
            # EN: Extract most frequent status code | FR: Extraire le code statut le plus fréquent
            top_status = max(data['status_codes'].items(), key=lambda x: x[1])
            # EN: Extract most common request | FR: Extraire la requête la plus commune
            top_request = max(data['requests'].items(), key=lambda x: x[1])
            
            # EN: Write formatted CSV line | FR: Écrire ligne CSV formatée
            writer.writerow({
                'IP Address': ip,
                'Threat Score': data['threat_score'],
                'Total Requests': data['count'],
                'First Seen': data['first_seen'].strftime('%Y-%m-%d %H:%M:%S'),
                'Last Seen': data['last_seen'].strftime('%Y-%m-%d %H:%M:%S'),
                'Main Status Code': f"{top_status[0]}({top_status[1]})",
                'Most Frequent Request': f"{top_request[0]}({top_request[1]})",
                'Detected Threats': "; ".join(
                    f"{t[0]}: {t[1]}" for t in data.get('threats', [])
                ),
                'Status Code Counts': ", ".join(
                    f"{k}({v})" for k, v in data['status_codes'].items()
                ),
                'Request Counts': ", ".join(
                    f"{req}({count})" for req, count in 
                    sorted(data['requests'].items(), key=lambda x: x[1], reverse=True)[:5]
                )
            })

def _generate_html_report(suspicious_ips, output_file):
    """
    EN: Generate interactive HTML dashboard with charts
    FR: Générer un tableau de bord HTML interactif avec graphiques
    
    Args/Paramètres:
        suspicious_ips: EN: Dictionary of IP analysis data | FR: Dictionnaire des données analysées
        output_file: EN: HTML file destination | FR: Destination du fichier HTML
    """
    # EN: Initialize threat statistics | FR: Initialiser les statistiques de menace
    critical = high = medium = low = 0
    total_requests = 0
    threat_types_data = defaultdict(int)
    status_codes_data = defaultdict(int)
    
    # EN: Process each IP's data | FR: Traiter les données de chaque IP
    for ip, data in suspicious_ips.items():
        total_requests += data['count']
        
        # EN: Categorize threat level | FR: Catégoriser le niveau de menace
        if data['threat_score'] >= 70:
            critical += 1
        elif data['threat_score'] >= 40:
            high += 1
        elif data['threat_score'] >= 20:
            medium += 1
        else:
            low += 1
        
        # EN: Count detected threat types | FR: Compter les types de menaces
        for threat in data.get('threats', []):
            threat_types_data[threat[0]] += 1
        
        # EN: Aggregate status codes | FR: Agréger les codes statut
        for code, count in data['status_codes'].items():
            status_codes_data[code] += count
    
    # EN: Format data for JavaScript charts | FR: Formater les données pour les graphiques
    threat_types_js = "{" + ", ".join(f"'{k}': {v}" for k, v in threat_types_data.items()) + "}"
    status_codes_js = "{" + ", ".join(f"'{k}': {v}" for k, v in status_codes_data.items()) + "}"
    
    # EN: Load HTML template | FR: Charger le template HTML
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Threat Analysis Dashboard</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/sortablejs@1.14.0/Sortable.min.js"></script>
        <style>
            :root {
                --critical: #e74c3c;
                --high: #f39c12;
                --medium: #f1c40f;
                --low: #2ecc71;
                --bg-color: #f5f7fa;
                --card-bg: #ffffff;
                --text-color: #2c3e50;
                --border-color: #e0e0e0;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 20px;
                background-color: var(--bg-color);
                color: var(--text-color);
            }
            
            .dashboard {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            
            .card {
                background: var(--card-bg);
                border-radius: 8px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
                padding: 20px;
                transition: transform 0.2s;
            }
            
            .card:hover {
                transform: translateY(-5px);
                box-shadow: 0 6px 12px rgba(0, 0, 0, 0.1);
            }
            
            .card-header {
                font-weight: 600;
                font-size: 1.2em;
                margin-bottom: 15px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            
            .chart-container {
                position: relative;
                height: 250px;
                width: 100%;
            }
            
            .ip-card {
                border-left: 4px solid var(--border-color);
                margin-bottom: 15px;
                background: var(--card-bg);
                border-radius: 6px;
                padding: 15px;
                transition: all 0.3s ease;
            }
            
            .ip-card.critical { border-left-color: var(--critical); }
            .ip-card.high { border-left-color: var(--high); }
            .ip-card.medium { border-left-color: var(--medium); }
            .ip-card.low { border-left-color: var(--low); }
            
            .ip-card:hover {
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            }
            
            .ip-header {
                display: flex;
                justify-content: space-between;
                margin-bottom: 10px;
                cursor: pointer;
            }
            
            .ip-address {
                font-weight: bold;
                font-size: 1.1em;
            }
            
            .threat-score {
                font-weight: bold;
                padding: 3px 8px;
                border-radius: 12px;
                font-size: 0.9em;
            }
            
            .critical .threat-score { background-color: var(--critical); color: white; }
            .high .threat-score { background-color: var(--high); color: white; }
            .medium .threat-score { background-color: var(--medium); }
            .low .threat-score { background-color: var(--low); color: white; }
            
            .threat-tag {
                display: inline-block;
                padding: 2px 8px;
                border-radius: 4px;
                font-size: 0.8em;
                margin-right: 5px;
                margin-bottom: 5px;
            }
            
            .threat-brute-force { background-color: #ffdddd; color: #cc0000; }
            .threat-port-scan { background-color: #fff3d6; color: #b37400; }
            .threat-ddos { background-color: #ffcccc; color: #990000; }
            .threat-sql-injection { background-color: #ffd6e0; color: #cc0066; }
            
            .ip-details {
                display: none;
                margin-top: 10px;
            }
            
            .data-grid {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 15px;
                margin-top: 15px;
            }
            
            .data-section h3 {
                font-size: 1em;
                margin-bottom: 10px;
                color: #7f8c8d;
            }
            
            .request-item {
                font-family: monospace;
                font-size: 0.9em;
                margin-bottom: 3px;
                word-break: break-all;
            }
            
            .status-code {
                display: inline-block;
                width: 40px;
                text-align: right;
                margin-right: 10px;
            }
            
            .search-container {
                margin-bottom: 20px;
            }
            
            #search-box {
                width: 100%;
                padding: 10px;
                border: 1px solid var(--border-color);
                border-radius: 4px;
                font-size: 1em;
            }
            
            .summary-bar {
                display: flex;
                justify-content: space-between;
                background: var(--card-bg);
                padding: 15px;
                border-radius: 6px;
                margin-bottom: 20px;
            }
            
            .summary-item {
                text-align: center;
                padding: 0 15px;
            }
            
            .summary-value {
                font-size: 1.5em;
                font-weight: bold;
            }
            
            .summary-label {
                font-size: 0.9em;
                color: #7f8c8d;
            }
            
            .critical-count { color: var(--critical); }
            .high-count { color: var(--high); }
            .medium-count { color: var(--medium); }
            .low-count { color: var(--low); }
            
            @media (max-width: 768px) {
                .dashboard {
                    grid-template-columns: 1fr;
                }
                
                .data-grid {
                    grid-template-columns: 1fr;
                }
            }
        </style>
    </head>
    <body>
        <h1>Threat Analysis Dashboard</h1>
        <div class="summary-bar">
            <div class="summary-item">
                <div class="summary-value">{{ ips|length }}</div>
                <div class="summary-label">Total IPs</div>
            </div>
            <div class="summary-item">
                <div class="summary-value critical-count">{{ critical_count }}</div>
                <div class="summary-label">Critical</div>
            </div>
            <div class="summary-item">
                <div class="summary-value high-count">{{ high_count }}</div>
                <div class="summary-label">High</div>
            </div>
            <div class="summary-item">
                <div class="summary-value medium-count">{{ medium_count }}</div>
                <div class="summary-label">Medium</div>
            </div>
            <div class="summary-item">
                <div class="summary-value low-count">{{ low_count }}</div>
                <div class="summary-label">Low</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">{{ total_requests }}</div>
                <div class="summary-label">Total Requests</div>
            </div>
        </div>
        
        <div class="search-container">
            <input type="text" id="search-box" placeholder="Search IPs or threats...">
        </div>
        
        <div class="dashboard">
            <div class="card">
                <div class="card-header">Threat Level Distribution</div>
                <div class="chart-container">
                    <canvas id="threatLevelChart"></canvas>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">Top Threat Types</div>
                <div class="chart-container">
                    <canvas id="threatTypeChart"></canvas>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">Status Code Distribution</div>
                <div class="chart-container">
                    <canvas id="statusCodeChart"></canvas>
                </div>
            </div>
        </div>
        
        <h2>Suspicious IPs ({{ ips|length }})</h2>
        <div id="ip-list">
            {% for ip, data in ips %}
            <div class="ip-card {% if data.threat_score >= 70 %}critical{% elif data.threat_score >= 40 %}high{% elif data.threat_score >= 20 %}medium{% else %}low{% endif %}" 
                 data-ip="{{ ip }}" 
                 data-score="{{ data.threat_score }}"
                 data-threats="{% for threat in data.threats %}{{ threat[0] }} {% endfor %}">
                <div class="ip-header" onclick="toggleDetails(this)">
                    <div>
                        <span class="ip-address">{{ ip }}</span>
                        <span> - {{ data.count }} requests</span>
                    </div>
                    <span class="threat-score">{{ data.threat_score }}</span>
                </div>
                
                <div class="ip-details">
                    {% if data.threats %}
                    <div class="threat-tags">
                        {% for threat in data.threats %}
                        <span class="threat-tag threat-{{ threat[0]|lower|replace('_','-') }}">
                            {{ threat[0]|replace('_', ' ') }}: {{ threat[1] }}
                        </span>
                        {% endfor %}
                    </div>
                    {% endif %}
                    
                    <div class="data-grid">
                        <div class="data-section">
                            <h3>Status Codes</h3>
                            <div>
                                {% for code, count in data.status_codes|dictsort(false, 'value', reverse=true) %}
                                <div>
                                    <span class="status-code">{{ code }}:</span>
                                    <span>{{ count }} ({{ (count/data.count*100)|round(1) }}%)</span>
                                </div>
                                {% endfor %}
                            </div>
                        </div>
                        
                        <div class="data-section">
                            <h3>Top Requests</h3>
                            <div>
                                {% for req, count in data.requests|dictsort(false, 'value', reverse=true)|batch(5)|first %}
                                <div class="request-item">{{ req }} ({{ count }})</div>
                                {% endfor %}
                                {% if data.requests|length > 5 %}
                                <div>... plus {{ data.requests|length - 5 }} more</div>
                                {% endif %}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>
        
        <script>
            // Search functionality
            document.getElementById('search-box').addEventListener('input', function() {
                const searchTerm = this.value.toLowerCase();
                const ipCards = document.querySelectorAll('.ip-card');
                
                ipCards.forEach(card => {
                    const ip = card.getAttribute('data-ip');
                    const threats = card.getAttribute('data-threats').toLowerCase();
                    
                    if (ip.includes(searchTerm) || threats.includes(searchTerm)) {
                        card.style.display = '';
                    } else {
                        card.style.display = 'none';
                    }
                });
            });
            
            // Toggle IP details
            function toggleDetails(element) {
                const details = element.parentElement.querySelector('.ip-details');
                details.style.display = details.style.display === 'none' ? 'block' : 'none';
            }
            
            // Initialize charts
            document.addEventListener('DOMContentLoaded', function() {
                // Threat Level Chart
                const threatLevelCtx = document.getElementById('threatLevelChart').getContext('2d');
                new Chart(threatLevelCtx, {
                    type: 'doughnut',
                    data: {
                        labels: ['Critical', 'High', 'Medium', 'Low'],
                        datasets: [{
                            data: [{{ critical_count }}, {{ high_count }}, {{ medium_count }}, {{ low_count }}],
                            backgroundColor: [
                                '#e74c3c',
                                '#f39c12',
                                '#f1c40f',
                                '#2ecc71'
                            ],
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom'
                            }
                        }
                    }
                });
                
                // Threat Type Chart
                const threatTypes = {{ threat_types_js }};
                const threatTypeLabels = Object.keys(threatTypes);
                const threatTypeData = Object.values(threatTypes);
                
                const threatTypeCtx = document.getElementById('threatTypeChart').getContext('2d');
                new Chart(threatTypeCtx, {
                    type: 'bar',
                    data: {
                        labels: threatTypeLabels.map(label => label.replace('_', ' ')),
                        datasets: [{
                            label: 'Count',
                            data: threatTypeData,
                            backgroundColor: [
                                '#e74c3c',
                                '#f39c12',
                                '#3498db',
                                '#9b59b6',
                                '#1abc9c'
                            ]
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        },
                        plugins: {
                            legend: {
                                display: false
                            }
                        }
                    }
                });
                
                // Status Code Chart
                const statusCodes = {{ status_codes_js }};
                const statusCodeLabels = Object.keys(statusCodes).sort();
                const statusCodeData = statusCodeLabels.map(code => statusCodes[code]);
                
                const statusCodeCtx = document.getElementById('statusCodeChart').getContext('2d');
                new Chart(statusCodeCtx, {
                    type: 'pie',
                    data: {
                        labels: statusCodeLabels,
                        datasets: [{
                            data: statusCodeData,
                            backgroundColor: [
                                '#3498db',
                                '#e74c3c',
                                '#f39c12',
                                '#2ecc71',
                                '#9b59b6',
                                '#1abc9c',
                                '#34495e'
                            ]
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom'
                            }
                        }
                    }
                });
            });
        </script>
    </body>
    </html>
    """
    
    # EN: Prepare template data | FR: Préparer les données du template
    template = Template(html_template)
    sorted_ips = sorted(suspicious_ips.items(), key=lambda x: x[1]['threat_score'], reverse=True)
    
    # EN: Format timestamps | FR: Formater les horodatages
    for ip, data in sorted_ips:
        data['first_seen'] = data['first_seen'].strftime('%Y-%m-%d %H:%M:%S')
        data['last_seen'] = data['last_seen'].strftime('%Y-%m-%d %H:%M:%S')
    
    # EN: Render final HTML | FR: Générer le HTML final
    html_content = template.render(
        ips=sorted_ips,
        now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        total_requests=total_requests,
        threat_types_js=threat_types_js,
        status_codes_js=status_codes_js
    )
    
    # EN: Write HTML file | FR: Écrire le fichier HTML
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

def colorize(text: str, color: str) -> str:
    """
    EN: Add ANSI color codes to terminal text
    FR: Ajouter des codes couleur ANSI au texte terminal
    
    Args/Paramètres:
        text: EN: Text to colorize | FR: Texte à colorer
        color: EN: ANSI color code | FR: Code couleur ANSI
    """
    return f"{color}{text}{Colors.END}"