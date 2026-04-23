import json
from typing import List, Dict, Any

class SecurityDebtAnalyzer:
    def __init__(self, report_path: str, context_path: str):
        self.report_path = report_path
        self.context_path = context_path
        self.context_data = self.load_context()

    def load_report(self) -> Dict[str, Any]:
        with open(self.report_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def load_context(self) -> Dict[str, Any]:
        with open(self.context_path, 'r', encoding='utf-8') as f:
            return json.load(f)


    def analyze(self) -> List[Dict[str, Any]]:
        data = self.load_report()
        results = []

        exposure = float(self.context_data.get("exposure_factor", 0.5))

        for match in data.get('matches', []):
            vuln = match.get('vulnerability', {})
            artifact = match.get('artifact', {})

            vuln_id = vuln.get('id', 'Desconocido')
            description = vuln.get('description', 'Descripción no disponible')
            pkg_name = artifact.get('name', 'Paquete Desconocido')
            severity = vuln.get('severity', 'Low')

            cvss_score = 0.0
            exploitability = 0.0
            cvss_data = vuln.get('cvss', [])
            
            if cvss_data and len(cvss_data) > 0:
                metrics = cvss_data[0].get('metrics', {})
                cvss_score = metrics.get('baseScore', 0.0)
                exploitability = metrics.get('exploitabilityScore', 0.0)
            
            if cvss_score == 0.0:
                cvss_score = {"Critical": 9.5, "High": 7.5, "Medium": 5.5, "Low": 2.5}.get(severity, 0.0)
                exploitability = 1.0 

            if exploitability == 0.0:
                exploitability = 1.0

            interest_rate = cvss_score * exploitability * exposure

            epss_score = 0.0
            epss_data = vuln.get('epss', [])
            if epss_data and len(epss_data) > 0:
                epss_score = epss_data[0].get('epss', 0.0)
            
            attack_probability_percent = epss_score * 100

            results.append({
                "id": vuln_id,
                "description": description,
                "package": pkg_name,
                "severity": severity,
                "interest_rate": round(interest_rate, 2),
                "attack_probability": round(attack_probability_percent, 4)
            })

        return sorted(results, key=lambda x: x['interest_rate'], reverse=True)