import json
import math
from typing import List, Dict, Any

# Horizontes de proyección en meses
PROJECTION_MONTHS = [1, 3, 6, 12]
 
# Mapeo de los valores cualitativos del CVSS al peso numérico CIA
CIA_IMPACT_WEIGHTS = {
    "HIGH":   1.0,
    "MEDIUM": 0.5,
    "LOW":    0.1,
    "NONE":   0.0,
}

class SecurityDebtAnalyzer:
    def __init__(self, report_path: str, context_path: str):
        """
        Inicializa el analizador cargando las rutas de los archivos.
        
        Args:
            report_path (str): Ruta al archivo JSON con el reporte de vulnerabilidades (Grype).
            context_path (str): Ruta al archivo JSON con el contexto de negocio y variables del entorno.
        """
        self.report_path = report_path
        self.context_path = context_path
        self.context_data = self.load_context()

    def load_report(self) -> Dict[str, Any]:
        """
        Lee y parsea el archivo JSON que contiene los hallazgos de seguridad.
        
        Returns:
            Dict[str, Any]: Diccionario con la estructura del reporte de vulnerabilidades.
        """
        with open(self.report_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def load_context(self) -> Dict[str, Any]:
        """
        Lee y parsea el archivo JSON que contiene el contexto de negocio
        (valor de los activos, exposición del entorno, etc.).
        
        Returns:
            Dict[str, Any]: Diccionario con las variables de negocio y entorno.
        """
        with open(self.context_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def compute_base_cost(self, cia_impacts: Dict[str, str]) -> float:
        """
        Calcula el coste base cruzando los pesos CIA del CVE
        con el valor del activo definido en el contexto.
 
        coste_base = Σ (peso_CIA_cvss × valor_CIA_activo)
 
        Si el contexto define asset_value_eur como escalar,
        se reparte en tercios iguales entre C, I y A. Sino
        obtiene los valores de cada uno

        Args:
            cia_impacts (Dict[str, str]): Diccionario con los niveles de impacto ("HIGH", "NONE", etc.) para C, I y A.

        Returns:
            float: El coste financiero base estimado para la vulnerabilidad.

        """
        asset_value = self.context_data.get("asset_value_eur", 100_000)
 
        if isinstance(asset_value, (int, float)):
            cia_values = {
                "confidentiality": asset_value / 3,
                "integrity":       asset_value / 3,
                "availability":    asset_value / 3,
            }
        else:
            cia_values = {
                "confidentiality": float(asset_value.get("confidentiality", 0)),
                "integrity":       float(asset_value.get("integrity",       0)),
                "availability":    float(asset_value.get("availability",    0)),
            }
 
        c_weight = CIA_IMPACT_WEIGHTS.get(cia_impacts.get("confidentiality", "NONE").upper(), 0.0)
        i_weight = CIA_IMPACT_WEIGHTS.get(cia_impacts.get("integrity",       "NONE").upper(), 0.0)
        a_weight = CIA_IMPACT_WEIGHTS.get(cia_impacts.get("availability",    "NONE").upper(), 0.0)
 
        return (
            c_weight * cia_values["confidentiality"] +
            i_weight * cia_values["integrity"]       +
            a_weight * cia_values["availability"]
        )

    def project_cost(self, base_cost: float, interest_rate: float, months: int) -> float:
        """
        Proyección con interés compuesto continuo:
            C(t) = C_base × e^(r × t)
        La tasa se normaliza a escala mensual.
        """
        r = interest_rate / 12.0
        return base_cost * math.exp(r * months)


    def analyze(self) -> List[Dict[str, Any]]:
        """
        Método principal que orquesta el análisis. 
        Itera sobre todas las vulnerabilidades detectadas, extrae sus métricas (CVSS, EPSS), 
        calcula la deuda de seguridad (intereses y probabilidad) y proyecta las pérdidas.

        Returns:
            List[Dict[str, Any]]: Lista de diccionarios, donde cada diccionario representa 
                                  una vulnerabilidad analizada y enriquecida con datos financieros, 
                                  ordenada de mayor a menor tasa de interés.
        """
        data     = self.load_report()
        results  = []
        exposure = float(self.context_data.get("exposure_factor", 0.5))
 
        for match in data.get('matches', []):
            vuln     = match.get('vulnerability', {})
            artifact = match.get('artifact', {})
 
            vuln_id     = vuln.get('id', 'Desconocido')
            description = vuln.get('description', 'Descripción no disponible')
            pkg_name    = artifact.get('name', 'Paquete Desconocido')
            severity    = vuln.get('severity', 'Low')
 
            # ── CVSS ──────────────────────────────────────────────────────────
            cvss_score     = 0.0
            cia_impacts    = {"confidentiality": "NONE", "integrity": "NONE", "availability": "NONE"}
            cvss_data      = vuln.get('cvss', [])
 
            if cvss_data:
                metrics        = cvss_data[0].get('metrics', {})
                cvss_score     = metrics.get('baseScore', 0.0)
 
                # Extraemos los impactos CIA del vector CVSS
                vector_string = cvss_data[0].get('vector', '')
                cia_impacts   = self._parse_cia_from_vector(vector_string, metrics)
 
            if cvss_score == 0.0:
                cvss_score = {
                    "Critical": 9.5, "High": 7.5,
                    "Medium":   5.5, "Low":  2.5
                }.get(severity, 0.0)
 
 
            # ── Tasa de interés ────────────────────────────────────────────────
            interest_rate = cvss_score * exposure
 
            # ── EPSS → probabilidad de ataque ─────────────────────────────────
            epss_score = 0.0
            epss_data  = vuln.get('epss', [])
            if epss_data:
                epss_score = epss_data[0].get('epss', 0.0)
 
            attack_probability_percent = epss_score * 100
 
            # ── Coste base CIA + proyección ajustada a la realidad ─────────────────
            base_cost   = self.compute_base_cost(cia_impacts)
            
            # Normalizamos la probabilidad (0.022% -> 0.00022)
            # Si es 0 (porque no hay EPSS), asumimos un 1% (0.01) para que no dé cero
            prob_factor = epss_score if epss_score > 0 else 0.01

            projections = {
                # Dividimos el interés entre 100 para que actúe como un % real
                # Y multiplicamos por la probabilidad real de que el ataque ocurra (prob_factor)
                f"{m}m": round(self.project_cost(base_cost, interest_rate / 100, m) * prob_factor)
                for m in PROJECTION_MONTHS
            }
 
            results.append({
                "id":                  vuln_id,
                "description":         description,
                "package":             pkg_name,
                "severity":            severity,
                "interest_rate":       round(interest_rate, 2),
                "attack_probability":  round(attack_probability_percent, 4),
                "cia_impacts":         cia_impacts,
                "base_cost_eur":       round(base_cost),
                "cost_projection_eur": projections,
            })
 
        return sorted(results, key=lambda x: x['interest_rate'], reverse=True)

    # ── Helpers ───────────────────────────────────────────────────────────────
 
    def _parse_cia_from_vector(
        self, vector: str, metrics: Dict[str, Any]) -> Dict[str, str]:
        """
        Intenta extraer C/I/A del vector CVSS.
        Soporta CVSS v3.x (C, I, A) y CVSS v4.0 (VC, VI, VA).
        Si no está disponible, cae en los campos individuales del objeto metrics.
        """
        cia = {"confidentiality": "NONE", "integrity": "NONE", "availability": "NONE"}
        if vector:
            parts = {p.split(':')[0]: p.split(':')[1] for p in vector.split('/') if ':' in p}
            expand = {"H": "HIGH", "M": "MEDIUM", "L": "LOW", "N": "NONE"}

            # Buscamos la métrica CVSS3 ("C"). Si no existe, buscamos la de CVSS4 ("VC"). 
            # Si tampoco, asignamos "N" (NONE).
            conf_val  = parts.get("C", parts.get("VC", "N"))
            int_val   = parts.get("I", parts.get("VI", "N"))
            avail_val = parts.get("A", parts.get("VA", "N"))
            cia["confidentiality"] = expand.get(conf_val,  "NONE")
            cia["integrity"]       = expand.get(int_val,   "NONE")
            cia["availability"]    = expand.get(avail_val, "NONE")
        else:
            # Fallback a campos explícitos si los hay
            cia["confidentiality"] = metrics.get("confidentialityImpact", "NONE")
            cia["integrity"]       = metrics.get("integrityImpact",       "NONE")
            cia["availability"]    = metrics.get("availabilityImpact",    "NONE")
        return cia