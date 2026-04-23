import sys
from src.analyzer import SecurityDebtAnalyzer

def main():
    if len(sys.argv) < 3:
        print("Error: Faltan argumentos. Uso: python main.py <reporte.json> <contexto.json>.")
        sys.exit(1)
        
    report_path = sys.argv[1]
    context_path = sys.argv[2]

    try:
        analyzer = SecurityDebtAnalyzer(report_path, context_path)
        results = analyzer.analyze()

        print("\n" + "="*50)
        print("Rastreador de deuda de seguridad")
        print("="*50)
        
        if not results:
            print("No se encontraron vulnerabilidades para analizar.")
            sys.exit(0)

        print(f"Se han procesado {len(results)} vulnerabilidades, ordenadas por deuda:\n")

        for res in results:
            alert_text = "[CRÍTICO]" if res['interest_rate'] > 20 else "[WARNING]"
            
            print(f"{alert_text} [{res['severity'].upper()}] {res['id']} detectado en el paquete '{res['package']}'")
            print(f"    ↳ Descripción: {res['description']} ({res['id']})")
            print(f"    ↳ Tasa de interés: {res['interest_rate']}")
            print(f"    ↳ Probabilidad de ataque futuro:   {res['attack_probability']} %\n")
            

    except FileNotFoundError as e:
        print(f"Error: No se encontró el archivo. Detalles: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error al procesar el reporte de seguridad: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()