import sys
from src.analyzer import SecurityDebtAnalyzer


def format_eur(amount: float) -> str:
    """Formatea una cantidad como euros con separador de miles."""
    return f"{amount:,.0f} €".replace(",", ".")


def cia_label(value: str) -> str:
    """Convierte el valor CIA a un símbolo visual compacto."""
    return {"HIGH": "Alto", "MEDIUM": "Medio", "LOW": "Bajo", "NONE": "—"}.get(value.upper(), "—")


def main():
    if len(sys.argv) < 3:
        print("Error: Faltan argumentos. Uso: python main.py <reporte.json> <contexto.json>.")
        sys.exit(1)

    report_path  = sys.argv[1]
    context_path = sys.argv[2]

    try:
        analyzer = SecurityDebtAnalyzer(report_path, context_path)
        results  = analyzer.analyze()

        print("\n" + "=" * 60)
        print("   RASTREADOR DE DEUDA DE SEGURIDAD")
        print("=" * 60)

        if not results:
            print("No se encontraron vulnerabilidades para analizar.")
            sys.exit(0)

        env_name = analyzer.context_data.get("environment", "Desconocido")
        project  = analyzer.context_data.get("project_name", "Desconocido")

        print(f"  Proyecto   : {project}")
        print(f"  Entorno    : {env_name}")
        print(f"  Total CVEs : {len(results)}")
        print("=" * 60 + "\n")

        for res in results:
            proj = res["cost_projection_eur"]
            cia  = res["cia_impacts"]

            print(f"[{res['severity'].upper()}] {res['id']}  —  paquete: '{res['package']}'")
            print(f"  ↳ Descripcion        : {res['description']}")
            print(f"  ↳ Impacto CIA        : C={cia_label(cia['confidentiality'])}  "
                  f"I={cia_label(cia['integrity'])}  "
                  f"A={cia_label(cia['availability'])}")
            print(f"  ↳ Tasa de interes    : {res['interest_rate']}")
            print(f"  ↳ Prob. ataque futuro: {res['attack_probability']} %")
            print(f"  ↳ Coste base estimado: {format_eur(res['base_cost_eur'])}")
            print(f"  ↳ Proyeccion de perdidas si se ignora:")
            print(f"       En  1 mes  → {format_eur(proj['1m'])}")
            print(f"       En  3 meses→ {format_eur(proj['3m'])}")
            print(f"       En  6 meses→ {format_eur(proj['6m'])}")
            print(f"       En 12 meses→ {format_eur(proj['12m'])}")
            print()

        # ── Resumen ejecutivo ──────────────────────────────────────────────────
        total_12m      = sum(r["cost_projection_eur"]["12m"] for r in results)
        critical_count = sum(1 for r in results if r["severity"] == "Critical")
        high_count     = sum(1 for r in results if r["severity"] == "High")

        print("=" * 60)
        print("  RESUMEN EJECUTIVO")
        print("=" * 60)
        print(f"  Vulnerabilidades criticas : {critical_count}")
        print(f"  Vulnerabilidades altas    : {high_count}")
        print(f"  Perdida total estimada")
        print(f"  si no se actua en 12 meses: {format_eur(total_12m)}")
        print("=" * 60 + "\n")

    except FileNotFoundError as e:
        print(f"Error: No se encontro el archivo. Detalles: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error al procesar el reporte de seguridad: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()