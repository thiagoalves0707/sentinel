#!/usr/bin/env python3
"""
cvss.py — calculadora CVSS v3.1 (nota base), seguindo a especificação oficial do FIRST.

  python scripts/cvss.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  → 9.8 Crítica

Também é importado pelo report.py para dar nota aos achados.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import SEVERITY_PT, sev_color  # noqa: E402

# Pesos da especificação CVSS v3.1 (seção 7.4)
W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}   # privilégio pesa menos quando o escopo muda

REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

LABELS = {
    "AV": ("Vetor de ataque", {"N": "Rede", "A": "Rede adjacente", "L": "Local", "P": "Físico"}),
    "AC": ("Complexidade", {"L": "Baixa", "H": "Alta"}),
    "PR": ("Privilégios exigidos", {"N": "Nenhum", "L": "Baixos", "H": "Altos"}),
    "UI": ("Interação do usuário", {"N": "Nenhuma", "R": "Necessária"}),
    "S": ("Escopo", {"U": "Inalterado", "C": "Alterado"}),
    "C": ("Confidencialidade", {"H": "Alta", "L": "Baixa", "N": "Nenhuma"}),
    "I": ("Integridade", {"H": "Alta", "L": "Baixa", "N": "Nenhuma"}),
    "A": ("Disponibilidade", {"H": "Alta", "L": "Baixa", "N": "Nenhuma"}),
}


def roundup(x: float) -> float:
    """Arredondamento para cima com 1 casa, à prova de erro de ponto flutuante (Apêndice A)."""
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def parse(vector: str) -> dict[str, str]:
    parts = vector.strip().split("/")
    if parts and parts[0].upper().startswith("CVSS:"):
        if parts[0] not in ("CVSS:3.1", "CVSS:3.0"):
            raise ValueError(f"versão não suportada: {parts[0]} (use CVSS:3.1)")
        parts = parts[1:]
    m: dict[str, str] = {}
    for p in parts:
        if ":" not in p:
            raise ValueError(f"métrica inválida: {p!r}")
        k, v = p.split(":", 1)
        m[k.upper()] = v.upper()
    missing = [k for k in REQUIRED if k not in m]
    if missing:
        raise ValueError(f"faltam métricas: {', '.join(missing)}")
    for k in REQUIRED:
        if m[k] not in LABELS[k][1]:
            raise ValueError(f"valor inválido {k}:{m[k]}")
    return m


def score(vector: str) -> float:
    m = parse(vector)
    changed = m["S"] == "C"
    iss = 1 - (1 - W["CIA"][m["C"]]) * (1 - W["CIA"][m["I"]]) * (1 - W["CIA"][m["A"]])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    pr = (PR_CHANGED if changed else PR_UNCHANGED)[m["PR"]]
    exploitability = 8.22 * W["AV"][m["AV"]] * W["AC"][m["AC"]] * pr * W["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    base = (impact + exploitability) * (1.08 if changed else 1)
    return roundup(min(base, 10))


def severity(s: float) -> str:
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return "info"


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)
    vec = sys.argv[1]
    try:
        m = parse(vec)
        s = score(vec)
    except ValueError as e:
        print(f"✖ {e}", file=sys.stderr)
        sys.exit(1)
    sev = severity(s)
    print(sev_color(sev, f" {s:.1f} {SEVERITY_PT[sev]} "))
    for k in REQUIRED:
        name, values = LABELS[k]
        print(f"  {name:<22} {values[m[k]]}")


if __name__ == "__main__":
    main()
