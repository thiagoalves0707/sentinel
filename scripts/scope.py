#!/usr/bin/env python3
"""
scope.py — o portão de autorização do Sentinel.

Todo trabalho começa aqui. Sem escopo, os scripts ativos se recusam a rodar.

  init    cria o engagement (scope.json + pastas) com o que foi autorizado
  check   diz se um ou mais alvos estão DENTRO do escopo  (exit 0 = todos ok, 2 = algum fora)
  show    mostra o escopo atual
  log     registra uma ação manual (ex.: um nmap que o Claude rodou) no log de atividades

Exemplos:
  python scripts/scope.py init --name "HTB - Lame" --mode ctf --in 10.10.10.3 \
      --auth "Plataforma Hack The Box (laboratório)"
  python scripts/scope.py init --name "Pentest ACME" --mode pentest \
      --in "*.acme.com" --in 203.0.113.0/28 --out admin.acme.com \
      --auth "Contrato 42/2026 assinado por Fulana (CISO)" --start 2026-11-10 --end 2026-11-21
  python scripts/scope.py check 10.10.10.3 https://app.acme.com/login
  python scripts/scope.py log "nmap -sV -T3 10.10.10.3" --target 10.10.10.3 --tool nmap
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (bold, check_target, die, dim, engagement_dir, green, load_scope,  # noqa: E402
                     log_action, now_iso, red, yellow)

MODES = {
    "ctf": "CTF / laboratório (HTB, TryHackMe, VulnHub, máquina própria)",
    "pentest": "Pentest autorizado por contrato/termo",
    "bugbounty": "Bug bounty (regras do programa valem como escopo)",
    "blue": "Defesa / auditoria do próprio ambiente",
    "own": "Sistema próprio (seu site, seu servidor, seu código)",
}


def cmd_init(a: argparse.Namespace) -> None:
    eng = engagement_dir(a.dir)
    f = eng / "scope.json"
    if f.exists() and not a.force:
        die(f"já existe um escopo em {f}. Use --force para sobrescrever.")
    if not a.in_scope:
        die("informe ao menos um alvo com --in")
    if not a.auth:
        die("informe quem autorizou com --auth (ex.: \"contrato X\", \"lab HTB\", \"meu próprio servidor\")")

    scope = {
        "name": a.name,
        "client": a.client or "",
        "mode": a.mode,
        "authorization": {"statement": a.auth, "recorded_at": now_iso()},
        "window": {"start": a.start or "", "end": a.end or ""},
        "in_scope": a.in_scope,
        "out_of_scope": a.out_scope or [],
        "rules": {
            "dos": False,                    # nada de negação de serviço
            "destructive": False,            # nada de apagar/alterar dados
            "social_engineering": False,
            "max_requests_per_second": a.max_rps,
            "notes": a.rules or "",
        },
        "tester": a.tester or "",
    }
    for sub in ("evidence", "recon", "loot"):
        (eng / sub).mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(scope, indent=2, ensure_ascii=False), encoding="utf-8")
    if not (eng / "findings.json").exists():
        (eng / "findings.json").write_text("[]\n", encoding="utf-8")
    # loot/ guarda credenciais e dados sensíveis encontrados: nunca versionar.
    (eng / ".gitignore").write_text("loot/\n*.pcap\n", encoding="utf-8")
    log_action(eng, "escopo criado", ", ".join(a.in_scope), "scope.py", a.auth)
    print(green(f"✔ engagement criado em {eng}"))
    show(scope)


def show(scope: dict) -> None:
    print(bold(f"\n  {scope['name']}") + dim(f"  [{scope['mode']}] {MODES.get(scope['mode'], '')}"))
    print(f"  Autorização: {scope['authorization']['statement']}")
    w = scope.get("window") or {}
    if w.get("start") or w.get("end"):
        print(f"  Janela:      {w.get('start') or '…'} → {w.get('end') or '…'}")
    print(green("  Dentro:      ") + ", ".join(scope["in_scope"]))
    if scope.get("out_of_scope"):
        print(red("  Fora:        ") + ", ".join(scope["out_of_scope"]))
    r = scope.get("rules", {})
    print(dim(f"  Regras:      sem DoS · sem ações destrutivas · máx {r.get('max_requests_per_second')} req/s"
              + (f" · {r['notes']}" if r.get("notes") else "")))
    print()


def cmd_show(a: argparse.Namespace) -> None:
    show(load_scope(engagement_dir(a.dir)))


def cmd_check(a: argparse.Namespace) -> None:
    eng = engagement_dir(a.dir)
    scope = load_scope(eng)
    all_ok = True
    for t in a.targets:
        ok, why = check_target(scope, t, resolve=a.resolve)
        all_ok &= ok
        print((green("✔ DENTRO ") if ok else red("✖ FORA   ")) + f"{t}  " + dim(why))
    if not all_ok:
        print(yellow("\nNão execute nada contra alvos FORA do escopo. Peça ao usuário para ampliar o escopo, se for o caso."))
    sys.exit(0 if all_ok else 2)


def cmd_log(a: argparse.Namespace) -> None:
    eng = engagement_dir(a.dir)
    load_scope(eng)
    log_action(eng, a.action, a.target or "", a.tool or "", a.note or "", a.result or "")
    print(green("✔ registrado"))


def main() -> None:
    p = argparse.ArgumentParser(description="Portão de autorização e escopo do Sentinel.")
    p.add_argument("--dir", help="pasta do engagement (padrão: ./engagement ou $SENTINEL_DIR)")
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("init", help="cria o engagement")
    i.add_argument("--name", required=True)
    i.add_argument("--mode", choices=MODES, required=True)
    i.add_argument("--in", dest="in_scope", action="append", help="alvo autorizado (repita)")
    i.add_argument("--out", dest="out_scope", action="append", help="alvo proibido (repita)")
    i.add_argument("--auth", help="declaração de autorização: quem, como, referência")
    i.add_argument("--client")
    i.add_argument("--tester")
    i.add_argument("--start", help="AAAA-MM-DD")
    i.add_argument("--end", help="AAAA-MM-DD")
    i.add_argument("--max-rps", type=int, default=10)
    i.add_argument("--rules", help="regras extras de engajamento")
    i.add_argument("--force", action="store_true")
    i.set_defaults(fn=cmd_init)

    c = sub.add_parser("check", help="confere se alvos estão no escopo")
    c.add_argument("targets", nargs="+")
    c.add_argument("--resolve", action="store_true", help="resolve DNS e confere os IPs também")
    c.set_defaults(fn=cmd_check)

    s = sub.add_parser("show", help="mostra o escopo")
    s.set_defaults(fn=cmd_show)

    lg = sub.add_parser("log", help="registra uma ação no log de atividades")
    lg.add_argument("action", help="o que foi feito (ex.: o comando executado)")
    lg.add_argument("--target")
    lg.add_argument("--tool")
    lg.add_argument("--note")
    lg.add_argument("--result")
    lg.set_defaults(fn=cmd_log)

    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
