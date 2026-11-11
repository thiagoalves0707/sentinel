"""
Peças compartilhadas por todos os scripts do Sentinel.

- Localiza a pasta do "engagement" (o trabalho atual: escopo, log, achados).
- Decide se um alvo está DENTRO do escopo autorizado (o coração da skill).
- Registra cada ação no log de atividades.
- Cores no terminal e severidades.

Só biblioteca padrão do Python (3.9+), pra rodar em Kali, Windows, Mac ou container.
"""
from __future__ import annotations

import datetime as dt
import fnmatch
import ipaddress
import json
import os
import socket
import sys
from pathlib import Path
from urllib.parse import urlsplit

# Windows: garante que acentos e símbolos saiam certos no terminal.
for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

VERSION = "1.0.0"
USER_AGENT = f"Sentinel/{VERSION} (auditoria de seguranca autorizada)"

# ──────────────────────────────────────────────────────────────────────────────
# Cores (desligam sozinhas quando a saída não é um terminal ou com NO_COLOR)
# ──────────────────────────────────────────────────────────────────────────────
_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def red(t: str) -> str: return c(t, "31")
def green(t: str) -> str: return c(t, "32")
def yellow(t: str) -> str: return c(t, "33")
def dim(t: str) -> str: return c(t, "2")
def bold(t: str) -> str: return c(t, "1")


def die(msg: str, code: int = 1) -> None:
    print(red(f"✖ {msg}"), file=sys.stderr)
    sys.exit(code)


# ──────────────────────────────────────────────────────────────────────────────
# Severidade
# ──────────────────────────────────────────────────────────────────────────────
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_PT = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Média",
    "low": "Baixa",
    "info": "Informativa",
}


def sev_color(sev: str, text: str | None = None) -> str:
    text = text or SEVERITY_PT.get(sev, sev)
    return {
        "critical": lambda t: c(t, "1;97;41"),
        "high": red,
        "medium": yellow,
        "low": lambda t: c(t, "36"),
    }.get(sev, dim)(text)


# ──────────────────────────────────────────────────────────────────────────────
# Engagement: pasta com scope.json, log.jsonl, findings.json, evidence/, recon/
# ──────────────────────────────────────────────────────────────────────────────
def engagement_dir(explicit: str | None = None) -> Path:
    """Ordem: --dir  →  $SENTINEL_DIR  →  ./engagement"""
    return Path(explicit or os.environ.get("SENTINEL_DIR") or "engagement").resolve()


def load_scope(eng: Path, required: bool = True) -> dict | None:
    f = eng / "scope.json"
    if not f.exists():
        if required:
            die(
                f"nenhum escopo em {f}.\n"
                "  Crie um antes de qualquer ação ativa:\n"
                "  python scripts/scope.py init --name \"...\" --mode ctf --in 10.10.10.5 "
                "--auth \"quem autorizou\""
            )
        return None
    return json.loads(f.read_text(encoding="utf-8"))


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def log_action(eng: Path, action: str, target: str = "", tool: str = "", note: str = "",
               result: str = "") -> None:
    """Uma linha JSON por ação. Vira o apêndice "Registro de atividades" do relatório."""
    eng.mkdir(parents=True, exist_ok=True)
    entry = {"ts": now_iso(), "action": action, "target": target, "tool": tool,
             "note": note, "result": result}
    with (eng / "log.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def read_log(eng: Path) -> list[dict]:
    f = eng / "log.jsonl"
    if not f.exists():
        return []
    out = []
    for line in f.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Escopo: um alvo está autorizado?
#
# Formatos aceitos nas listas in_scope / out_of_scope:
#   10.10.10.5            IP único
#   10.10.10.0/24         rede CIDR (IPv4 ou IPv6)
#   10.10.10.10-10.10.10.50   faixa de IPs
#   app.exemplo.com       domínio exato
#   *.exemplo.com         qualquer subdomínio (não inclui o próprio exemplo.com)
#   https://app.exemplo.com/api   URL (vale o host)
#
# Regra de ouro: out_of_scope SEMPRE vence. Na dúvida, fora do escopo.
# ──────────────────────────────────────────────────────────────────────────────
def normalize_target(target: str) -> str:
    """URL, host:porta ou [ipv6]:porta → só o host/IP, em minúsculas."""
    t = target.strip()
    if "://" in t:
        t = urlsplit(t).hostname or ""
    elif t.startswith("[") and "]" in t:          # [::1]:8080
        t = t[1:t.index("]")]
    elif t.count(":") == 1:                        # host:porta (IPv6 tem vários ':')
        t = t.split(":")[0]
    return t.strip().rstrip(".").lower()


def _as_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _entry_matches(entry: str, host: str, exclusion: bool = False) -> bool:
    """exclusion=True: um domínio proibido também proíbe todos os subdomínios dele."""
    entry = entry.strip()
    if not entry:
        return False
    ip = _as_ip(host)
    # Faixa a-b
    if "-" in entry and all(_as_ip(p.strip()) for p in entry.split("-", 1)):
        lo, hi = (ipaddress.ip_address(p.strip()) for p in entry.split("-", 1))
        return ip is not None and ip.version == lo.version and lo <= ip <= hi
    # CIDR
    if "/" in entry and "://" not in entry:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            return ip is not None and ip.version == net.version and ip in net
        except ValueError:
            pass
    norm = normalize_target(entry)
    if _as_ip(norm):
        return ip is not None and ip == ipaddress.ip_address(norm)
    if ip is not None:
        return False
    if norm.startswith("*."):
        return fnmatch.fnmatch(host, norm) and host != norm[2:]
    return host == norm or (exclusion and host.endswith("." + norm))


def check_target(scope: dict, target: str, resolve: bool = False) -> tuple[bool, str]:
    """Retorna (autorizado, motivo). Com resolve=True, também confere os IPs do domínio."""
    host = normalize_target(target)
    if not host:
        return False, "alvo vazio/inválido"

    # Janela de tempo autorizada
    win = scope.get("window") or {}
    today = dt.date.today().isoformat()
    if win.get("start") and today < win["start"]:
        return False, f"fora da janela autorizada (começa em {win['start']})"
    if win.get("end") and today > win["end"]:
        return False, f"fora da janela autorizada (terminou em {win['end']})"

    for e in scope.get("out_of_scope", []):
        if _entry_matches(e, host, exclusion=True):
            return False, f"explicitamente FORA do escopo ({e})"

    match = next((e for e in scope.get("in_scope", []) if _entry_matches(e, host)), None)
    if not match and not (resolve and _as_ip(host) is None):
        return False, "não está na lista de escopo"

    if resolve and _as_ip(host) is None:
        try:
            ips = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
        except socket.gaierror:
            return False, "domínio não resolve (DNS)" if match else "não está na lista de escopo"
        for addr in ips:
            for e in scope.get("out_of_scope", []):
                if _entry_matches(e, addr, exclusion=True):
                    return False, f"{host} resolve para {addr}, que está FORA do escopo ({e})"
        if not match:
            # Caso típico de CTF: "lame.htb" no /etc/hosts apontando pro IP autorizado.
            # Só vale se TODOS os IPs do nome estiverem no escopo.
            in_ips = [x for x in ips if any(_entry_matches(e, x) for e in scope.get("in_scope", []))]
            if ips and len(in_ips) == len(ips):
                return True, f"{host} resolve para {', '.join(ips)}, dentro do escopo"
            return False, "não está na lista de escopo"
        return True, f"dentro do escopo ({match}); resolve para {', '.join(ips)}"

    return True, f"dentro do escopo ({match})"


def load_findings(eng: Path) -> list[dict]:
    f = eng / "findings.json"
    return json.loads(f.read_text(encoding="utf-8")) if f.exists() else []


def save_findings(eng: Path, findings: list[dict]) -> None:
    (eng / "findings.json").write_text(json.dumps(findings, indent=2, ensure_ascii=False) + "\n",
                                       encoding="utf-8")


def add_finding(eng: Path, finding: dict) -> tuple[dict, bool]:
    """Adiciona um achado com ID sequencial (SNT-001…). Ignora duplicata de mesmo título+alvo.
    Retorna (achado, foi_criado)."""
    findings = load_findings(eng)
    for f in findings:
        if f.get("title") == finding.get("title") and f.get("target") == finding.get("target"):
            return f, False
    finding = {
        "id": f"SNT-{len(findings) + 1:03d}",
        "status": "confirmado",
        "found_at": now_iso(),
        **finding,
    }
    if finding.get("severity") not in SEVERITIES:
        finding["severity"] = "info"
    findings.append(finding)
    save_findings(eng, findings)
    return finding, True


def require_in_scope(eng: Path, target: str, tool: str) -> dict:
    """Trava usada pelos scripts ativos: aborta se o alvo não estiver autorizado."""
    scope = load_scope(eng)
    ok, why = check_target(scope, target, resolve=True)
    if not ok:
        log_action(eng, "bloqueado", target, tool, why, "fora do escopo")
        die(f"{target}: {why}. Nada foi enviado ao alvo.", 2)
    return scope
