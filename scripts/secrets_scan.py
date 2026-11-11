#!/usr/bin/env python3
"""
secrets_scan.py — caça senhas, tokens e chaves esquecidos em código (e no histórico do git).

Defensivo: roda na SUA pasta/repositório, antes de publicar. Os valores encontrados
aparecem MASCARADOS na tela (ex.: ghp_Ab12…••••), nunca inteiros.

  python scripts/secrets_scan.py .                 # pasta atual
  python scripts/secrets_scan.py ~/meu-projeto --git   # + todo o histórico de commits
  python scripts/secrets_scan.py . --json saida.json

Sai com código 1 se achar algo — dá pra usar em CI pra barrar o push.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import SEVERITY_PT, bold, dim, green, red, sev_color, yellow  # noqa: E402

# (nome, regex, severidade). O grupo 1, se houver, é o segredo em si.
RULES: list[tuple[str, re.Pattern, str]] = [
    ("Chave privada (PEM/SSH)", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"), "critical"),
    ("AWS Access Key ID", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), "critical"),
    ("AWS Secret Access Key", re.compile(r"(?i)aws.{0,20}?secret.{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]"), "critical"),
    ("Token do GitHub", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,})\b"), "critical"),
    ("Token do GitHub (fine-grained)", re.compile(r"\b(github_pat_[A-Za-z0-9_]{60,})\b"), "critical"),
    ("Token do GitLab", re.compile(r"\b(glpat-[A-Za-z0-9_-]{20,})\b"), "critical"),
    ("Chave da Anthropic", re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{30,})\b"), "critical"),
    ("Chave da OpenAI", re.compile(r"\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})\b"), "critical"),
    ("Chave de API do Google", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"), "high"),
    ("Chave secreta do Stripe", re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{20,})\b"), "critical"),
    ("Token do Slack", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b"), "high"),
    ("Webhook do Slack", re.compile(r"(https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+)"), "medium"),
    ("Webhook do Discord", re.compile(r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]{50,})"), "medium"),
    ("Token de bot do Telegram", re.compile(r"\b(\d{8,10}:AA[0-9A-Za-z_-]{33})\b"), "high"),
    ("Chave do SendGrid", re.compile(r"\b(SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43})\b"), "high"),
    ("JWT", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"), "medium"),
    ("Senha em URL de conexão", re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@'\"]+:([^/\s:@'\"]{3,})@[^\s'\"]+"), "high"),
    # Genérico: variável com nome de segredo recebendo um valor literal com cara de segredo.
    ("Segredo atribuído no código", re.compile(
        r"(?i)\b[\w.-]*(?:password|passwd|senha|secret|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret)[\w.-]*"
        r"\s*[:=]\s*['\"]?((?!\$)[^\s'\"<>{}]{8,})['\"]?"), "high"),   # (?!\$): ignora $VARIAVEL
]

# Valores que são claramente exemplo/placeholder — não contam.
PLACEHOLDER = re.compile(
    r"(?i)(example|exemplo|sample|dummy|changeme|change_me|your[_-]|seu[_-]|sua[_-]|cole_|placeholder|"
    r"xxxx|\*{3,}|<[^>]+>|\$\{|\{\{|process\.env|os\.environ|getenv|redacted|todo|test|fake|null|none|true|false)")

SKIP_DIRS = {".git", "node_modules", "dist", "build", ".venv", "venv", "__pycache__", ".next", ".cache",
             "vendor", "target", ".idea", ".vscode", "coverage"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar", ".7z", ".mp3",
            ".mp4", ".woff", ".woff2", ".ttf", ".otf", ".exe", ".dll", ".so", ".pyc", ".lock", ".min.js", ".map"}
SENSITIVE_FILES = re.compile(r"(^|/)(\.env(\.[\w-]+)?|id_rsa|id_ed25519|.*\.pem|.*\.p12|.*\.pfx|.*\.kdbx|"
                             r"credentials(\.json)?|\.npmrc|\.pypirc|\.htpasswd|.*\.tfstate)$")
SENSITIVE_OK = re.compile(r"\.(example|sample|template|dist)$|\.env\.example$")


def entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {ch: s.count(ch) for ch in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in freq.values())


def mask(secret: str) -> str:
    keep = 6 if len(secret) > 16 else 3
    return secret[:keep] + "…" + "•" * 6


def scan_text(text: str, where: str, results: list[dict]) -> None:
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000:   # linha minificada gigante
            continue
        if "sentinel:ignore" in line:   # escape explícito para falso positivo
            continue
        for name, rx, sev in RULES:
            for m in rx.finditer(line):
                secret = m.group(1) if m.groups() else m.group(0)
                if PLACEHOLDER.search(secret):
                    continue
                if name == "Segredo atribuído no código":
                    if entropy(secret) < 3.0:
                        continue   # valor repetitivo/simples: provavelmente teste, não vazamento real
                    if re.search(r"[()\[\]]", secret) or re.fullmatch(r"[A-Za-z_][\w.]*", secret):
                        continue   # é código (chamada de função, variável), não um valor literal
                results.append({"rule": name, "severity": sev, "where": where, "line": lineno,
                                "preview": mask(secret)})
                break
            else:
                continue
            break   # uma regra por linha basta (evita o mesmo segredo aparecer duas vezes)


def git_ignored(root: Path, rels: list[str]) -> set[str]:
    """Quais desses arquivos o git ignora (.gitignore)? Esses não sobem no push."""
    if not rels:
        return set()
    try:
        # -z + bytes: separador nulo, imune à conversão \n → \r\n do Windows
        r = subprocess.run(["git", "-C", str(root), "check-ignore", "--stdin", "-z"],
                           input="\0".join(rels).encode("utf-8"), capture_output=True)
        return set(r.stdout.decode("utf-8", "replace").split("\0")) - {""} if r.returncode in (0, 1) else set()
    except FileNotFoundError:
        return set()


def scan_dir(root: Path, results: list[dict], include_ignored: bool = False) -> tuple[int, int]:
    files: list[tuple[Path, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        files += [(Path(dirpath) / fn, (Path(dirpath) / fn).relative_to(root).as_posix()) for fn in filenames]
    ignored = set() if include_ignored else git_ignored(root, [rel for _, rel in files])
    n = 0
    for p, rel in files:
        if rel in ignored:
            continue   # protegido pelo .gitignore: não vai pro GitHub
        if SENSITIVE_FILES.search(rel) and not SENSITIVE_OK.search(rel):
            results.append({"rule": "Arquivo sensível fora do .gitignore", "severity": "high", "where": rel,
                            "line": 0, "preview": "vai subir no próximo commit — adicione ao .gitignore"})
        if any(p.name.lower().endswith(e) for e in SKIP_EXT):
            continue
        try:
            if p.stat().st_size > 1_000_000:
                continue
            data = p.read_bytes()
        except OSError:
            continue
        if b"\x00" in data[:4096]:
            continue   # binário
        scan_text(data.decode("utf-8", "replace"), rel, results)
        n += 1
    return n, len(ignored)


def scan_git(root: Path, results: list[dict]) -> int:
    """Varre cada versão de cada arquivo que já passou pelo histórico (todas as branches)."""
    try:
        out = subprocess.run(["git", "-C", str(root), "log", "--all", "-p", "--no-color", "--unified=0",
                              "--format=@@COMMIT %h"], capture_output=True, text=True, encoding="utf-8",
                             errors="replace", check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(yellow("  (não é um repositório git ou git não instalado — pulando histórico)"))
        return 0
    commit, file, commits = "?", "?", 0
    seen = {(r["where"], r["preview"]) for r in results}
    for line in out.splitlines():
        if line.startswith("@@COMMIT "):
            commit = line.split()[1]
            commits += 1
        elif line.startswith("+++ b/"):
            file = line[6:]
            if SENSITIVE_FILES.search(file) and not SENSITIVE_OK.search(file):
                key = (f"{file} (histórico)", "")
                if key not in seen:
                    seen.add(key)
                    results.append({"rule": "Arquivo sensível já foi commitado", "severity": "high",
                                    "where": f"{file} (histórico)", "line": 0, "preview": f"commit {commit}"})
        elif line.startswith("+") and not line.startswith("+++"):
            tmp: list[dict] = []
            scan_text(line[1:], f"{file} @ {commit}", tmp)
            for r in tmp:
                key = (r["where"].split(" @ ")[0], r["preview"])
                if key in seen:
                    continue
                seen.add(key)
                r["line"] = 0
                results.append(r)
    return commits


def main() -> None:
    ap = argparse.ArgumentParser(description="Procura segredos vazados em código e no histórico git.")
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--git", action="store_true", help="varre também todo o histórico de commits")
    ap.add_argument("--json", help="salva o resultado em JSON (valores sempre mascarados)")
    ap.add_argument("--include-ignored", action="store_true",
                    help="varre também arquivos protegidos pelo .gitignore (ex.: seu .env local)")
    a = ap.parse_args()

    root = Path(a.path).resolve()
    if not root.is_dir():
        print(red(f"✖ pasta não encontrada: {root}"))
        sys.exit(2)
    results: list[dict] = []
    files, ignored = scan_dir(root, results, a.include_ignored)
    commits = scan_git(root, results) if a.git else 0

    print(bold(f"\n  Varredura de segredos · {root}"))
    print(dim(f"  {files} arquivo(s)" + (f" · {commits} commit(s) no histórico" if a.git else "")
              + (f" · {ignored} ignorado(s) pelo .gitignore (use --include-ignored para ver)" if ignored else "")
              + "\n"))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for r in sorted(results, key=lambda r: (order[r["severity"]], r["where"])):
        loc = r["where"] + (f":{r['line']}" if r["line"] else "")
        print(f"  {sev_color(r['severity'], SEVERITY_PT[r['severity']]):<12} {bold(r['rule'])}")
        print(dim(f"      {loc}   {r['preview']}"))
    if results:
        print(red(f"\n  ✖ {len(results)} possível(is) segredo(s)."))
        print(dim("  Se for real: 1) REVOGUE/troque a chave no serviço (apagar do código não basta — ela já vazou)\n"
                  "               2) mova para .env (no .gitignore) ou um cofre de segredos\n"
                  "               3) se estava no histórico, limpe com git filter-repo e force push\n"
                  "  Falso positivo? Adicione o comentário  sentinel:ignore  na linha."))
    else:
        print(green("  ✔ Nenhum segredo encontrado."))
    if a.json:
        Path(a.json).write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    sys.exit(1 if results else 0)


if __name__ == "__main__":
    main()
