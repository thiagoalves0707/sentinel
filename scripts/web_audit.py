#!/usr/bin/env python3
"""
web_audit.py — auditoria PASSIVA de um site: cabeçalhos de segurança, cookies, TLS e vazamentos.

Só faz requisições GET normais (as mesmas que um navegador faria). Nada de fuzzing,
força bruta ou payload. Mesmo assim, só roda contra alvos DENTRO do escopo.

  python scripts/web_audit.py https://app.exemplo.com
  python scripts/web_audit.py https://app.exemplo.com --probe       # + checa arquivos expostos comuns
  python scripts/web_audit.py https://app.exemplo.com --add-findings # registra o que achar em findings.json

Saída: nota de A+ a F, lista de checagens e (com --json) um arquivo em recon/.
"""
from __future__ import annotations

import argparse
import datetime as dt
import http.client
import json
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
import warnings
from pathlib import Path
from urllib.parse import urljoin, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (SEVERITY_PT, USER_AGENT, add_finding, bold, dim,  # noqa: E402
                     engagement_dir, green, log_action, red, require_in_scope, sev_color, yellow)

TIMEOUT = 12

# Arquivos que NUNCA deveriam estar públicos. Só testados com --probe.
# Para cada um: caminho, o que precisa aparecer na resposta pra contar como exposto, severidade.
PROBES = [
    ("/.git/HEAD", re.compile(r"^ref: refs/", re.M), "high", "Repositório .git exposto",
     "O diretório .git está acessível. Dá pra baixar o código-fonte inteiro e o histórico — "
     "que costuma ter senhas e chaves antigas."),
    ("/.env", re.compile(r"^[A-Z0-9_]{2,}=", re.M), "critical", "Arquivo .env exposto",
     "O arquivo de variáveis de ambiente está público. Ele normalmente contém senhas de banco, "
     "chaves de API e segredos da aplicação."),
    ("/.DS_Store", re.compile(r"Bud1"), "low", "Arquivo .DS_Store exposto",
     "Revela nomes de arquivos e pastas do servidor (listagem indireta)."),
    ("/server-status", re.compile(r"Apache Server Status", re.I), "medium",
     "Página server-status do Apache exposta",
     "Mostra requisições em andamento, IPs de clientes e URLs internas."),
    ("/phpinfo.php", re.compile(r"<title>PHP [0-9.]+ - phpinfo", re.I), "medium", "phpinfo() exposto",
     "Revela versões, caminhos, variáveis de ambiente e configuração completa do PHP."),
]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Queremos VER o redirecionamento (ex.: http→https), não segui-lo."""
    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


_opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))


def fetch(url: str, rps_delay: float) -> tuple[int, dict, list[str], bytes]:
    """GET simples. Retorna (status, cabeçalhos em minúsculas, lista de Set-Cookie, corpo até 64 KB)."""
    time.sleep(rps_delay)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        resp = _opener.open(req, timeout=TIMEOUT)
    except urllib.error.HTTPError as e:   # 3xx/4xx/5xx também têm cabeçalhos úteis
        resp = e
    headers = {k.lower(): v for k, v in resp.headers.items()}
    cookies = resp.headers.get_all("Set-Cookie") or []
    body = resp.read(65536) if hasattr(resp, "read") else b""
    return resp.status if hasattr(resp, "status") else resp.code, headers, cookies, body


def tls_info(host: str, port: int) -> dict:
    ctx = ssl.create_default_context()
    info: dict = {}
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                info["version"] = s.version()
                info["cipher"] = s.cipher()[0]
                exp = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=dt.timezone.utc)
                info["expires"] = exp.date().isoformat()
                info["days_left"] = (exp - dt.datetime.now(dt.timezone.utc)).days
                info["issuer"] = dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "?")
                info["valid"] = True
    except ssl.SSLCertVerificationError as e:
        info.update(valid=False, error=f"certificado inválido: {e.verify_message}")
    except (OSError, ssl.SSLError) as e:
        info.update(valid=False, error=str(e))
    # Servidor ainda aceita TLS 1.0/1.1? (só um handshake, sem dados)
    legacy = []
    for name, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        c2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c2.check_hostname = False
        c2.verify_mode = ssl.CERT_NONE
        try:
            with warnings.catch_warnings():   # o Python avisa que TLS 1.0/1.1 é obsoleto — é exatamente o que testamos
                warnings.simplefilter("ignore", DeprecationWarning)
                c2.minimum_version = ver
                c2.maximum_version = ver
            c2.set_ciphers("ALL:@SECLEVEL=0")
            with socket.create_connection((host, port), timeout=6) as sock:
                with c2.wrap_socket(sock, server_hostname=host):
                    legacy.append(name)
        except (OSError, ssl.SSLError, ValueError):
            pass
    info["legacy_protocols"] = legacy
    return info


class Audit:
    def __init__(self, url: str):
        self.url = url
        self.checks: list[dict] = []   # {ok, sev, title, detail, fix}

    def ok(self, title: str, detail: str = "") -> None:
        self.checks.append({"ok": True, "sev": "info", "title": title, "detail": detail})

    def bad(self, sev: str, title: str, detail: str, fix: str, ref: str = "") -> None:
        self.checks.append({"ok": False, "sev": sev, "title": title, "detail": detail, "fix": fix, "ref": ref})

    def grade(self) -> str:
        penalty = {"critical": 40, "high": 25, "medium": 10, "low": 4, "info": 0}
        pts = 100 - sum(penalty[c["sev"]] for c in self.checks if not c["ok"])
        for limit, g in ((97, "A+"), (85, "A"), (70, "B"), (55, "C"), (40, "D"), (25, "E")):
            if pts >= limit:
                return g
        return "F"


def analyze_headers(a: Audit, h: dict, https: bool) -> None:
    MDN = "https://developer.mozilla.org/docs/Web/HTTP/Headers/"
    if https:
        hsts = h.get("strict-transport-security", "")
        m = re.search(r"max-age=(\d+)", hsts)
        if not hsts:
            a.bad("medium", "HSTS ausente",
                  "Sem Strict-Transport-Security, um atacante na mesma rede pode rebaixar a conexão para HTTP.",
                  "Strict-Transport-Security: max-age=31536000; includeSubDomains", MDN + "Strict-Transport-Security")
        elif not m or int(m.group(1)) < 15552000:
            a.bad("low", "HSTS com max-age curto", f"Valor atual: {hsts}",
                  "Use max-age de pelo menos 6 meses (15552000), idealmente 1 ano.", MDN + "Strict-Transport-Security")
        else:
            a.ok("HSTS ativo", hsts)

    csp = h.get("content-security-policy", "")
    if not csp:
        a.bad("medium", "Content-Security-Policy ausente",
              "Sem CSP, qualquer XSS encontrado consegue carregar e executar scripts de qualquer lugar.",
              "Defina uma CSP começando por: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
              MDN + "Content-Security-Policy")
    else:
        # Vale a diretiva script-src; se não existir, o navegador usa default-src.
        directives = {d.strip().split(" ")[0]: d.strip() for d in csp.split(";") if d.strip()}
        script_rule = directives.get("script-src") or directives.get("default-src", "")
        weak = [w for w in ("'unsafe-inline'", "'unsafe-eval'") if w in script_rule]
        if weak:
            a.bad("low", "CSP permite scripts inseguros", f"A política contém {', '.join(weak)}, o que anula boa parte da proteção contra XSS.",
                  "Troque scripts inline por arquivos ou use nonces/hashes.", MDN + "Content-Security-Policy")
        else:
            a.ok("Content-Security-Policy presente")

    if h.get("x-content-type-options", "").lower() != "nosniff":
        a.bad("low", "X-Content-Type-Options ausente",
              "O navegador pode 'adivinhar' o tipo de arquivo e executar conteúdo enviado como se fosse script.",
              "X-Content-Type-Options: nosniff", MDN + "X-Content-Type-Options")
    else:
        a.ok("X-Content-Type-Options: nosniff")

    if "frame-ancestors" not in csp and not h.get("x-frame-options"):
        a.bad("medium", "Proteção contra clickjacking ausente",
              "A página pode ser embutida num iframe de outro site para enganar o usuário a clicar.",
              "X-Frame-Options: DENY  (ou CSP frame-ancestors 'self')", MDN + "X-Frame-Options")
    else:
        a.ok("Proteção contra clickjacking")

    if not h.get("referrer-policy"):
        a.bad("low", "Referrer-Policy ausente", "URLs completas (com tokens em query string) podem vazar para outros sites.",
              "Referrer-Policy: strict-origin-when-cross-origin", MDN + "Referrer-Policy")
    else:
        a.ok("Referrer-Policy", h["referrer-policy"])

    if not h.get("permissions-policy"):
        a.bad("info", "Permissions-Policy ausente", "Não restringe câmera, microfone, geolocalização etc.",
              "Permissions-Policy: camera=(), microphone=(), geolocation=()", MDN + "Permissions-Policy")

    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        v = h.get(name, "")
        if re.search(r"\d+\.\d+", v):
            a.bad("low", f"Versão de software exposta ({name})",
                  f"{name}: {v} — facilita procurar exploits conhecidos para essa versão exata.",
                  f"Remova ou generalize o cabeçalho {name}.", "https://owasp.org/www-project-secure-headers/")

    acao = h.get("access-control-allow-origin", "")
    if acao == "*" and h.get("access-control-allow-credentials", "").lower() == "true":
        a.bad("high", "CORS aberto com credenciais",
              "Qualquer site pode fazer requisições autenticadas e ler as respostas em nome do usuário.",
              "Liste explicitamente as origens permitidas.", "https://portswigger.net/web-security/cors")
    elif acao == "*":
        a.bad("info", "CORS liberado para qualquer origem",
              "Normal para APIs/arquivos públicos; ruim se a resposta tiver dado privado.",
              "Restrinja as origens se o conteúdo não for público.", "https://portswigger.net/web-security/cors")


def analyze_cookies(a: Audit, cookies: list[str], https: bool) -> None:
    for raw in cookies:
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        problems = []
        if https and "secure" not in [p.strip() for p in low.split(";")]:
            problems.append("sem Secure")
        if "httponly" not in low:
            problems.append("sem HttpOnly")
        if "samesite" not in low:
            problems.append("sem SameSite")
        sessionish = re.search(r"sess|sid|auth|token|jwt|login", name, re.I)
        if problems:
            a.bad("medium" if sessionish and "sem HttpOnly" in problems else "low",
                  f"Cookie '{name}' {', '.join(problems)}",
                  "Cookies de sessão sem essas flags ficam expostos a XSS (HttpOnly), a tráfego sem criptografia (Secure) "
                  "e a CSRF (SameSite).",
                  f"Set-Cookie: {name}=…; Secure; HttpOnly; SameSite=Lax",
                  "https://owasp.org/www-community/controls/SecureCookieAttribute")
        else:
            a.ok(f"Cookie '{name}' com Secure/HttpOnly/SameSite")


def run(url: str, probe: bool, rps: int) -> tuple[Audit, dict]:
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    host, https = parts.hostname or "", parts.scheme == "https"
    port = parts.port or (443 if https else 80)
    delay = 1.0 / max(rps, 1)
    a = Audit(url)
    raw: dict = {"url": url}

    status, h, cookies, body = fetch(url, delay)
    raw.update(status=status, headers=h)
    print(dim(f"  GET {url} → {status}"))

    # HTTP → HTTPS
    if https:
        try:
            st, hh, _, _ = fetch(f"http://{parts.netloc}{parts.path or '/'}", delay)
            loc = hh.get("location", "")
            if st in (301, 302, 307, 308) and loc.startswith("https://"):
                a.ok("HTTP redireciona para HTTPS", f"{st} → {loc}")
            else:
                a.bad("medium", "HTTP não redireciona para HTTPS",
                      f"http://{host} respondeu {st} sem mandar para HTTPS.",
                      "Redirecione toda requisição HTTP com 301 para a versão HTTPS.")
        except (OSError, http.client.HTTPException):
            a.ok("Porta 80 fechada (só HTTPS)")
    else:
        a.bad("high", "Site sem HTTPS", "Todo o tráfego, inclusive senhas e cookies, trafega em texto puro.",
              "Ative HTTPS (Let's Encrypt é gratuito) e redirecione o HTTP.")

    analyze_headers(a, h, https)
    analyze_cookies(a, cookies, https)

    if https:
        t = tls_info(host, port)
        raw["tls"] = t
        if not t.get("valid"):
            a.bad("high", "Certificado TLS inválido", t.get("error", ""), "Instale um certificado válido para o domínio.")
        else:
            a.ok(f"TLS {t['version']} · {t['cipher']}", f"emitido por {t['issuer']}, expira em {t['expires']}")
            if t["days_left"] < 0:
                a.bad("high", "Certificado expirado", f"Expirou em {t['expires']}.", "Renove o certificado.")
            elif t["days_left"] < 21:
                a.bad("medium", "Certificado perto de expirar", f"Faltam {t['days_left']} dias.",
                      "Renove já e automatize a renovação (certbot/ACME).")
        if t.get("legacy_protocols"):
            a.bad("medium", "Protocolos TLS obsoletos aceitos", ", ".join(t["legacy_protocols"]) +
                  " têm falhas conhecidas (BEAST, POODLE) e não são mais aceitos pelos navegadores.",
                  "Aceite apenas TLS 1.2 e 1.3.", "https://datatracker.ietf.org/doc/rfc8996/")

    # security.txt (RFC 9116) — boa prática, não falha
    try:
        st, _, _, _ = fetch(urljoin(url, "/.well-known/security.txt"), delay)
        if st == 200:
            a.ok("security.txt publicado")
        else:
            a.bad("info", "security.txt ausente", "Pesquisadores não têm um canal oficial pra reportar falhas.",
                  "Publique /.well-known/security.txt (RFC 9116).", "https://securitytxt.org/")
    except (OSError, http.client.HTTPException):
        pass

    if probe:
        for path, sig, sev, title, desc in PROBES:
            try:
                st, _, _, b = fetch(urljoin(url, path), delay)
            except (OSError, http.client.HTTPException):
                continue
            if st == 200 and sig.search(b.decode("utf-8", "replace")):
                a.bad(sev, title, f"{urljoin(url, path)} respondeu 200. {desc}",
                      f"Bloqueie {path} no servidor web e remova o arquivo do diretório público. "
                      "Se havia segredos nele, troque todos (considere-os vazados).")
            else:
                a.ok(f"{path} não exposto", f"HTTP {st}")
    return a, raw


def print_report(a: Audit) -> None:
    g = a.grade()
    color = green if g.startswith("A") else yellow if g in "BC" else red
    print(f"\n  {bold(a.url)}   nota {color(bold(f' {g} '))}\n")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for ck in sorted(a.checks, key=lambda c: (c["ok"], order[c["sev"]])):
        if ck["ok"]:
            print(green("  ✔ ") + ck["title"] + (dim(f"  {ck['detail']}") if ck.get("detail") else ""))
        else:
            print(f"  {sev_color(ck['sev'], '✖')} {ck['title']} " + sev_color(ck["sev"], f"[{SEVERITY_PT[ck['sev']]}]"))
            print(dim(f"      {ck['detail']}"))
            print(dim(f"      ↳ correção: {ck['fix']}"))
    bad = [c for c in a.checks if not c["ok"]]
    print(dim(f"\n  {len(a.checks) - len(bad)} ok · {len(bad)} problema(s)\n"))


def main() -> None:
    p = argparse.ArgumentParser(description="Auditoria passiva de segurança web.")
    p.add_argument("url")
    p.add_argument("--dir", help="pasta do engagement")
    p.add_argument("--probe", action="store_true", help="checa também arquivos sensíveis expostos (.git, .env…)")
    p.add_argument("--add-findings", action="store_true", help="registra problemas (exceto informativos) em findings.json")
    p.add_argument("--json", action="store_true", help="salva o resultado bruto em recon/")
    a = p.parse_args()

    eng = engagement_dir(a.dir)
    scope = require_in_scope(eng, a.url, "web_audit.py")
    rps = int((scope.get("rules") or {}).get("max_requests_per_second") or 5)

    try:
        audit, raw = run(a.url, a.probe, rps)
    except (OSError, http.client.HTTPException) as e:
        log_action(eng, f"web_audit {a.url}", a.url, "web_audit.py", result=f"erro: {e}")
        print(red(f"✖ não consegui acessar {a.url}: {e}"))
        sys.exit(1)

    print_report(audit)
    bad = [c for c in audit.checks if not c["ok"]]
    log_action(eng, f"web_audit {a.url}" + (" --probe" if a.probe else ""), a.url, "web_audit.py",
               result=f"nota {audit.grade()}, {len(bad)} problema(s)")

    if a.json:
        out = eng / "recon" / f"web_{urlsplit(audit.url).hostname}.json"
        out.write_text(json.dumps({**raw, "grade": audit.grade(), "checks": audit.checks}, indent=2,
                                  ensure_ascii=False, default=str), encoding="utf-8")
        print(dim(f"  salvo em {out}"))

    if a.add_findings:
        n = 0
        for ck in bad:
            if ck["sev"] == "info":
                continue
            _, created = add_finding(eng, {
                "title": ck["title"], "target": audit.url, "severity": ck["sev"],
                "category": "Configuração de segurança (OWASP A05)",
                "description": ck["detail"], "remediation": ck["fix"],
                "references": [ck["ref"]] if ck.get("ref") else [], "source": "web_audit"})
            n += created
        print(green(f"  ✔ {n} achado(s) novo(s) em findings.json"))


if __name__ == "__main__":
    main()
