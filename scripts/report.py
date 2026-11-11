#!/usr/bin/env python3
"""
report.py — achados e relatório final do engagement.

  add     registra um achado (vulnerabilidade) em findings.json
  list    lista os achados por severidade
  build   gera report.html (pronto pra entregar / imprimir em PDF) e report.md

Exemplos:
  python scripts/report.py add --title "SQL Injection no login" --target https://app.acme.com/login \
      --cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" --category "A03 Injection" \
      --description "O parâmetro user é concatenado na query..." \
      --evidence "POST /login user=admin'-- → 302 /dashboard" \
      --remediation "Usar queries parametrizadas..." --ref https://owasp.org/Top10/A03_2021-Injection/
  python scripts/report.py build

Textos aceitam um markdown simples: **negrito**, `código`, listas com "- " e blocos ```.
Se existir engagement/summary.md, ele vira o Resumo executivo.
"""
from __future__ import annotations

import argparse
import html
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cvss  # noqa: E402
from _common import (SEVERITIES, SEVERITY_PT, VERSION, add_finding, bold, die, dim,  # noqa: E402
                     engagement_dir, green, load_findings, load_scope, log_action, now_iso,
                     read_log, save_findings, sev_color)

SEV_HEX = {"critical": "#ff2d55", "high": "#ef4444", "medium": "#f59e0b", "low": "#38bdf8",
           "info": "#8b8b95"}


# ──────────────────────────────────────────────────────────────────────────────
# add / list
# ──────────────────────────────────────────────────────────────────────────────
def cmd_add(a: argparse.Namespace) -> None:
    eng = engagement_dir(a.dir)
    load_scope(eng)
    f: dict = {"title": a.title, "target": a.target or "", "category": a.category or "",
               "description": a.description or "", "impact": a.impact or "",
               "evidence": a.evidence or "", "remediation": a.remediation or "",
               "references": a.ref or [], "evidence_files": a.file or [],
               "status": a.status, "source": "manual"}
    if a.cvss:
        try:
            f["score"] = cvss.score(a.cvss)
        except ValueError as e:
            die(f"vetor CVSS inválido: {e}")
        f["cvss"] = a.cvss
        f["severity"] = cvss.severity(f["score"])
    else:
        f["severity"] = a.severity or "info"
    finding, created = add_finding(eng, f)
    if not created:
        die(f"já existe um achado igual: {finding['id']}")
    log_action(eng, f"achado registrado: {finding['title']}", finding["target"], "report.py",
               result=finding["id"])
    print(green(f"✔ {finding['id']} ") + sev_color(finding["severity"]) + f"  {finding['title']}")


def cmd_set(a: argparse.Namespace) -> None:
    """Atualiza um achado existente: status, severidade/CVSS ou textos."""
    eng = engagement_dir(a.dir)
    findings = load_findings(eng)
    f = next((x for x in findings if x["id"].lower() == a.id.lower()), None)
    if not f:
        die(f"achado {a.id} não encontrado")
    if a.cvss:
        try:
            f["score"] = cvss.score(a.cvss)
        except ValueError as e:
            die(f"vetor CVSS inválido: {e}")
        f["cvss"], f["severity"] = a.cvss, cvss.severity(f["score"])
    elif a.severity:
        f["severity"] = a.severity
        f.pop("score", None)
        f.pop("cvss", None)
    for key in ("status", "title", "description", "impact", "evidence", "remediation"):
        if getattr(a, key):
            f[key] = getattr(a, key)
    if a.ref:
        f.setdefault("references", []).extend(a.ref)
    save_findings(eng, findings)
    log_action(eng, f"achado atualizado: {f['id']}", f.get("target", ""), "report.py",
               result=f"{f.get('status')} / {f['severity']}")
    print(green(f"✔ {f['id']} ") + sev_color(f["severity"]) + f"  {f['title']}  " + dim(f.get("status", "")))


def sort_key(f: dict):
    return (SEVERITIES.index(f.get("severity", "info")), -(f.get("score") or 0), f.get("id", ""))


def cmd_list(a: argparse.Namespace) -> None:
    findings = sorted(load_findings(engagement_dir(a.dir)), key=sort_key)
    if not findings:
        print(dim("nenhum achado ainda."))
        return
    for f in findings:
        sc = f"{f['score']:.1f}" if f.get("score") is not None else "  - "
        st = "" if f.get("status") == "confirmado" else dim(f"  ({f.get('status')})")
        label = f"{SEVERITY_PT[f['severity']]:<11}"
        print(f"{f['id']}  {sev_color(f['severity'], label)} {sc}  "
              f"{bold(f['title'])}  {dim(f.get('target', ''))}{st}")
    c = Counter(f["severity"] for f in findings)
    print(dim("\n" + " · ".join(f"{SEVERITY_PT[s]}: {c[s]}" for s in SEVERITIES if c[s])))


# ──────────────────────────────────────────────────────────────────────────────
# Markdown mínimo → HTML (seguro: tudo é escapado antes)
# ──────────────────────────────────────────────────────────────────────────────
def _inline(t: str) -> str:
    t = html.escape(t)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"(https?://[^\s<]+)", r'<a href="\1">\1</a>', t)
    return t


def md(text: str) -> str:
    if not text:
        return ""
    out, para, items = [], [], []
    lines = text.replace("\r\n", "\n").split("\n")
    i = 0

    def flush():
        if para:
            out.append("<p>" + _inline(" ".join(para)) + "</p>")
            para.clear()
        if items:
            out.append("<ul>" + "".join(f"<li>{_inline(x)}</li>" for x in items) + "</ul>")
            items.clear()

    while i < len(lines):
        line = lines[i]
        if line.strip().startswith("```"):
            flush()
            block = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                block.append(lines[i])
                i += 1
            out.append("<pre>" + html.escape("\n".join(block)) + "</pre>")
        elif re.match(r"^\s*[-*] ", line):
            if para:
                flush()
            items.append(re.sub(r"^\s*[-*] ", "", line))
        elif not line.strip():
            flush()
        else:
            if items:
                flush()
            para.append(line.strip())
        i += 1
    flush()
    return "\n".join(out)


# ──────────────────────────────────────────────────────────────────────────────
# build
# ──────────────────────────────────────────────────────────────────────────────
CSS = """
:root{--bg:#0b0b0d;--panel:#131317;--line:#24242b;--txt:#e7e7ea;--mut:#9a9aa5;--red:#ef4444}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.6 "Segoe UI",system-ui,-apple-system,sans-serif}
main{max-width:980px;margin:0 auto;padding:0 24px 80px}
a{color:#f87171}
code,pre{font-family:"JetBrains Mono","Cascadia Code",Consolas,monospace;font-size:.86em}
code{background:#1d1d23;padding:.1em .4em;border-radius:4px}
pre{background:#08080a;border:1px solid var(--line);border-left:3px solid var(--red);padding:14px 16px;
    border-radius:8px;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
h2{font-size:13px;letter-spacing:.18em;text-transform:uppercase;color:var(--red);margin:56px 0 18px;
   display:flex;align-items:center;gap:12px}
h2::after{content:"";flex:1;height:1px;background:var(--line)}
.cover{padding:72px 0 40px;border-bottom:1px solid var(--line);position:relative;overflow:hidden}
.cover::before{content:"";position:absolute;inset:0;background:
  radial-gradient(600px 240px at 85% 0%,rgba(239,68,68,.22),transparent 70%),
  repeating-linear-gradient(0deg,transparent 0 3px,rgba(255,255,255,.015) 3px 4px);pointer-events:none}
.brand{font:700 13px "JetBrains Mono",Consolas,monospace;color:var(--red);letter-spacing:.3em}
.cover h1{font-size:40px;line-height:1.15;margin:18px 0 10px;font-weight:750}
.meta{display:flex;flex-wrap:wrap;gap:8px 28px;color:var(--mut);font-size:14px;margin-top:22px}
.meta b{color:var(--txt);font-weight:600}
.conf{display:inline-block;margin-top:26px;border:1px solid var(--red);color:var(--red);
      font:600 11px Consolas,monospace;letter-spacing:.2em;padding:4px 10px;border-radius:4px}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;border-top:3px solid}
.stat .n{font-size:32px;font-weight:750;line-height:1}
.stat .l{color:var(--mut);font-size:13px;margin-top:6px}
.bar{display:flex;height:10px;border-radius:99px;overflow:hidden;margin:18px 0 6px;background:var(--panel)}
.risk{display:flex;align-items:center;gap:14px;background:var(--panel);border:1px solid var(--line);
      border-radius:12px;padding:16px 18px;margin-top:14px}
.badge{display:inline-block;font:700 11px "Segoe UI",sans-serif;letter-spacing:.06em;text-transform:uppercase;
       padding:3px 9px;border-radius:99px;color:#0b0b0d;white-space:nowrap}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;color:var(--mut);font-weight:600;font-size:12px;letter-spacing:.06em;text-transform:uppercase}
th,td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
td.mono{font-family:Consolas,monospace;font-size:13px;color:var(--mut)}
.kv{display:grid;grid-template-columns:170px 1fr;gap:8px 18px}
.kv dt{color:var(--mut)} .kv dd{margin:0}
.finding{background:var(--panel);border:1px solid var(--line);border-radius:14px;margin:18px 0;overflow:hidden;
         border-left:4px solid}
.fh{padding:18px 22px;border-bottom:1px solid var(--line);display:flex;gap:14px;align-items:flex-start}
.fh .id{font:600 13px Consolas,monospace;color:var(--mut);padding-top:3px}
.fh h3{margin:0;font-size:19px;flex:1}
.score{text-align:right;font:750 26px/1 "Segoe UI",sans-serif}
.score small{display:block;font:500 10.5px Consolas,monospace;color:var(--mut);margin-top:6px;white-space:nowrap}
@media (max-width:700px){.fh{flex-wrap:wrap}.score{text-align:left;width:100%}.score small{white-space:normal;overflow-wrap:anywhere}}
.fb{padding:6px 22px 18px}
.fb h4{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:var(--mut);margin:18px 0 6px}
.tags{display:flex;flex-wrap:wrap;gap:8px;padding:12px 22px 0}
.tag{font-size:12px;color:var(--mut);background:#1b1b21;border:1px solid var(--line);padding:2px 10px;border-radius:99px}
.empty{color:var(--mut);background:var(--panel);border:1px dashed var(--line);border-radius:12px;padding:22px;text-align:center}
footer{color:var(--mut);font-size:12px;text-align:center;margin-top:60px}
@media (max-width:700px){.stats{grid-template-columns:repeat(2,1fr)}.kv{grid-template-columns:1fr}.cover h1{font-size:30px}}
@media print{
  :root{--bg:#fff;--panel:#fff;--line:#ddd;--txt:#111;--mut:#555}
  body{font-size:12px} .cover::before{display:none} pre{background:#f6f6f6}
  .finding{break-inside:avoid} h2{break-after:avoid}
}
"""


def esc(t) -> str:
    return html.escape(str(t if t is not None else ""))


def badge(sev: str) -> str:
    return f'<span class="badge" style="background:{SEV_HEX[sev]}">{SEVERITY_PT[sev]}</span>'


def build_html(scope: dict, findings: list[dict], log: list[dict], summary: str) -> str:
    counts = Counter(f["severity"] for f in findings)
    total = len(findings)
    worst = next((s for s in SEVERITIES if counts[s]), None)
    date = now_iso()[:10]

    stats = "".join(
        f'<div class="stat" style="border-top-color:{SEV_HEX[s]}"><div class="n">{counts[s]}</div>'
        f'<div class="l">{SEVERITY_PT[s]}</div></div>' for s in SEVERITIES)
    bar = "".join(f'<span style="width:{counts[s] / total * 100:.2f}%;background:{SEV_HEX[s]}"></span>'
                  for s in SEVERITIES if counts[s]) if total else ""
    risk_txt = {
        "critical": "Há falhas que permitem comprometimento sério com pouco esforço. Corrija imediatamente.",
        "high": "Há falhas exploráveis com impacto relevante. Priorize a correção nos próximos dias.",
        "medium": "Não há falhas graves, mas existem fraquezas que facilitam ataques. Planeje a correção.",
        "low": "Postura boa; restam apenas melhorias de baixo impacto.",
        "info": "Nenhuma vulnerabilidade explorável; apenas observações.",
    }
    risk = (f'<div class="risk">{badge(worst)}<div><b>Risco geral: {SEVERITY_PT[worst]}.</b> '
            f'{risk_txt[worst]}</div></div>') if worst else \
        '<div class="risk"><div><b>Nenhum achado registrado.</b></div></div>'

    rows = ""
    for f in findings:
        sc = f'{f["score"]:.1f}' if f.get("score") is not None else "—"
        rows += (f'<tr><td class="mono">{esc(f["id"])}</td>'
                 f'<td><a href="#{esc(f["id"])}">{esc(f["title"])}</a></td>'
                 f'<td>{badge(f["severity"])}</td><td class="mono">{sc}</td>'
                 f'<td class="mono">{esc(f.get("target", ""))}</td></tr>')
    table = (f'<table><tr><th>ID</th><th>Achado</th><th>Severidade</th><th>CVSS</th><th>Alvo</th></tr>'
             f'{rows}</table>') if findings else '<div class="empty">Nenhum achado registrado.</div>'

    cards = ""
    for f in findings:
        sev = f["severity"]
        score_html = (f'<div class="score" style="color:{SEV_HEX[sev]}">{f["score"]:.1f}'
                      f'<small>{esc(f.get("cvss", ""))}</small></div>') if f.get("score") is not None else ""
        tags = [f.get("target"), f.get("category")]
        if f.get("status") and f["status"] != "confirmado":
            tags.append(f"status: {f['status']}")
        tag_html = "".join(f'<span class="tag">{esc(t)}</span>' for t in tags if t)
        sections = ""
        for key, label in (("description", "Descrição"), ("impact", "Impacto"),
                           ("evidence", "Evidência"), ("remediation", "Recomendação")):
            val = f.get(key)
            if not val:
                continue
            body = f"<pre>{esc(val)}</pre>" if key == "evidence" else md(val)
            sections += f"<h4>{label}</h4>{body}"
        if f.get("evidence_files"):
            sections += "<h4>Arquivos de evidência</h4><ul>" + "".join(
                f"<li><code>{esc(x)}</code></li>" for x in f["evidence_files"]) + "</ul>"
        if f.get("references"):
            sections += "<h4>Referências</h4><ul>" + "".join(
                f"<li>{_inline(r)}</li>" for r in f["references"]) + "</ul>"
        cards += (f'<article class="finding" id="{esc(f["id"])}" style="border-left-color:{SEV_HEX[sev]}">'
                  f'<div class="fh"><span class="id">{esc(f["id"])}</span><h3>{esc(f["title"])}<br>{badge(sev)}</h3>'
                  f'{score_html}</div><div class="tags">{tag_html}</div><div class="fb">{sections}</div></article>')

    w = scope.get("window") or {}
    rules = scope.get("rules") or {}
    scope_html = (
        '<dl class="kv">'
        f'<dt>Autorização</dt><dd>{esc(scope["authorization"]["statement"])}</dd>'
        f'<dt>Modalidade</dt><dd>{esc(scope["mode"])}</dd>'
        + (f'<dt>Janela</dt><dd>{esc(w.get("start") or "…")} → {esc(w.get("end") or "…")}</dd>'
           if w.get("start") or w.get("end") else "")
        + f'<dt>Dentro do escopo</dt><dd>{"<br>".join(f"<code>{esc(x)}</code>" for x in scope["in_scope"])}</dd>'
        + (f'<dt>Fora do escopo</dt><dd>{"<br>".join(f"<code>{esc(x)}</code>" for x in scope["out_of_scope"])}</dd>'
           if scope.get("out_of_scope") else "")
        + f'<dt>Regras</dt><dd>Sem negação de serviço · sem ações destrutivas · máx. '
          f'{esc(rules.get("max_requests_per_second"))} req/s'
        + (f' · {esc(rules["notes"])}' if rules.get("notes") else "") + '</dd></dl>'
    )

    method = md(
        "O teste seguiu as fases do PTES/OWASP WSTG, sempre restrito ao escopo acima:\n\n"
        "- **Reconhecimento:** mapeamento de hosts, portas, serviços e tecnologias.\n"
        "- **Enumeração e análise:** identificação de versões, configurações e superfícies de ataque.\n"
        "- **Validação:** confirmação manual de cada vulnerabilidade com a prova mínima necessária, "
        "sem alterar dados nem afetar a disponibilidade.\n"
        "- **Classificação:** severidade pelo CVSS v3.1 (nota base) e recomendação de correção.\n"
    )

    log_rows = "".join(
        f'<tr><td class="mono">{esc(e.get("ts", "")[:19].replace("T", " "))}</td>'
        f'<td><code>{esc(e.get("action", ""))}</code></td><td class="mono">{esc(e.get("target", ""))}</td>'
        f'<td>{esc(e.get("result") or e.get("note") or "")}</td></tr>' for e in log)
    log_html = (f'<table><tr><th>Quando</th><th>Ação</th><th>Alvo</th><th>Resultado</th></tr>{log_rows}</table>'
                if log else '<div class="empty">Sem registros.</div>')

    summary_html = md(summary) if summary.strip() else md(
        f"Foram identificados **{total} achado(s)** no escopo avaliado. "
        "Os detalhes, as evidências e as recomendações de cada um estão na seção Achados.")

    return f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Relatório de Segurança · {esc(scope["name"])}</title>
<style>{CSS}</style></head><body><main>
<header class="cover">
  <div class="brand">▲ SENTINEL // RELATÓRIO DE SEGURANÇA</div>
  <h1>{esc(scope["name"])}</h1>
  <div class="meta">
    {f'<span>Cliente <b>{esc(scope["client"])}</b></span>' if scope.get("client") else ''}
    <span>Data <b>{date}</b></span>
    {f'<span>Responsável <b>{esc(scope["tester"])}</b></span>' if scope.get("tester") else ''}
    <span>Achados <b>{total}</b></span>
  </div>
  <span class="conf">CONFIDENCIAL</span>
</header>

<h2>Resumo executivo</h2>
{summary_html}
<div class="stats">{stats}</div>
<div class="bar">{bar}</div>
{risk}

<h2>Escopo e autorização</h2>
{scope_html}

<h2>Metodologia</h2>
{method}

<h2>Visão geral dos achados</h2>
{table}

<h2>Achados em detalhe</h2>
{cards or '<div class="empty">Nenhum achado registrado.</div>'}

<h2>Apêndice · Registro de atividades</h2>
{log_html}

<footer>Gerado pelo Sentinel v{VERSION} · CVSS v3.1 · Documento confidencial — distribua apenas aos responsáveis.</footer>
</main></body></html>
"""


def build_md(scope: dict, findings: list[dict], summary: str) -> str:
    counts = Counter(f["severity"] for f in findings)
    lines = [f"# Relatório de Segurança — {scope['name']}", "",
             f"**Data:** {now_iso()[:10]} · **Autorização:** {scope['authorization']['statement']}", "",
             "## Resumo", "", summary.strip() or f"{len(findings)} achado(s).", "",
             "| Severidade | Qtde |", "|---|---|"]
    lines += [f"| {SEVERITY_PT[s]} | {counts[s]} |" for s in SEVERITIES]
    lines += ["", "## Escopo", ""] + [f"- `{x}`" for x in scope["in_scope"]]
    if scope.get("out_of_scope"):
        lines += ["", "**Fora do escopo:**"] + [f"- `{x}`" for x in scope["out_of_scope"]]
    lines += ["", "## Achados", ""]
    for f in findings:
        sc = f" · CVSS {f['score']:.1f} (`{f['cvss']}`)" if f.get("score") is not None else ""
        lines += [f"### {f['id']} · {f['title']}", "",
                  f"**Severidade:** {SEVERITY_PT[f['severity']]}{sc} · **Alvo:** `{f.get('target', '')}`", ""]
        for key, label in (("description", "Descrição"), ("impact", "Impacto"),
                           ("remediation", "Recomendação")):
            if f.get(key):
                lines += [f"**{label}:** {f[key]}", ""]
        if f.get("evidence"):
            lines += ["**Evidência:**", "```", f["evidence"], "```", ""]
        if f.get("references"):
            lines += ["**Referências:**"] + [f"- {r}" for r in f["references"]] + [""]
    return "\n".join(lines)


def cmd_build(a: argparse.Namespace) -> None:
    eng = engagement_dir(a.dir)
    scope = load_scope(eng)
    findings = sorted(load_findings(eng), key=sort_key)
    if not a.include_unconfirmed:
        skipped = [f for f in findings if f.get("status") not in (None, "confirmado")]
        findings = [f for f in findings if f.get("status") in (None, "confirmado")]
        if skipped:
            print(dim(f"  {len(skipped)} achado(s) não confirmado(s) ficaram de fora "
                      "(use --include-unconfirmed para incluir)."))
    summary_f = eng / "summary.md"
    summary = summary_f.read_text(encoding="utf-8") if summary_f.exists() else ""
    out_html = eng / "report.html"
    out_md = eng / "report.md"
    out_html.write_text(build_html(scope, findings, read_log(eng), summary), encoding="utf-8")
    out_md.write_text(build_md(scope, findings, summary), encoding="utf-8")
    log_action(eng, "relatório gerado", tool="report.py", result=f"{len(findings)} achado(s)")
    print(green(f"✔ {out_html}"))
    print(green(f"✔ {out_md}"))


def main() -> None:
    p = argparse.ArgumentParser(description="Achados e relatório do Sentinel.")
    p.add_argument("--dir", help="pasta do engagement")
    sub = p.add_subparsers(dest="cmd", required=True)

    ad = sub.add_parser("add", help="registra um achado")
    ad.add_argument("--title", required=True)
    ad.add_argument("--target")
    ad.add_argument("--cvss", help='vetor, ex.: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"')
    ad.add_argument("--severity", choices=SEVERITIES, help="use se não houver vetor CVSS")
    ad.add_argument("--category", help="ex.: A01 Broken Access Control, CWE-89")
    ad.add_argument("--description")
    ad.add_argument("--impact")
    ad.add_argument("--evidence", help="requisição/resposta, saída de comando (texto)")
    ad.add_argument("--file", action="append", help="arquivo de evidência (repita)")
    ad.add_argument("--remediation")
    ad.add_argument("--ref", action="append", help="link de referência (repita)")
    ad.add_argument("--status", default="confirmado", choices=["confirmado", "a confirmar", "falso positivo"])
    ad.set_defaults(fn=cmd_add)

    st = sub.add_parser("set", help="atualiza um achado (ex.: confirmar ou marcar falso positivo)")
    st.add_argument("id", help="ex.: SNT-003")
    st.add_argument("--status", choices=["confirmado", "a confirmar", "falso positivo"])
    st.add_argument("--cvss")
    st.add_argument("--severity", choices=SEVERITIES)
    st.add_argument("--title")
    st.add_argument("--description")
    st.add_argument("--impact")
    st.add_argument("--evidence")
    st.add_argument("--remediation")
    st.add_argument("--ref", action="append")
    st.set_defaults(fn=cmd_set)

    ls = sub.add_parser("list", help="lista os achados")
    ls.set_defaults(fn=cmd_list)

    b = sub.add_parser("build", help="gera report.html e report.md")
    b.add_argument("--include-unconfirmed", action="store_true")
    b.set_defaults(fn=cmd_build)

    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
