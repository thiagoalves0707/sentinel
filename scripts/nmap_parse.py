#!/usr/bin/env python3
"""
nmap_parse.py — transforma a saída XML do nmap em um mapa de ataque legível.

  nmap -sV -sC -T3 -oX engagement/recon/nmap.xml 10.10.10.3      (você roda o nmap)
  python scripts/nmap_parse.py engagement/recon/nmap.xml           (o Sentinel interpreta)

O que ele faz:
  - lista hosts, portas abertas, serviços e versões
  - avisa se apareceu algum host FORA do escopo no resultado
  - aponta serviços de risco (Telnet, FTP anônimo, SMBv1, banco de dados exposto, Docker API…)
  - sugere o próximo passo de enumeração para cada serviço
  - com --add-findings, registra os riscos como achados "a confirmar"
  - salva um resumo em recon/hosts.json
"""
from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (SEVERITY_PT, add_finding, bold, check_target, dim, engagement_dir,  # noqa: E402
                     green, load_scope, log_action, red, sev_color, yellow)

# Serviços que, só de estarem expostos, já merecem atenção.
# porta/serviço → (severidade, título, por quê)
RISKY = {
    "telnet": ("high", "Telnet exposto", "Telnet trafega usuário e senha em texto puro."),
    "ms-wbt-server": ("medium", "RDP exposto", "RDP aberto é alvo constante de força bruta e já teve falhas críticas (BlueKeep)."),
    "vnc": ("high", "VNC exposto", "VNC frequentemente tem senha fraca ou nenhuma e dá controle total da tela."),
    "mysql": ("medium", "Banco MySQL exposto", "Banco de dados não deveria aceitar conexões da rede externa."),
    "postgresql": ("medium", "Banco PostgreSQL exposto", "Banco de dados não deveria aceitar conexões da rede externa."),
    "ms-sql-s": ("medium", "Banco SQL Server exposto", "Banco de dados não deveria aceitar conexões da rede externa."),
    "mongodb": ("high", "MongoDB exposto", "MongoDB exposto foi a causa de milhares de vazamentos (sem autenticação por padrão em versões antigas)."),
    "redis": ("high", "Redis exposto", "Redis sem senha permite ler/gravar dados e, em muitos casos, executar código."),
    "elasticsearch": ("high", "Elasticsearch exposto", "API sem autenticação expõe todos os índices."),
    "memcache": ("medium", "Memcached exposto", "Vaza dados em cache e pode ser usado para ataques de amplificação."),
    "docker": ("critical", "API do Docker exposta", "Quem acessa a API do Docker controla o host inteiro."),
    "snmp": ("medium", "SNMP exposto", "Community strings padrão (public/private) vazam configuração da rede."),
    "rpcbind": ("low", "rpcbind exposto", "Revela serviços RPC/NFS disponíveis."),
    "nfs": ("medium", "NFS exposto", "Compartilhamentos NFS mal configurados podem ser montados por qualquer um."),
}
PORT_HINT = {23: "telnet", 3389: "ms-wbt-server", 5900: "vnc", 3306: "mysql", 5432: "postgresql",
             1433: "ms-sql-s", 27017: "mongodb", 6379: "redis", 9200: "elasticsearch",
             11211: "memcache", 2375: "docker", 161: "snmp", 111: "rpcbind", 2049: "nfs"}

# Próximo passo sugerido por serviço (comandos clássicos de enumeração, não destrutivos).
NEXT = {
    "http": "python scripts/web_audit.py http://{ip}:{port} --probe  ·  whatweb  ·  ffuf/gobuster com wordlist pequena",
    "https": "python scripts/web_audit.py https://{ip}:{port} --probe  ·  whatweb",
    "ftp": "ftp {ip} (testar login anonymous)  ·  nmap --script ftp-anon,ftp-syst -p{port} {ip}",
    "ssh": "versão → pesquisar CVEs (searchsploit)  ·  ssh-audit {ip}",
    "microsoft-ds": "smbclient -N -L //{ip}  ·  enum4linux-ng -A {ip}  ·  nmap --script smb-protocols,smb-security-mode -p445 {ip}",
    "netbios-ssn": "smbclient -N -L //{ip}  ·  enum4linux-ng -A {ip}",
    "ldap": "ldapsearch -x -H ldap://{ip} -s base namingcontexts",
    "domain": "dig axfr @{ip} <domínio>  (transferência de zona)",
    "smtp": "nmap --script smtp-commands,smtp-open-relay -p{port} {ip}",
    "snmp": "snmpwalk -v2c -c public {ip}",
    "mysql": "nmap --script mysql-info,mysql-empty-password -p{port} {ip}",
    "redis": "redis-cli -h {ip} INFO  (só leitura)",
    "ms-wbt-server": "nmap --script rdp-enum-encryption,rdp-ntlm-info -p{port} {ip}",
}


def service_name(port_el) -> tuple[str, str]:
    s = port_el.find("service")
    if s is None:
        return "?", ""
    name = s.get("name", "?")
    if s.get("tunnel") == "ssl" and name == "http":
        name = "https"
    ver = " ".join(x for x in (s.get("product"), s.get("version"), s.get("extrainfo")) if x)
    return name, ver


def parse(xml_path: Path) -> list[dict]:
    root = ET.parse(xml_path).getroot()   # XML gerado pelo seu próprio nmap
    hosts = []
    for h in root.findall("host"):
        if h.find("status") is not None and h.find("status").get("state") != "up":
            continue
        addr = next((a.get("addr") for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), "?")
        names = [n.get("name") for n in h.findall("hostnames/hostname")]
        os_match = h.find("os/osmatch")
        ports = []
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            name, ver = service_name(p)
            scripts = {s.get("id"): s.get("output", "") for s in p.findall("script")}
            ports.append({"port": int(p.get("portid")), "proto": p.get("protocol"),
                          "service": name, "version": ver, "scripts": scripts})
        hosts.append({"ip": addr, "hostnames": names, "os": os_match.get("name") if os_match is not None else "",
                      "ports": ports})
    return hosts


def risks_for(host: dict) -> list[dict]:
    out = []
    for p in host["ports"]:
        key = p["service"] if p["service"] in RISKY else PORT_HINT.get(p["port"])
        if key in RISKY:
            sev, title, why = RISKY[key]
            out.append({"sev": sev, "title": title, "why": why, "port": p})
        joined = " ".join(p["scripts"].values())
        if "Anonymous FTP login allowed" in joined:
            out.append({"sev": "high", "title": "FTP aceita login anônimo",
                        "why": "Qualquer pessoa lista (e às vezes envia) arquivos sem senha.", "port": p})
        if "NT LM 0.12" in joined or "SMBv1" in joined:
            out.append({"sev": "high", "title": "SMBv1 habilitado",
                        "why": "SMBv1 é o protocolo explorado pelo EternalBlue/WannaCry.", "port": p})
        if "message_signing: disabled" in joined or "not required" in p["scripts"].get("smb2-security-mode", ""):
            out.append({"sev": "medium", "title": "Assinatura SMB não exigida",
                        "why": "Permite ataques de relay NTLM na rede interna.", "port": p})
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Interpreta XML do nmap (-oX).")
    ap.add_argument("xml")
    ap.add_argument("--dir", help="pasta do engagement")
    ap.add_argument("--add-findings", action="store_true", help="registra os riscos como achados 'a confirmar'")
    a = ap.parse_args()

    eng = engagement_dir(a.dir)
    scope = load_scope(eng)
    try:
        hosts = parse(Path(a.xml))
    except (ET.ParseError, FileNotFoundError) as e:
        print(red(f"✖ não consegui ler {a.xml}: {e}"))
        sys.exit(1)

    all_risks = 0
    for h in hosts:
        ok, why = check_target(scope, h["ip"])
        label = h["ip"] + (f" ({', '.join(h['hostnames'])})" if h["hostnames"] else "")
        print("\n" + bold(f"■ {label}") + (dim(f"  {h['os']}") if h["os"] else ""))
        if not ok:
            print(red(f"  ⚠ FORA DO ESCOPO: {why}. Não interaja com este host."))
            continue
        if not h["ports"]:
            print(dim("  nenhuma porta aberta"))
        for p in h["ports"]:
            print(f"  {green(str(p['port']) + '/' + p['proto']):<20} {p['service']:<15} {dim(p['version'])}")
        risks = risks_for(h)
        for r in risks:
            print(f"  {sev_color(r['sev'], '▲ ' + SEVERITY_PT[r['sev']])}  {r['title']} "
                  f"{dim('(porta ' + str(r['port']['port']) + ') — ' + r['why'])}")
            if a.add_findings:
                add_finding(eng, {
                    "title": r["title"], "target": f"{h['ip']}:{r['port']['port']}", "severity": r["sev"],
                    "status": "a confirmar", "category": "Exposição de serviço",
                    "description": r["why"],
                    "evidence": f"nmap: {r['port']['port']}/{r['port']['proto']} open {r['port']['service']} "
                                f"{r['port']['version']}".strip(),
                    "remediation": "Restrinja o acesso por firewall/VPN, desative o serviço se não for necessário "
                                   "e mantenha-o atualizado.",
                    "source": "nmap_parse"})
        all_risks += len(risks)
        hints = []
        for p in h["ports"]:
            tpl = NEXT.get(p["service"])
            if tpl:
                hints.append(f"{p['port']}/{p['service']}: " + tpl.format(ip=h["ip"], port=p["port"]))
        if hints:
            print(yellow("  próximos passos:"))
            for x in hints:
                print(dim("    → " + x))

    out = eng / "recon" / "hosts.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(hosts, indent=2, ensure_ascii=False), encoding="utf-8")
    total_ports = sum(len(h["ports"]) for h in hosts)
    log_action(eng, f"nmap_parse {a.xml}", tool="nmap_parse.py",
               result=f"{len(hosts)} host(s), {total_ports} porta(s), {all_risks} risco(s)")
    print(dim(f"\n{len(hosts)} host(s) · {total_ports} porta(s) abertas · {all_risks} ponto(s) de atenção · resumo em {out}"))
    if a.add_findings and all_risks:
        print(yellow("Achados registrados como 'a confirmar' — valide cada um antes de marcar como confirmado."))


if __name__ == "__main__":
    main()
