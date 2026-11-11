# Metodologia — recon e enumeração por serviço

Baseada em PTES e OWASP WSTG. Sempre: `scope.py check <alvo>` antes, `scope.py log` depois.

## 1. Reconhecimento

### Passivo (não toca o alvo)
- DNS público: `dig +short A dominio`, `dig MX`, `dig TXT` (SPF/DMARC dizem que serviços de e-mail usam).
- Subdomínios por certificados: crt.sh (`https://crt.sh/?q=%25.dominio&output=json`). **Subdomínio
  descoberto não entra no escopo automaticamente** — confira com `scope.py check`.
- Tecnologias e histórico: Wayback Machine, cabeçalhos em respostas já vistas, vagas de emprego.
- Código público do alvo (GitHub da empresa) → `secrets_scan.py` se for clonado com permissão.

### Ativo
```bash
# descoberta rápida de portas (todas TCP), depois versão/scripts só nas abertas
nmap -p- --min-rate 500 -T3 -oA engagement/recon/allports <alvo>
nmap -sV -sC -p <portas> -T3 -oX engagement/recon/nmap.xml <alvo>
python scripts/nmap_parse.py engagement/recon/nmap.xml --add-findings
# UDP (lento — só as principais)
nmap -sU --top-ports 25 -T3 <alvo>
```
Em CTF, `--min-rate` mais alto é aceitável. Em ambiente real, respeite `max_requests_per_second`.

## 2. Enumeração por serviço

| Porta | Serviço | O que olhar | Comandos |
|---|---|---|---|
| 21 | FTP | login anônimo, upload permitido, versão (vsftpd 2.3.4 tem backdoor) | `ftp <ip>` (anonymous), `nmap --script ftp-anon,ftp-syst` |
| 22 | SSH | versão (CVE), algoritmos fracos, login por senha permitido | `ssh-audit <ip>`, `ssh -v <ip>` |
| 25/587 | SMTP | open relay, enumeração de usuários (VRFY/EXPN) | `nmap --script smtp-commands,smtp-open-relay,smtp-enum-users` |
| 53 | DNS | transferência de zona | `dig axfr @<ip> <dominio>` |
| 80/443 | HTTP(S) | tudo da seção web abaixo | `web_audit.py`, `whatweb`, `ffuf` |
| 88/389/636 | Kerberos/LDAP | domínio AD, usuários, bind anônimo | `ldapsearch -x -H ldap://<ip> -s base namingcontexts`, `nxc ldap` |
| 111/2049 | RPC/NFS | compartilhamentos montáveis, `no_root_squash` | `showmount -e <ip>`, `rpcinfo -p <ip>` |
| 139/445 | SMB | sessão nula, shares legíveis/graváveis, SMBv1, assinatura | `smbclient -N -L //<ip>`, `enum4linux-ng -A <ip>`, `nxc smb <ip> --shares -u '' -p ''` |
| 161/udp | SNMP | community `public` | `snmpwalk -v2c -c public <ip>`, `onesixtyone` |
| 1433/3306/5432 | Bancos | exposição externa, senha vazia/padrão | `nmap --script mysql-info,mysql-empty-password`, cliente oficial |
| 3389 | RDP | NLA, versão do Windows (rdp-ntlm-info revela nome/domínio) | `nmap --script rdp-ntlm-info,rdp-enum-encryption` |
| 5985/5986 | WinRM | acesso remoto com credencial válida | `evil-winrm -i <ip> -u <u> -p <p>` (após obter credencial) |
| 6379 | Redis | sem senha | `redis-cli -h <ip> INFO` (só leitura) |
| 8080/8443 | Painéis | Tomcat/Jenkins/etc. com credencial padrão | página de login + documentação de credencial padrão |
| 9200 | Elasticsearch | API aberta | `curl http://<ip>:9200/_cat/indices` |
| 27017 | MongoDB | sem autenticação | `mongosh --host <ip> --eval 'db.adminCommand({listDatabases:1})'` |

## 3. Web (resumo — detalhes em web-checklist.md)

1. `python scripts/web_audit.py <url> --probe --add-findings`
2. Tecnologia e versão: `whatweb <url>`, cabeçalhos, `/robots.txt`, `/sitemap.xml`, comentários no HTML,
   arquivos `.js` (endpoints de API e chaves esquecidas aparecem muito ali).
3. Conteúdo: `ffuf -u <url>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -rate 10 -mc all -fc 404`
4. Virtual hosts (CTF): `ffuf -u http://<ip> -H "Host: FUZZ.<dominio>" -w subdomains-top1million-5000.txt -fs <tamanho padrão>`
5. Mapeie toda funcionalidade (login, cadastro, upload, busca, filtros, IDs em URL, APIs) e teste cada uma
   contra o checklist.

## 4. Pesquisa de vulnerabilidades

- Versão exata → `searchsploit <produto> <versão>`, NVD (nvd.nist.gov), GitHub Security Advisories.
- Leia o exploit antes de rodar. Entenda o que ele faz, ajuste para a prova mínima, e em ambiente real
  confirme com o usuário antes de executar.
- Registre a CVE nas referências do achado.

## 5. Pós-exploração (CTF/lab, ou pentest com autorização explícita para isso)

- Estabilize a shell: `python3 -c 'import pty;pty.spawn("/bin/bash")'`, `export TERM=xterm`, `stty raw -echo; fg`.
- Enumere para escalar privilégio → `privesc.md`.
- Em ambiente real: colete só a evidência necessária (`id`, `hostname`, `ip a`), não navegue em dados de
  usuários, não instale nada persistente, e documente a limpeza de qualquer arquivo que você criou.
