# Blue team — hardening, logs e resposta a incidente

## Hardening rápido de servidor Linux

| Área | Verificar | Corrigir |
|---|---|---|
| Atualizações | `apt list --upgradable` / `dnf check-update` | `unattended-upgrades` ligado |
| SSH | `sshd -T \| grep -E "permitrootlogin\|passwordauthentication\|port"` | `PermitRootLogin no`, `PasswordAuthentication no` (só chave), `fail2ban` |
| Firewall | `ufw status` / `nft list ruleset` | negar entrada por padrão; abrir só 22 (restrito a IPs), 80, 443 |
| Serviços expostos | `ss -tlnp` | banco/Redis/Docker escutando em `127.0.0.1`, nunca `0.0.0.0` |
| Usuários | `awk -F: '$3==0' /etc/passwd`, `sudo -l -U <u>` | um só UID 0; sudo mínimo |
| Permissões | `find / -perm -4000`, `find / -perm -o+w -type f` | remover SUID desnecessário, arquivos world-writable |
| Docker | `docker ps`, grupo docker | não expor 2375; usuário no grupo docker = root |
| Logs | `journalctl`, `/var/log/auth.log` | retenção, envio para fora do servidor |
| Backups | existe? testado? | 3-2-1, um offline/imutável (ransomware) |

## Web (cabeçalhos por plataforma)

Cabeçalhos recomendados:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```
- **nginx**: `add_header Nome "valor" always;` no bloco `server`.
- **Apache**: `Header always set Nome "valor"` (mod_headers).
- **Vercel**: `vercel.json` → `"headers": [{"source": "/(.*)", "headers": [{"key": "...", "value": "..."}]}]`.
- **Netlify / Cloudflare Pages**: arquivo `_headers` com `/*` e os cabeçalhos indentados.
- **Next.js**: `async headers()` no `next.config.js`.
- **GitHub Pages**: não aceita cabeçalhos — use `<meta http-equiv="Content-Security-Policy" content="...">`
  no `<head>` (CSP e Referrer-Policy funcionam por meta; HSTS/X-Frame-Options não) ou ponha o Cloudflare na frente.

## Análise de logs — o que procurar

```bash
# SSH: força bruta e logins bem-sucedidos
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head
grep "Accepted" /var/log/auth.log
# Web: scanners, traversal, injeção, shells
grep -iE "\.\./|union.*select|<script|/etc/passwd|cmd=|wget |curl |\.php\?.*=http" access.log | head
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head        # IPs mais ativos
awk '$9 ~ /^5/' access.log | head                                     # erros 5xx (exploração quebrando algo?)
```
Windows (Event Viewer / `Get-WinEvent`): 4625 (login falhou), 4624 tipo 3/10 (login rede/RDP),
4720 (usuário criado), 4732 (adicionado a grupo admin), 7045 (serviço instalado), 4104 (script PowerShell).

## Resposta a incidente — primeiros 60 minutos

1. **Não desligue a máquina** (perde memória e conexões). Isole da rede (firewall/VLAN) se houver dano ativo.
2. **Preserve evidências**: `date`, `w`, `ps auxf`, `ss -tanp`, `last`, cópia de `/var/log`, hash dos arquivos
   suspeitos (`sha256sum`). Registre cada comando com horário (`scope.py log` serve para isso também).
3. **Escopo do incidente**: quando começou, qual porta/serviço/conta entrou, quais outros hosts conversaram
   com o IP do atacante.
4. **Contenção**: trocar credenciais expostas (começando pelas de maior privilégio), revogar tokens/chaves,
   bloquear IPs/domínios de C2, corrigir a falha de entrada.
5. **Erradicação e recuperação**: reinstalar a partir de imagem limpa é mais seguro do que "limpar".
6. **Lições**: linha do tempo, causa raiz, o que detectou (ou não), o que muda. LGPD: incidente com dado
   pessoal pode exigir comunicação à ANPD e aos titulares.

## Segredos vazados (fluxo certo)

1. `python scripts/secrets_scan.py <repo> --git`
2. Para cada segredo real: **revogar/trocar no provedor primeiro** — o valor já está comprometido.
3. Mover para variável de ambiente/`.env` (no `.gitignore`) ou cofre (Vault, Doppler, secrets do GitHub Actions).
4. Limpar histórico (`git filter-repo --replace-text`) e force push, só se o repositório for público e com ok
   do dono — e lembrar que forks/clones antigos ainda têm o valor (por isso o passo 2 vem antes).
5. Prevenir: ativar GitHub secret scanning / push protection; rodar o scanner em CI (exit 1 barra o merge).
