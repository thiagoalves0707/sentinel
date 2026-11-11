# Checklist de testes web (OWASP Top 10 2021 + WSTG)

Para cada item: **como testar** e **prova mínima segura**. Em produção, nunca use payload que altere ou
apague dados (`DROP`, `DELETE`, `UPDATE`), e não dispare XSS armazenado que outros usuários reais vão ver.

## A01 — Quebra de controle de acesso
- **IDOR**: troque IDs em URL/corpo/JSON (`/api/pedidos/1042` → `1041`). Use DUAS contas suas de teste e
  mostre que a conta A lê/edita dado da conta B. Prova: as duas requisições lado a lado.
- Funções de admin acessíveis por usuário comum (forçar URL `/admin`, trocar `role` no corpo, método HTTP
  diferente: `GET` bloqueado mas `POST` liberado).
- Referência a arquivo: `?file=../../../../etc/passwd` (path traversal). Prova: ler um arquivo inócuo.
- CORS com `Origin: https://evil.example` refletido + `Access-Control-Allow-Credentials: true`.

## A02 — Falhas criptográficas
- `web_audit.py` cobre HTTPS, HSTS, TLS antigo, certificado.
- Dados sensíveis em texto puro (senha no corpo de resposta, token em URL, cookie sem `Secure`).
- Hash de senha fraco (MD5/SHA1 sem salt) quando há como observar (dump em CTF, código).

## A03 — Injeção
- **SQLi**: `'` e `"` em cada parâmetro → erro? Depois boolean (`' AND 1=1-- -` vs `' AND 1=2-- -`) ou tempo
  (`' AND SLEEP(3)-- -`, uma vez só). Prova mínima: `@@version`/`version()`. `sqlmap` só com `--risk 1
  --level 1 --batch` e escopo explícito; nunca `--os-shell`/`--dump-all` em produção.
- **XSS**: `"><svg onload=alert(document.domain)>` refletido. Em armazenado, use texto inofensivo e remova depois.
- **Command injection**: `;id`, `|id`, `$(id)` em campos que viram comando (ping, conversão de arquivo).
- **SSTI**: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` → `49` na resposta indica template injection.
- NoSQL (`{"$ne": null}`), LDAP, XPath, cabeçalhos (CRLF `%0d%0a`).

## A04 — Design inseguro
- Lógica de negócio: valor negativo no carrinho, cupom reaplicado, pular etapa do fluxo, condição de corrida
  (duas requisições simultâneas de saque/resgate — só em ambiente de teste).
- Recuperação de senha: token previsível, sem expiração, enumeração de usuário pela mensagem.

## A05 — Configuração incorreta
- `web_audit.py --probe`: cabeçalhos, `.git`, `.env`, `server-status`, `phpinfo`.
- Listagem de diretório, páginas de erro com stack trace, modo debug ligado (Django/Flask/Laravel),
  painéis com credencial padrão, buckets S3/Blob públicos citados no HTML/JS.

## A06 — Componentes vulneráveis
- Versões em cabeçalhos, `/package.json`, comentários, caminhos de `.js` (`jquery-1.12.4.min.js`).
- Cruzar com CVE (NVD, Snyk, GitHub Advisories). Só reporte se a versão afetada estiver confirmada.

## A07 — Falhas de identificação e autenticação
- Sem limite de tentativas (teste com no máx. ~20-50 tentativas, conforme as regras).
- Enumeração de usuário (mensagens ou tempos diferentes para usuário existente/inexistente).
- Sessão: token não muda após login (fixation), não expira no logout, JWT com `alg: none`/segredo fraco
  (`hashcat -m 16500` só em CTF/lab), cookie sem `HttpOnly`/`Secure`/`SameSite`.
- MFA contornável (pular a etapa, reutilizar código).

## A08 — Falhas de integridade
- Desserialização insegura (Java `rO0`, PHP `O:`, Python pickle, .NET ViewState sem MAC).
- Scripts de CDN sem `integrity` (SRI); atualização sem assinatura.

## A09 — Falhas de log e monitoramento
- Difícil de testar de fora; pergunte/observe: tentativas de login falhas geram alerta? Há rate limit/WAF?

## A10 — SSRF
- Parâmetros que recebem URL (webhook, importar por link, preview de imagem). Teste com um endpoint seu
  (ex.: Burp Collaborator, interactsh) e, em lab, `http://127.0.0.1:<porta>`, `http://169.254.169.254/`
  (metadados de nuvem — em produção, pare na prova de que a requisição sai; não leia credenciais).

## Extras frequentes
- **Upload**: extensão dupla (`.php.jpg`), content-type falso, SVG com script, polyglot; prova = executar
  `phpinfo()`/`id` em lab, ou só mostrar que o arquivo é servido como executável em produção.
- **CSRF**: ação sensível sem token e cookie sem `SameSite` → página HTML de prova que só *demonstra*
  a requisição (em conta de teste).
- **Open redirect**: `?next=https://evil.example`.
- **GraphQL**: introspecção ligada (`{__schema{types{name}}}`), queries sem autorização por campo.
- **APIs**: endpoints `/v1` antigos ainda ativos, mass assignment (`"isAdmin": true` no cadastro).
