# Relatório de Segurança — Laboratório Demo — Rede Interna

**Data:** 2026-11-10 · **Autorização:** Laboratório próprio, rede isolada 10.10.10.0/28

## Resumo

O teste avaliou a rede de laboratório **10.10.10.0/28** (exceto o gateway 10.10.10.1). Foram encontrados **2 problemas críticos/altos que, juntos, dão acesso total aos dados da intranet** sem precisar de nenhuma senha:

- o **Redis** responde a qualquer um na rede, sem autenticação;
- o **FTP anônimo** entrega um backup com a senha do banco de dados.

Recomendamos, nesta ordem: fechar o Redis e o FTP anônimo hoje, trocar a senha do banco e, em seguida, desativar o SMBv1 e exigir assinatura SMB no servidor de arquivos.

| Severidade | Qtde |
|---|---|
| Crítica | 1 |
| Alta | 2 |
| Média | 2 |
| Baixa | 0 |
| Informativa | 0 |

## Escopo

- `10.10.10.0/28`
- `*.lab.local`

**Fora do escopo:**
- `10.10.10.1`

## Achados

### SNT-002 · Redis sem autenticação exposto na rede

**Severidade:** Crítica · CVSS 9.8 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) · **Alvo:** `10.10.10.5:6379`

**Descrição:** O Redis 5.0.7 em **10.10.10.5:6379** aceita comandos sem senha (`requirepass` não definido) e escuta em todas as interfaces.

**Impacto:** Leitura e alteração de todos os dados em cache (incluindo sessões da intranet). Com `CONFIG SET dir`, um atacante pode gravar arquivos no servidor e chegar a execução de código.

**Recomendação:** - Definir `requirepass` (ou ACLs no Redis 6+)
- `bind 127.0.0.1` e `protected-mode yes`
- Bloquear a porta 6379 no firewall
- Renomear/desabilitar `CONFIG`, `FLUSHALL` e `DEBUG`

**Evidência:**
```
$ redis-cli -h 10.10.10.5 INFO server
# Server
redis_version:5.0.7
redis_mode:standalone
os:Linux 5.4.0-216-generic x86_64

$ redis-cli -h 10.10.10.5 DBSIZE
(integer) 1842
```

**Referências:**
- https://redis.io/docs/latest/operate/oss_and_stack/management/security/

### SNT-001 · FTP anônimo expõe backup de configuração com credenciais

**Severidade:** Alta · CVSS 7.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`) · **Alvo:** `10.10.10.5:21`

**Descrição:** O vsftpd aceita login `anonymous` e o diretório `backups/` contém `intranet-config.bak`, legível por qualquer pessoa.

**Impacto:** O arquivo traz usuário e senha do banco de dados da intranet em texto puro.

**Recomendação:** - Desabilitar `anonymous_enable` no vsftpd
- Remover backups do diretório público
- **Trocar a senha do banco**: ela deve ser considerada comprometida

**Evidência:**
```
ftp> login anonymous
230 Login successful.
ftp> ls backups
-rw-r--r--  1 ftp ftp  2311 intranet-config.bak

(conteúdo omitido do relatório — credencial guardada em loot/, fora do controle de versão)
```

### SNT-003 · SMBv1 habilitado

**Severidade:** Alta · CVSS 7.5 (`CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`) · **Alvo:** `10.10.10.7:445`

**Descrição:** O Samba em 10.10.10.7 ainda negocia o dialeto **NT LM 0.12 (SMBv1)**.

**Recomendação:** No smb.conf: `server min protocol = SMB2_10`. Reinicie o serviço.

**Evidência:**
```
nmap --script smb-protocols -p445 10.10.10.7
  NT LM 0.12 (SMBv1) [dangerous, but default]
```

**Referências:**
- https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3

### SNT-006 · Painel da intranet sem limite de tentativas de login

**Severidade:** Média · CVSS 5.3 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) · **Alvo:** `http://10.10.10.5/login`

**Descrição:** O formulário de login aceitou 50 tentativas seguidas com senha errada sem bloqueio, atraso ou CAPTCHA (teste limitado a 50 tentativas, conforme as regras).

**Recomendação:** Bloqueio progressivo por conta/IP, atraso exponencial e MFA para contas administrativas.

**Referências:**
- https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/

### SNT-004 · Assinatura SMB não exigida

**Severidade:** Média · CVSS 4.2 (`CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`) · **Alvo:** `10.10.10.7:445`

**Descrição:** Permite ataques de relay NTLM na rede interna.

**Recomendação:** No smb.conf: `server signing = mandatory`.

**Evidência:**
```
nmap: 445/tcp open microsoft-ds Samba smbd 4.6.2
```
