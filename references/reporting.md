# Escrevendo achados e relatório

Um achado bom responde: **o que é, onde está, como provar, o que acontece se alguém explorar, como corrigir.**

## Anatomia de um achado (`report.py add`)

| Campo | Bom | Ruim |
|---|---|---|
| `--title` | "IDOR permite ler pedidos de outros clientes" | "Vulnerabilidade na API" |
| `--target` | `https://loja.exemplo.com/api/pedidos/{id}` | `loja.exemplo.com` |
| `--description` | o mecanismo técnico, em 2–4 frases | copiar a definição da OWASP |
| `--impact` | consequência para o negócio: "qualquer cliente logado vê nome, CPF e endereço dos outros 40 mil clientes" | "perda de confidencialidade" |
| `--evidence` | requisição + resposta mínimas, reproduzíveis, com dados sensíveis mascarados | print sem contexto |
| `--remediation` | correção concreta para a stack deles + como validar | "sanitize as entradas" |
| `--ref` | OWASP, CWE, CVE, documentação oficial | — |

## CVSS 3.1 — vetores de referência

`python scripts/cvss.py "<vetor>"` mostra nota e explicação.

| Cenário típico | Vetor | Nota |
|---|---|---|
| RCE sem autenticação | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 |
| SQLi com leitura do banco, sem login | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | 7.5 |
| SQLi que exige login comum | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | 8.1 |
| IDOR leitura de dados de outros usuários | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 |
| XSS refletido | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 |
| XSS armazenado (usuário logado injeta) | `AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | 5.4 |
| CSRF em ação sensível | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | 6.5 |
| Sem limite de tentativas no login | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | 5.3 |
| Escalação local para root | `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 7.8 |
| Cabeçalho de segurança ausente | sem CVSS: severidade Baixa/Informativa | — |

Dicas: `S:C` (escopo alterado) quando o impacto sai do componente vulnerável (XSS afeta o navegador da
vítima; fuga de container afeta o host). Não infle: se precisa de login, `PR:L`; se a vítima precisa clicar, `UI:R`.

## Resumo executivo (`engagement/summary.md`)

Para quem não é técnico. 3–6 linhas:
1. O que foi testado e quando.
2. A conclusão em uma frase ("um atacante sem senha consegue acessar todos os dados da intranet").
3. Os 2–3 problemas que mais importam, em linguagem simples.
4. O que fazer primeiro (ordem de prioridade).

## Bug bounty

Siga o formato da plataforma (HackerOne/Bugcrowd/Intigriti): título, resumo, passos para reproduzir
numerados, prova de conceito, impacto, sugestão de correção. Um achado por relatório. Nunca teste fora das
regras do programa nem acesse dados de usuários reais além do mínimo para provar (use suas próprias contas).
