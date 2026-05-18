---
title: "Reconhecimento web do zero, só com a stdlib do Python"
date: 2026-05-18 12:00:00 +0100
categories: [Notes, Tools]
tags: [recon, web, python, dns, tls, http-headers]
pin: false
permalink: /posts/recon-web-stdlib-python/
---

> English version: [Web reconnaissance from scratch, with nothing but the Python standard library](/posts/web-recon-stdlib-python/).
{: .prompt-info }

Quando começamos a olhar para a superfície web de um alvo, costumam ser sempre as mesmas cinco coisas: uma lista dos subdomínios, uma auditoria dos *security headers*, o certificado TLS, as *flags* dos cookies e os registos DNS. Existe uma pilha de ferramentas maduras para cada uma — `subfinder`, `nmap`, `testssl.sh`, `dig`, e por aí fora — mas costurá-las num relatório único leva tempo e exige uma instalação a funcionar para cada uma delas.

Queria algo que conseguisse correr em qualquer máquina com Python 3.8 ou superior, sem `pip install`, sem Homebrew, sem nada para configurar. O resultado é o `recon.py`, um orquestrador que corre cinco ferramentas mais pequenas em sequência e produz um único relatório em Markdown.

Este post percorre o que faz, o que o output revela e por onde se pode evoluir a partir daí.

## A pipeline

O `recon.py` não tem rasgo de génio nenhum — compõe cinco ferramentas que já existem na mesma toolchain:

```
subfinder.py          → descobre subdomínios via crt.sh + wordlist pequena
check_headers.py      → audita security headers (HSTS, CSP, X-Frame, etc.)
tls_inspect.py        → vai buscar o cert, enumera versões TLS aceites
cookie_check.py       → verifica flags do Set-Cookie (HttpOnly, Secure, SameSite)
dns_records.py        → A/AAAA/MX/NS/TXT/CAA + auditoria SPF/DMARC + AXFR
```

Cada uma é stdlib pura. O orquestrador corre-as, captura o output JSON e renderiza um relatório único em Markdown.

## Correr a ferramenta

A invocação mais pequena:

```bash
$ tools/recon.py example.com
```

Para um alvo com vários subdomínios, podes pedir que avalie os top N (por omissão 10):

```bash
$ tools/recon.py example.com --top 5 --output relatorio.md --lang pt
```

A flag `--lang pt` afeta o output de todas as sub-ferramentas — útil quando a audiência do relatório fala português.

## O aspeto do output

Exemplo truncado de uma execução real:

```
## Reconhecimento: example.com

### Subdomínios (12 encontrados, top 5 resolvidos)
- www.example.com           → 93.184.216.34
- api.example.com           → 93.184.216.50
- mail.example.com          → 93.184.216.60
- dev.example.com           → 10.0.0.1   ← IP interno exposto publicamente
- old.example.com           → CNAME old-example.herokudns.com

### Security headers (por subdomínio)
| Host | Score | Notas |
|------|-------|-------|
| www.example.com | 5/9 | Falta CSP, Permissions-Policy |
| api.example.com | 3/9 | Falta HSTS, CSP, X-Frame, COOP |

### Certificados TLS
- www: Let's Encrypt, expira 2024-09-01 (143 dias), TLS 1.0 ✗ aceite
- api: Let's Encrypt, expira 2024-09-01, só TLS 1.2/1.3 ✓

### Cookies
- www.example.com  → `session=...` falta SameSite, Secure OK
- api.example.com  → sem Set-Cookie

### Registos DNS
- A:    93.184.216.34
- MX:   mail.example.com
- SPF:  ✓ presente (`v=spf1 ~all`)
- DMARC: ✗ em falta — qualquer um pode forjar o From neste domínio
- AXFR: recusado por todos os NS (bom sinal)
```

Só com este relatório já consegues escrever o primeiro parágrafo da lista de findings.

## Ler o relatório com olho crítico

Algumas coisas que vale a pena assinalar na primeira leitura:

**IPs internos no DNS.** Um subdomínio a resolver para `10.x.x.x` ou `192.168.x.x` ou é um erro de configuração ou é um *split-horizon* deliberado. De qualquer forma é ruído para um recrutador e sinal para um atacante. A linha `dev.example.com → 10.0.0.1` no exemplo acima é um padrão real; já o vi várias vezes.

**CNAME a apontar para um serviço externo.** `old-example.herokudns.com` é um candidato a *subdomain takeover* se a aplicação Heroku tiver sido apagada mas o CNAME tiver ficado para trás. Merece uma verificação à parte com o `subdomain_takeover.py` — ver o [post seguinte](/posts/subdomain-takeover-cnames-orfaos/) sobre isto.

**TLS 1.0 aceite.** Os browsers deixaram de o negociar em 2020, mas um servidor que continue a oferecê-lo está exposto a clientes legados e a quem use um *downgrade* tipo BEAST. Vale como finding mesmo que nenhum utilizador atual seja afetado.

**DMARC em falta.** O SPF sozinho não impede a mensagem de chegar — apenas deixa ao recetor a decisão. Sem DMARC, o recetor não tem nenhuma política de enforcement para aplicar, e o header From pode ser o que o atacante quiser.

## O que esta ferramenta não é

Este orquestrador **não** substitui uma suite de recon a sério. Não vai:

- Fazer crawl da aplicação à procura de rotas como o Burp / ZAP fazem
- Correr verificações autenticadas
- Detetar comportamento de WAF para além do que já vem na resposta HTTP
- Fazer brute-force de diretórios — para isso usa o [`path_scan.py`](https://github.com/ciberacaro/ciberacaro.github.io/blob/main/tools/path_scan.py)

Aquilo em que é bom: um *first sweep* rápido e repetível, que transforma uma página em branco num ponto de partida estruturado. Combina-o com o `path_scan.py`, com o `subdomain_takeover.py` e com o resto da toolchain conforme o que o relatório revelar.

## Onde encontrar

As 27 ferramentas vivem no diretório [`tools/`](https://github.com/ciberacaro/ciberacaro.github.io/tree/main/tools) deste repositório, com um [tutorial bilingue de fundo](https://github.com/ciberacaro/ciberacaro.github.io/blob/main/tools/HOWTO.txt) para cada uma.

```bash
git clone https://github.com/ciberacaro/ciberacaro.github.io.git
cd ciberacaro.github.io
python3 tools/recon.py o-teu-alvo.example
```

Não há passo de instalação. O único pré-requisito é Python 3.8 ou superior.

---

*Se encontrares um problema real numa das ferramentas, ou quiseres comparar notas sobre o fluxo de recon, a forma mais fácil de me contactares é pelo [repositório no GitHub](https://github.com/ciberacaro/ciberacaro.github.io).*
