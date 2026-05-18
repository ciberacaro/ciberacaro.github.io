---
title: "Subdomain takeover: encontrar os CNAMEs órfãos que toda a gente esquece"
date: 2026-05-18 12:15:00 +0100
categories: [Notes, Tools]
tags: [subdomain-takeover, dns, cname, recon, bug-bounty]
pin: false
permalink: /posts/subdomain-takeover-cnames-orfaos/
---

> English version: [Subdomain takeover: finding the dangling CNAMEs everyone forgets](/posts/subdomain-takeover-dangling-cnames/).
{: .prompt-info }

Um *subdomain takeover* é o tipo de bug que soa demasiado simples para ser real. Uma organização cria um subdomínio — digamos `campanha-marketing.example.com` — e aponta-o para um serviço externo como GitHub Pages, Heroku ou um *bucket* S3. A campanha acaba. Alguém apaga o site no GitHub Pages, ou a *app* no Heroku, ou o *bucket* S3. O registo DNS fica.

Agora qualquer pessoa que consiga registar um novo site no GitHub Pages (ou *app* no Heroku, ou *bucket* S3) com o nome certo pode servir conteúdo a partir de `campanha-marketing.example.com`, com toda a confiança que o domínio pai carrega — incluindo, em muitos casos, cookies e acesso CORS.

É um bug fácil de introduzir, muito fácil de não notar, e uma entrada recorrente na HackerOne, Bugcrowd e plataformas semelhantes.

## Como é que isto acontece, na prática

O padrão é sempre o mesmo:

1. Uma equipa de marketing ou engenharia cria `subdominio.example.com` apontando para `oprojeto.github.io` (ou qualquer outro serviço).
2. Meses depois, a equipa apaga o projeto do serviço.
3. Ninguém remove o registo DNS.

O CNAME passa a apontar para um nome que resolve mas está "não reclamado" — o serviço continua a servir alguma coisa, mas serve uma página de erro que diz, na prática, *"este site não está configurado"*. Um atacante que registe `oprojeto` na mesma plataforma passa a controlar `subdominio.example.com`.

## O que se pode fazer com um destes

O impacto depende da confiança que o domínio pai carrega:

- **Roubo de cookies** se o *scope* do cookie estiver definido como `.example.com`.
- **Bypass de CORS** se a aplicação confiar em origens `*.example.com`.
- **Phishing** com um URL perfeitamente legítimo.
- **Dano de marca** — conteúdo no teu domínio que tu não escreveste.
- **Bypass do *HSTS preload pinning*** em certas configurações.

Algumas destas precisam de outras condições alinhadas, mas a *posição* — servir conteúdo a partir de um domínio de confiança — é o ponto de apoio.

## Como encontrar

Precisas de três coisas:

1. **Uma lista de subdomínios.** Ou enumeras (logs de certificados via crt.sh, *brute force*, DNS passivo) ou já tens uma.
2. **O CNAME de cada subdomínio.** Uma query DNS, nada de especial.
3. **Uma forma de saber se o alvo do CNAME está "não reclamado".** Cada serviço tem uma página de erro reconhecível; bater a resposta contra uma fingerprint conhecida é suficiente.

O `subdomain_takeover.py` faz as três:

```bash
$ tools/subdomain_takeover.py example.com
```

Enumera automaticamente via crt.sh, resolve CNAMEs por UDP/53 raw e verifica cada um contra 16 fingerprints de serviços — GitHub Pages, Heroku, Netlify, AWS S3, Azure, Fastly, Shopify, Tumblr, WP Engine e outros.

Para um domínio em que já tens uma lista de subdomínios:

```bash
$ tools/subfinder.py example.com --json | jq -r '.resolved[].host' | \
    tools/subdomain_takeover.py example.com --subdomains -
```

## O aspeto de um resultado vulnerável

Output real (com partes sensíveis a esconder):

```
Domínio: example.com
Subdomínios verificados: 14

Vulneráveis (2):
  campanha-marketing.example.com
    CNAME  → campanha-marketing-2022.github.io
    Serviço: GitHub Pages
    Estado: VULNERÁVEL — serviço não registado detetado

  old.example.com
    CNAME  → old-example-app.herokudns.com
    Serviço: Heroku
    Estado: VULNERÁVEL — serviço não registado detetado
```

A combinação que sinaliza um *finding* é *(padrão CNAME coincide) E (corpo da resposta coincide com a fingerprint de "não registado")*. Um CNAME a apontar para `*.github.io` não é, por si só, uma vulnerabilidade — só é vulnerabilidade quando o site do GitHub Pages já não existe.

## O que NÃO fazer

Quando encontrares um subdomínio realmente vulnerável:

- **Não registes tu o serviço.** Mesmo com boa intenção, isso constitui acesso não autorizado. Em Portugal, a Lei do Cibercrime (Lei n.º 109/2009) trata o acesso indevido a sistemas informáticos como crime, e "ia devolver" não é uma defesa.
- **Reporta pelo canal correto.** Se a organização publicar um `security.txt` (em `/.well-known/security.txt`), aí diz para onde enviar reports de vulnerabilidades. Senão, procura um programa de VDP ou bug bounty.
- **Documenta o finding antes de reportar.** Tira um screenshot, guarda a resposta DNS, guarda a fingerprint HTTP. Queres que o report seja reproduzível sem voltar a atuar sobre o subdomínio vulnerável.

## Limitações desta abordagem

Três coisas que a ferramenta não faz:

- **Serviços muito recentes.** As fingerprints envelhecem. Aparecem novos PaaS, mudam páginas de erro antigas. A lista atual de 16 cobre os casos comuns mas não é exaustiva — a referência da comunidade é o `can-i-take-over-xyz` no GitHub, vale a pena consultar se estás a caçar a sério.
- **CNAMEs *wildcard*.** Se `*.example.com` apontar para um serviço, o comportamento de resolução pode ser imprevisível.
- **Serviços autenticados.** Alguns takeovers (Azure DNS, certas configurações Fastly) requerem passos adicionais que a ferramenta não consegue automatizar.

Mas para uma auditoria de perímetro de uma organização, ou como ponto de partida num bug bounty, isto apanha os casos fáceis de forma fiável.

## Onde encontrar

O [`tools/subdomain_takeover.py`](https://github.com/ciberacaro/ciberacaro.github.io/blob/main/tools/subdomain_takeover.py) é Python 3.8+ stdlib pura — sem `pip install`, sem biblioteca DNS externa.

```bash
git clone https://github.com/ciberacaro/ciberacaro.github.io.git
cd ciberacaro.github.io
python3 tools/subdomain_takeover.py o-teu-alvo.example
```

Combina-o com o [`recon.py`](/posts/recon-web-stdlib-python/) para o panorama mais alargado.

---

*Leitura adicional: o [feed Hacktivity da HackerOne](https://hackerone.com/hacktivity?type=public) tem centenas de reports divulgados com a tag "Subdomain takeover" — os writeups são um dos melhores materiais de treino gratuitos para apanhar o padrão.*
