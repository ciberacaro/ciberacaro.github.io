---
title: "Análise de logs do zero: detetar brute force e scanners em cinco minutos"
date: 2026-05-18 12:30:00 +0100
categories: [Notes, Tools]
tags: [logs, forensics, brute-force, detection, python]
pin: false
permalink: /posts/analise-de-logs-brute-force/
---

> English version: [Log analysis from scratch: spotting brute force and scanners in five minutes](/posts/log-analysis-brute-force/).
{: .prompt-info }

A primeira vez que olhamos para um log de acesso de um servidor com algum tamanho — umas centenas de milhares de linhas é o normal — pode dar a sensação de que o sinal está invisível. Não há forma fácil de olhar para um ficheiro de texto plano e ver onde estão os problemas. Podes fazer `grep`, mas ainda não sabes do que andas à procura.

Este post percorre uma pequena ferramenta em Python, o `log_parser.py`, e os três padrões que ela procura. Os padrões interessam mais do que a ferramenta: a partir do momento em que sabes o que procurar, fazes isto com `grep`, com `awk`, com Splunk, ou com a SIEM que estiver em uso no dia.

## O que a ferramenta extrai

Para cada linha do log, o parser tira as coisas que normalmente interessam:

- Endereços IPv4 e IPv6 (com validação de octetos)
- Endereços de email
- Nomes de domínio
- URLs e caminhos HTTP
- Status codes HTTP
- Timestamps em três formatos comuns (ISO 8601, Apache, syslog)

Para logs de acesso do Apache e do nginx existe uma regex de *fast-path* que extrai IP + timestamp + método + caminho + status numa só correspondência, o que interessa quando estás a processar um ficheiro de vários gigabytes.

O output ordena cada categoria — top 10 IPs por número de pedidos, top 10 caminhos, top 5 emails — e classifica cada IP como privado, público, *loopback* ou *link-local*. Essa última parte sozinha já chega muitas vezes para revelar uma má configuração: um serviço público não devia estar a registar pedidos a partir de `10.x.x.x` a não ser que tenhas uma razão concreta.

## Padrão 1: brute force

O brute force tem uma forma muito reconhecível num log. O mesmo IP faz muitos pedidos, a maioria recebe uma resposta 4xx (401 Unauthorized ou 403 Forbidden), e quase todos atingem um pequeno conjunto de URLs (um formulário de login, um painel de administração, um `/wp-login.php`).

O limiar da ferramenta é configurável — por omissão sinaliza qualquer IP que tenha dez ou mais respostas 4xx. Num servidor com tráfego razoável, costuma compensar subir para 25 ou 50, caso contrário utilizadores normais com favoritos antigos disparam o alerta. Numa aplicação interna com pouco tráfego, o valor por omissão chega.

```bash
$ tools/log_parser.py access.log --bruteforce 25
```

Num cenário real, o finding fica assim:

```
Padrões suspeitos (3):
  ✗ Suspeita de brute-force: 185.220.101.5 → 187 respostas 4xx
  ✗ Suspeita de brute-force: 91.234.56.78  → 54 respostas 4xx
  ...
```

187 respostas falhadas a partir do mesmo IP não é um engano da parte do utilizador. O passo seguinte é ver para onde estavam a apontar (quase sempre uma página de login), que user agent usaram (quase sempre algo obviamente automatizado), e se algum dos seus 5xx ou raros 2xx sugere que a tentativa teve sucesso.

## Padrão 2: atividade de scanner

Um scanner tem outra forma: um IP a tocar em muitos caminhos diferentes, a maioria a devolver 404. Quem quer que seja está a enumerar — a correr uma wordlist contra o teu servidor para encontrar painéis de admin, ficheiros de backup, ficheiros `.env` expostos, e o resto da lista do costume.

A ferramenta sinaliza qualquer IP que toque em mais de 50 caminhos únicos. Na prática isto apanha scanners automatizados — `nikto`, `gobuster`, a fase de recon de um worm oportunista — muito antes de chegarem a algum sítio interessante.

```
✗ Scanner: 91.234.56.78 → 124 caminhos únicos (provável scanner)
```

Costuma dar para ver este padrão a chegar, porque a taxa de pedidos é demasiado rápida para um humano. Quinhentos pedidos em dois minutos não é alguém a navegar.

## Padrão 3: caminhos sensíveis

Este é sobre sinal absoluto, não relativo. Há caminhos que praticamente nunca deviam aparecer num log saudável:

- `/.env`
- `/.git/config`
- `/wp-admin/`
- `/backup.zip` ou ficheiros `*.bak`
- `/admin/`
- `/phpmyadmin/`

A ferramenta mantém um padrão regex para estes e conta quantas vezes alguma linha do log lhes bate. Se `/.env` aparece 45 vezes, não é porque 45 utilizadores legítimos diferentes resolveram digitar `.env` no browser. É um ou mais scanners a tentar levantar as tuas variáveis de ambiente.

```
✗ Acessos a caminhos sensíveis: /.env (45×), /.git/config (12×), /wp-admin/ (8×)
```

Dois passos seguintes que vale a pena fazer: confirmar que os caminhos não existem mesmo (um `200` em `/.env` é um problema sério, não uma curiosidade), e ver se os IPs que lhes bateram coincidem com os findings de brute force e scanner — normalmente coincidem.

## Um exemplo prático

Um fragmento de log de acesso:

```
185.220.101.5 - - [15/Jan/2026:14:32:18 +0000] "GET /wp-login.php HTTP/1.1" 401 4571
185.220.101.5 - - [15/Jan/2026:14:32:19 +0000] "POST /wp-login.php HTTP/1.1" 401 4571
185.220.101.5 - - [15/Jan/2026:14:32:20 +0000] "POST /wp-login.php HTTP/1.1" 401 4571
91.234.56.78 - - [15/Jan/2026:14:33:01 +0000] "GET /.env HTTP/1.1" 404 134
91.234.56.78 - - [15/Jan/2026:14:33:01 +0000] "GET /.git/config HTTP/1.1" 404 134
91.234.56.78 - - [15/Jan/2026:14:33:02 +0000] "GET /backup.zip HTTP/1.1" 404 134
```

Mesmo com seis linhas, os dois padrões são visíveis: um IP a fazer brute-force ao WordPress, outro a varrer caminhos sensíveis. Num log real não os vês com este nível de limpeza — ficam escondidos por baixo de milhares de pedidos normais — mas a estrutura por baixo é a mesma.

## O que fazer com os findings

Três passos imediatos, por ordem:

1. **Bloquear a origem.** Se a firewall, CDN ou WAF aceitam regras de IP, é a ação mais barata. O Fail2ban automatiza isto para SSH e alguns outros serviços.
2. **Investigar as falhas.** Algum dos 4xx tornou-se 2xx? O scanner encontrou alguma coisa? Faz `grep` dos caminhos sensíveis no log inteiro à procura de status `200`.
3. **Empurrar os dados para uma SIEM se tiveres uma.** O output JSON (`--json`) está pensado para ser canalizado para outra ferramenta. A estrutura é estável: `ip_stats`, `url_stats`, `email_stats`, `date_range`, `suspicious`.

```bash
$ tools/log_parser.py access.log --json | \
    jq '.suspicious[] | select(.kind == "bruteforce")'
```

## Onde encontrar

O [`tools/log_parser.py`](https://github.com/ciberacaro/ciberacaro.github.io/blob/main/tools/log_parser.py) é Python 3.8+ stdlib pura — sem dependências externas, faz streaming linha a linha por isso aguenta logs de vários gigabytes sem problema.

```bash
git clone https://github.com/ciberacaro/ciberacaro.github.io.git
cd ciberacaro.github.io
python3 tools/log_parser.py /caminho/para/access.log
```

---

*Esta ferramenta mapeia diretamente para o currículo do CET em Cibersegurança, unidades UC01481 (scripts em cibersegurança) e UC01482 (normalização e filtragem de logs). Se estás a seguir esse programa, é uma implementação de referência útil para as técnicas que ambas as unidades descrevem.*
