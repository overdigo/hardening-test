# 🛡️ HTTP Header Security Testing Suite

<p align="center">
  <img src="https://img.shields.io/badge/version-6.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/bash-5.0%2B-orange.svg" alt="Bash">
  <img src="https://img.shields.io/badge/tests-2700%2B-brightgreen.svg" alt="Tests">
  <img src="https://img.shields.io/badge/categories-65%2B-purple.svg" alt="Categories">
  <img src="https://img.shields.io/badge/modules-4-red.svg" alt="Modules">
</p>

<p align="center">
  <strong>Uma ferramenta abrangente para testar a segurança de cabeçalhos HTTP, protocolos, portas expostas e vulnerabilidades web em servidores.</strong>
</p>

---

## 📋 Índice

- [Sobre](#-sobre)
- [Funcionalidades](#-funcionalidades)
- [Requisitos](#-requisitos)
- [Instalação](#-instalação)
- [Uso](#-uso)
- [Categorias de Testes](#-categorias-de-testes)
- [Novidades v5.0.0](#-novidades-v500)
- [Exemplos](#-exemplos)
- [Interpretando Resultados](#-interpretando-resultados)
- [Configuração do Servidor](#-configuração-do-servidor)
- [Contribuindo](#-contribuindo)
- [Licença](#-licença)

---

## 📖 Sobre

O **HTTP Header Security Testing Suite** é uma ferramenta de linha de comando projetada para avaliar a robustez das configurações de segurança de servidores web. Ela simula diversos tipos de ataques através de cabeçalhos HTTP maliciosos, testa protocolos HTTP/1.0, 1.1, 2 e 3, verifica portas de serviços expostos e realiza testes abrangentes de vulnerabilidades web.

### Por que usar?

- ✅ Verificar configurações de WAF (Web Application Firewall)
- ✅ Testar regras de segurança do Nginx/Apache
- ✅ Validar proteções contra injeções (SQL, XSS, Command, XSLT, SSI/ESI, CSS, Email)
- ✅ Auditar conformidade com boas práticas de segurança
- ✅ Identificar vulnerabilidades antes de atacantes
- ✅ Testar técnicas de bypass de filtros e WAF
- ✅ Verificar versões de protocolo HTTP suportadas
- ✅ Detectar portas de serviços expostas indevidamente (MySQL, Redis, etc.)
- ✅ Testar ataques avançados (Cache Poisoning, HTTP Smuggling, H2C, etc.)
- ✅ **🆕 Verificar proteções contra Clickjacking**
- ✅ **🆕 Auditar Security Headers essenciais**
- ✅ **🆕 Testar segurança de cookies e sessões**
- ✅ **🆕 Detectar painéis admin e arquivos sensíveis expostos**
- ✅ **🆕 Testar proteção CSRF**
- ✅ **🆕 Testar bypass de erro 403**
- ✅ **🆕 Testar ataques JWT (none algorithm, claim tampering)**
- ✅ **🆕 Testar NoSQL Injection (MongoDB, Redis)**
- ✅ **🆕 Testar LDAP/XPath Injection**
- ✅ **🆕 Testar Insecure Deserialization (PHP, Java, Python, .NET)**
- ✅ **🆕 Testar File Upload bypass**
- ✅ **🆕 Testar Open Redirect**
- ✅ **🆕 Testar IDOR e Privilege Escalation**
- ✅ **🆕 Testar Prototype Pollution**
- ✅ **⚡ Módulos especializados para XSS, SQL Injection, Command Injection e File Inclusion (1050+ testes)**

### 🧩 Arquitetura Modular (v6.0.0)

A versão 6.0 introduz **4 módulos especializados** que expandem drasticamente a cobertura de testes:

| Módulo | Testes | Arquivo | README |
|--------|--------|---------|--------|
| **🎨 XSS Tester** | 250+ | `xss-tester.sh` | [XSS-TESTER-README.md](XSS-TESTER-README.md) |
| **💉 SQLi Tester** | 300+ | `sqli-tester.sh` | [SQLI-TESTER-README.md](SQLI-TESTER-README.md) |
| **⚙️ CMDi Tester** | 250+ | `cmdi-tester.sh` | [CMDI-TESTER-README.md](CMDI-TESTER-README.md) |
| **📁 LFI/RFI Tester** | 250+ | `lfi-rfi-tester.sh` | [LFI-RFI-TESTER-README.md](LFI-RFI-TESTER-README.md) |

Cada módulo é:
- ✅ **Independente**: Pode ser executado separadamente
- ✅ **Documentado**: README completo com técnicas, exemplos e prevenção
- ✅ **Baseado em PayloadsAllTheThings**: Usar payloads community-driven
- ✅ **Organizado**: Categorias lógicas para testes focados
- ✅ **Extensível**: Fácil adicionar novos payloads

```bash
# Executar módulo específico
./head-test.sh -u https://example.com -c xss
./head-test.sh -u https://example.com -c sqli
./head-test.sh -u https://example.com -c cmdi
./head-test.sh -u https://example.com -c lfi
```

---

## ✨ Funcionalidades

### 🎯 2700+ Testes de Segurança

| Categoria | Quantidade | Descrição |
|-----------|------------|-----------|
| **⚡ XSS (Módulo)** | **250+** | **Cross-Site Scripting - 10 categorias especializadas** |
| **⚡ SQLi (Módulo)** | **300+** | **SQL Injection - 10 categorias incluindo bypass de WAF** |
| **⚡ CMDi (Módulo)** | **250+** | **Command Injection - RCE, bypass, reverse shell** |
| **⚡ LFI/RFI (Módulo)** | **250+** | **File Inclusion - LFI, RFI, wrappers, LFI-to-RCE** |
| Métodos HTTP | 30 | GET, POST, PUT, DELETE, WebDAV, métodos customizados |
| Cookies Maliciosos | 40 | XSS, SQL Injection, overflow, encoding attacks |
| Query String | 50 | SQL Injection, XSS, LFI, RFI, CMDi |
| URI Maliciosa | 50 | WordPress, arquivos sensíveis, backups |
| Header Injection | 20 | CRLF, X-Forwarded, override attacks |
| Content-Type | 20 | XXE, XSS, MIME type attacks |
| Accept-Encoding | 20 | Encoding attacks, overflow |
| X-Forwarded-For | 20 | IP spoofing, bypass de WAF |
| Range Header | 20 | DoS via range requests |
| HTTP Smuggling | 20 | CL.TE, TE.CL, header obfuscation |
| Nginx Attacks | 20 | Path traversal, buffer overflow, config exposure |
| PHP Attacks | 20 | Wrappers, deserialization, code injection |
| Database Attacks | 20 | MySQL/MariaDB specific SQLi |
| SSRF Attacks | 15 | Cloud metadata, internal networks |
| Rate Limiting | 10 | Brute force, login protection |
| Injection Tests | 15 | Template, LDAP, XML injection |
| Path/URL Bypass | 70+ | Null byte, encoding, protocol switch |
| HTTP Protocols | 20 | HTTP/1.0, 1.1, 2 e 3 version tests |
| Hop-by-Hop Headers | 25 | Connection header abuse, bypass |
| Cache Poisoning | 30 | Cache key manipulation, deception |
| Connection Contamination | 20 | Pipeline pollution, queue poisoning |
| Response Smuggling | 25 | Response splitting, desync |
| H2C Smuggling | 20 | HTTP/2 Cleartext smuggling |
| SSI/ESI Injection | 30 | Server/Edge Side Includes |
| CDN/Cloudflare Bypass | 25 | Origin IP discovery |
| XSLT Injection | 20 | XSLT server-side injection |
| WAF Bypass | 35 | Encoding, method, path bypass |
| Exposed Ports | 45 | MySQL, Redis, Docker, K8s, etc. |
| **🆕 403 Bypass** | **100+** | IP spoofing headers, port bypass, URL encoding |
| **🆕 Clickjacking** | **10** | X-Frame-Options, CSP frame-ancestors |
| **🆕 Security Headers** | **15** | Headers essenciais, information disclosure |
| **🆕 Session Security** | **15** | Cookie flags (HttpOnly, Secure, SameSite) |
| **🆕 CSS Injection** | **12** | Expression, @import, exfiltration |
| **🆕 Email Injection** | **15** | SMTP/IMAP header injection |
| **🆕 Default Credentials** | **50+** | Admin panels, sensitive files |
| **🆕 Account Enumeration** | **10** | WordPress, login enumeration |
| **🆕 Format String** | **12** | %s, %x, %n injection |
| **🆕 CSRF Protection** | **15** | Token bypass, SameSite verification |
| **🆕 JWT Attacks** | **30** | none algorithm, claim tampering, kid/jku injection |
| **🆕 NoSQL Injection** | **30** | MongoDB, CouchDB, Redis injection |
| **🆕 LDAP Injection** | **20** | Filter injection, blind LDAP |
| **🆕 XPath Injection** | **20** | Node extraction, blind XPath |
| **🆕 Deserialization** | **30** | PHP, Java, Python Pickle, .NET, YAML |
| **🆕 File Upload** | **30** | Extension bypass, MIME spoofing |
| **🆕 Open Redirect** | **25** | URL redirect bypass, encoded URLs |
| **🆕 IDOR/Priv Esc** | **30** | IDOR, mass assignment, GraphQL authz |
| **🆕 Time-based Blind** | **20** | SQL SLEEP, NoSQL sleep, CMDi delays |
| **🆕 Prototype Pollution** | **20** | __proto__, constructor pollution |
| **🆕 WAF Evasion** | **150+** | Bypass techniques for Cloudflare, Imperva, ModSec, AWS WAF, F5, Sucuri, Wordfence |
| **🆕 Obfuscated Payloads** | **140+** | Case toggling, URL/double encoding, Unicode, comments, junk chars, wildcards |
| User-Agents | 100+ | Bots maliciosos, scrapers, scanners |
| Referers | 100+ | SPAM, SEO Black Hat, Injection |
| Fake Bots | 10 | Impostores de Googlebot/Bingbot |

### 🛠️ Recursos

- **Modo Verbose**: Detalhes de cada requisição
- **Exportação de Resultados**: Salva em arquivo para análise
- **Seleção de Categorias**: Execute apenas os testes necessários
- **Filtros de Resultados**: Mostra apenas PASS, FAIL ou todos
- **15 User-Agents**: Desktop, Mobile, Tablets de diferentes navegadores
- **Resultados Coloridos**: Fácil identificação de falhas
- **Resumo Estatístico**: Taxa de sucesso e métricas
- **Listas Externas**: Suporte a listas customizadas
- **Port Scanning**: Verificação de portas sensíveis com netcat
- **Protocol Testing**: Suporte a HTTP/1.0, 1.1, 2 e 3
- **Recomendações Integradas**: Dicas de hardening após cada categoria

---

## 📦 Requisitos

- **Bash** 4.0 ou superior
- **curl** (com suporte a HTTP/2, idealmente HTTP/3)
- **netcat (nc)** - para testes de portas expostas
- **Sistema operacional**: Linux, macOS, WSL

### Verificar requisitos:

```bash
bash --version
curl --version
nc -h
```

### Instalação de dependências (Debian/Ubuntu):

```bash
sudo apt update
sudo apt install curl netcat-openbsd
```

---

## 🚀 Instalação

### Opção 1: Clone do repositório

```bash
git clone https://github.com/seu-usuario/hardening-test.git
cd hardening-test
chmod +x head-test.sh
```

### Opção 2: Download direto

```bash
curl -O https://raw.githubusercontent.com/seu-usuario/hardening-test/main/head-test.sh
chmod +x head-test.sh
```

---

## 🐳 Docker (com HTTP/3)

O projeto inclui suporte a Docker para rodar os testes com **HTTP/3 (QUIC)** nativo, usando a imagem `ymuski/curl-http3` como base.

### Build da Imagem

```bash
./docker-run.sh build
```

### Executar Testes

```bash
# Teste completo
./docker-run.sh test https://meusite.com

# Teste de categoria específica
./docker-run.sh test https://meusite.com -c header

# Apenas falhas
./docker-run.sh test https://meusite.com -f fail -c all
```

### Verificar Suporte HTTP/3

```bash
# Verifica se o site suporta HTTP/3
./docker-run.sh http3 https://cloudflare.com

# Ou execute curl diretamente
./docker-run.sh curl -IL --http3 -k https://cloudflare.com
```

### Shell Interativo

```bash
./docker-run.sh shell
```

Dentro do container você pode executar comandos curl com HTTP/3:

```bash
curl -IL --http3 -k https://cloudflare.com
```

### Comandos Disponíveis

| Comando | Descrição |
|---------|-----------|
| `./docker-run.sh build` | Constrói a imagem Docker |
| `./docker-run.sh test <URL> [OPTIONS]` | Executa testes na URL |
| `./docker-run.sh http3 <URL>` | Verifica suporte HTTP/3 |
| `./docker-run.sh curl <ARGS>` | Executa curl com HTTP/3 |
| `./docker-run.sh shell` | Shell interativo |

### Por que usar Docker?

- ✅ **HTTP/3 nativo**: curl compilado com nghttp3 e ngtcp2
- ✅ **Ambiente isolado**: Não afeta o sistema host
- ✅ **Reprodutível**: Mesmas versões em qualquer máquina
- ✅ **Sem dependências**: Tudo já está instalado na imagem

---

## 📖 Uso

### Sintaxe básica

```bash
./head-test.sh [OPÇÕES] <URL>
```

### Opções disponíveis

| Opção | Descrição |
|-------|-----------|
| `-h, --help` | Mostra a ajuda |
| `-v, --verbose` | Modo verboso com detalhes |
| `-o, --output <arquivo>` | Salva resultados em arquivo |
| `-u, --user-agent <num>` | Seleciona User-Agent (1-15) |
| `-c, --category <cat>` | Executa categoria específica |
| `-f, --filter <filtro>` | Filtra resultados: all, pass, fail |
| `-p, --with-ports` | Inclui teste de portas no `all` (opcional, lento) |

---

## 🧪 Categorias de Testes

### Todas as Categorias Disponíveis

| Categoria | Alias | Descrição |
|-----------|-------|-----------|
| `all` | - | Executa todos os testes |
| `method` | - | Métodos HTTP (GET, POST, PUT, DELETE, etc.) |
| `cookie` | - | Cookies maliciosos |
| `query` | - | Query strings maliciosas |
| `host` | - | Host headers inválidos |
| `uri` | - | URIs maliciosas (WordPress, arquivos sensíveis) |
| `header` | - | Header injection |
| `contenttype` | - | Content-Type attacks |
| `encoding` | - | Accept-Encoding attacks |
| `xff` | - | X-Forwarded-For spoofing |
| `range` | - | Range header attacks |
| `smuggling` | - | HTTP request smuggling |
| `nginx` | - | Nginx specific attacks |
| `php` | - | PHP specific attacks |
| `database` | `db` | Database/SQL injection |
| `ssrf` | - | SSRF attacks |
| `pathbypass` | `bypass` | Path/URL bypass techniques |
| `injection` | `injections` | Template, LDAP, XML injection |
| `ratelimit` | `bruteforce`, `login` | Rate limiting tests |
| `protocol` | `protocols`, `http` | HTTP/1.0, 1.1, 2 e 3 tests |
| `hopbyhop` | `hbh` | Hop-by-Hop headers abuse |
| `cache` | `cachepoisoning`, `cachedeception` | Cache poisoning/deception |
| `contamination` | `connectioncontamination` | HTTP connection contamination |
| `responsesmuggling` | `desync` | HTTP response smuggling |
| `h2c` | `h2csmuggling` | H2C (HTTP/2 Cleartext) smuggling |
| `ssi` | `esi`, `ssiesi` | SSI/ESI injection |
| `cdn` | `cloudflare`, `cdnbypass` | CDN/Cloudflare bypass |
| `xslt` | `xsltinjection` | XSLT server-side injection |
| `waf` | `wafbypass`, `proxy` | WAF/Proxy bypass |
| `ports` | `exposedports`, `portscan` | Exposed ports check (execução paralela) |
| **🆕 `403bypass`** | `403`, `forbidden` | Bypass de erro 403 |
| **🆕 `clickjacking`** | `xfo`, `framebusting` | Proteção contra Clickjacking |
| **🆕 `secheaders`** | `securityheaders`, `headers` | Security Headers check |
| **🆕 `session`** | `cookies`, `cookiesecurity` | Segurança de sessão/cookies |
| **🆕 `css`** | `cssinjection` | CSS Injection |
| **🆕 `email`** | `smtp`, `imap`, `emailinjection` | Email/SMTP/IMAP Injection |
| **🆕 `credentials`** | `defaultcreds`, `adminpanels` | Credenciais padrão e painéis admin |
| **🆕 `enumeration`** | `userenum`, `accountenum` | Enumeração de contas |
| **🆕 `formatstring`** | `printf` | Format String Injection |
| **🆕 `csrf`** | `xsrf` | Proteção CSRF |
| **🆕 `jwt`** | `jwtattack`, `token` | JWT Security (none alg, tampering) |
| **🆕 `nosql`** | `mongodb`, `nosqlinjection` | NoSQL Injection |
| **🆕 `ldap`** | `ldapinjection` | LDAP Injection |
| **🆕 `xpath`** | `xpathinjection` | XPath Injection |
| **🆕 `deser`** | `deserialization`, `unserialize` | Insecure Deserialization |
| **🆕 `upload`** | `fileupload`, `uploadbypass` | File Upload Security |
| **🆕 `redirect`** | `openredirect`, `urlredirect` | Open Redirect |
| **🆕 `idor`** | `privesc`, `privilege` | IDOR / Privilege Escalation |
| **🆕 `timebased`** | `blind`, `timeblind` | Time-based Blind Injection |
| **🆕 `prototype`** | `protopollution`, `__proto__` | Prototype Pollution |
| **🆕 `evasion`** | `waf-evasion`, `bypass-waf` | WAF Evasion Techniques (150+ payloads) |
| **🆕 `obfuscated`** | `obfuscation`, `encoded` | Obfuscated Payloads (140+ variants) |
| **⚡ `xss`** | - | **[MÓDULO] XSS Tester - 250+ testes (10 categorias)** |
| **⚡ `sqli`** | `sqlinjection`, `sql` | **[MÓDULO] SQLi Tester - 300+ testes (10 categorias)** |
| **⚡ `cmdi`** | `commandinjection`, `rce` | **[MÓDULO] CMDi Tester - 250+ testes (8 categorias)** |
| **⚡ `lfi`** | `rfi`, `fileinclusion` | **[MÓDULO] LFI/RFI Tester - 250+ testes (7 categorias)** |
| `useragent` | - | User-Agent tests |
| `referer` | `referer-all` | Todos os referers maliciosos |
| `referer-spam` | `spam` | Apenas referers SPAM |
| `referer-seo` | `seoblackhat` | Apenas SEO Black Hat |
| `referer-injection` | `injection-referer` | Apenas injection payloads |
| `fakebots` | - | Fake bot detection |

---

## � Novidades v6.0.0

###🧩 Arquitetura Modular - 4 Módulos Especializados (1050+ testes)

A versão 6.0 representa uma **revolução na arquitetura do projeto**, introduzindo 4 módulos especializados que transformam o `head-test.sh` em um **framework profissional de testes de segurança**.

#### 🎨 XSS Tester (250+ testes)
```bash
./head-test.sh -u https://example.com -c xss
```

**10 categorias especializadas:**
- XSS Básico (20 variações)
- XSS HTML5 Tags (25 variações)
- XSS Wrappers (15 variações)
- XSS Polyglot (10 variações)
- XSS WAF Bypass (30 variações)
- XSS DOM-based (20 variações)
- XSS File-based (SVG, XML, Markdown, CSS)
- XSS Advanced (35 variações)
- XSS Blind (20 variações)
- Payloads avançados do PayloadsAllTheThings

**Destaques:**
- ✅ Baseado no repositório PayloadsAllTheThings
- ✅ Cobertura completa de técnicas modernas
- ✅ README dedicado com 100+ exemplos
- ✅ Testes de bypass específicos para cada cenário

#### 💉 SQLi Tester (300+ testes)
```bash
./head-test.sh -u https://example.com -c sqli
```

**10 categorias especializadas:**
- SQLi Clássico (30 variações OR/AND)
- SQLi UNION-Based (25 variações)
- SQLi Error-Based (20 variações MySQL, MSSQL, PostgreSQL, Oracle)
- SQLi Blind (25 variações Boolean + Time-based)
- SQLi Authentication Bypass (30 variações)
- SQLi Stacked Queries (15 variações)
- SQLi WAF Bypass (40 técnicas de evasão)
- SQLi Polyglot (10 payloads universais)
- SQLi Database-Specific (20 testes por DBMS)
- SQLi Advanced (50 payloads Generic_ErrorBased)

**Destaques:**
- ✅ Suporte a 6+ bancos de dados
- ✅ 40 técnicas de bypass de WAF
- ✅ Payloads do OWASP e PayloadsAllTheThings
- ✅ Comparação detalhada com SQLmap

#### ⚙️ CMDi Tester (250+ testes)
```bash
./head-test.sh -u https://example.com -c cmdi
```

**8 categorias especializadas:**
- CMDi Básico (30 variações de command chaining)
- CMDi Bypass (50 técnicas de evasão)
- CMDi Time-Based (20 blind injection)
- CMDi Data Exfiltration (15 DNS/HTTP/File)
- CMDi Polyglot (10 multi-contexto)
- CMDi Argument Injection (20 curl, wget, ssh, etc.)
- CMDi Reverse Shell (15 bash, nc, python, perl, php)
- CMDi Advanced (50 payloads command_exec.txt)

**Destaques:**
- ✅ 50 técnicas de bypass (encoding, quotes, wildcards)
- ✅ 15 variantes de reverse shell
- ✅ Argument injection em 20+ comandos
- ✅ Comparação com Commix

#### 📁 LFI/RFI Tester (250+ testes)
```bash
./head-test.sh -u https://example.com -c lfi
```

**7 categorias especializadas:**
- LFI Básico (30 path traversal)
- LFI Bypass (50 técnicas null byte, encoding, filtros)
- LFI PHP Wrappers (25 php://filter, data://, expect://)
- RFI (20 HTTP, FTP, SMB, data wrapper)
- LFI to RCE (15 log poisoning, session, /proc)
- Path Traversal Deep (20 variações profundas)
- LFI Advanced (50 payloads Linux/Windows/Web)

**Destaques:**
- ✅ 25 PHP wrappers testados
- ✅ Log poisoning para 6 serviços
- ✅ Suporte Linux, Windows, BSD, macOS
- ✅ Comparação com Kadimus e LFISuite

### 📚 Documentação Completa

Cada módulo possui README dedicado:
- [XSS-TESTER-README.md](XSS-TESTER-README.md) - Guia completo de XSS
- [SQLI-TESTER-README.md](SQLI-TESTER-README.md) - Guia completo de SQLi
- [CMDI-TESTER-README.md](CMDI-TESTER-README.md) - Guia completo de CMDi
- [LFI-RFI-TESTER-README.md](LFI-RFI-TESTER-README.md) - Guia completo de LFI/RFI

Cada README inclui:
- ✅ Explicação de todas as técnicas
- ✅ Exemplos de código vulnerável vs exploits
- ✅ Guia de prevenção e remediação
- ✅ Comparação com ferramentas profissionais
- ✅ Casos de uso em CI/CD
- ✅ Referências e documentação oficial

### 🔧 Melhorias de Arquitetura

- ✅ **PayloadsAllTheThings integrado**: Requer git clone do repositório
- ✅ **Modularização completa**: Fácil manutenção e extensão
- ✅ **Escalabilidade**: Adicionar novos módulos é plug-and-play
- ✅ **Reusabilidade**: Módulos podem ser usados em outros projetos
- ✅ **Versionamento**: Cada módulo tem sua própria documentação

### 📊 Estatísticas v6.0.0

| Métrica | v5.1.0 | v6.0.0 | Incremento |
|---------|--------|--------|------------|
| **Total de Testes** | 1650+ | 2700+ | +63% |
| **Arquivos de Script** | 1 | 5 | +4 módulos |
| **Documentação** | 1 README | 5 READMEs | +100 páginas |
| **Categorias** | 60+ | 65+ | +5 |
| **Payloads externos** | 0 | PayloadsAllTheThings | Community-driven |

---

## �🆕 Novidades v5.0.0

### 🔓 403 Bypass Tests (100+ testes)

Testa técnicas de bypass para erro 403 Forbidden:

```bash
./head-test.sh -c 403bypass https://meusite.com
```

**Técnicas testadas:**
- **IP Spoofing Headers**: X-Forwarded-For, X-Originating-IP, True-Client-IP, CF-Connecting-IP, X-Real-IP, etc.
- **Port Bypass**: X-Forwarded-Port (443, 4443, 80, 8080, 8443)
- **Protocol Bypass**: X-Forwarded-Scheme, X-Forwarded-Proto
- **URL Encoding**: 100+ payloads de encoding e path traversal
- **SQLi libinjection Bypass**: Técnicas para bypass de ModSecurity/WAF

### 🖼️ Clickjacking Protection

Verifica proteções contra Clickjacking:

```bash
./head-test.sh -c clickjacking https://meusite.com
```

- Verifica X-Frame-Options (DENY/SAMEORIGIN)
- Verifica CSP frame-ancestors
- Testa tentativas de bypass

### 🔒 Security Headers Check

Audita headers de segurança essenciais:

```bash
./head-test.sh -c secheaders https://meusite.com
```

**Headers verificados:**
- X-Content-Type-Options (nosniff)
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy
- Strict-Transport-Security (HSTS)
- Cross-Origin-Opener-Policy (COOP)
- Cross-Origin-Resource-Policy (CORP)
- Cross-Origin-Embedder-Policy (COEP)

**Headers que devem estar AUSENTES:**
- Server (version disclosure)
- X-Powered-By
- X-AspNet-Version
- X-Generator

### 🍪 Session Security (Cookie Flags)

Verifica flags de segurança em cookies:

```bash
./head-test.sh -c session https://meusite.com
```

- **HttpOnly**: Previne acesso via JavaScript
- **Secure**: Previne envio em conexões HTTP
- **SameSite**: Previne CSRF (Strict/Lax)
- Testes de Session Fixation

### 🎨 CSS Injection

Testa vulnerabilidades de CSS Injection:

```bash
./head-test.sh -c css https://meusite.com
```

- expression(), @import, behavior
- CSS Exfiltration
- CSS Keylogger payloads

### 📧 Email Injection (SMTP/IMAP)

Testa injeção em funcionalidades de email:

```bash
./head-test.sh -c email https://meusite.com
```

- SMTP Header Injection (Bcc, Cc, To, Subject)
- IMAP Command Injection
- CRLF em campos de email

### 🔑 Default Credentials & Admin Panels

Verifica exposição de painéis admin e arquivos sensíveis:

```bash
./head-test.sh -c credentials https://meusite.com
```

**Categorias verificadas:**
- Painéis Admin genéricos (/admin, /administrator, /dashboard)
- WordPress específico (/wp-admin, /wp-login.php, /xmlrpc.php)
- Database Admin (/phpmyadmin, /adminer)
- Arquivos sensíveis (.env, .git, config.php, database.yml)
- Backups (.bak, .sql, .zip, .tar.gz)
- API Endpoints (/api, /graphql, /swagger)

### 👤 Account Enumeration

Testa se é possível enumerar usuários:

```bash
./head-test.sh -c enumeration https://meusite.com
```

- WordPress ?author=N enumeration
- REST API users endpoint
- Diferença de resposta em login

### 📝 Format String Injection

Testa vulnerabilidades de format string:

```bash
./head-test.sh -c formatstring https://meusite.com
```

- %s, %x, %n, %d, %p payloads
- Direct parameter access
- Width e precision specifiers

### 🛡️ CSRF Protection

Verifica proteções contra CSRF:

```bash
./head-test.sh -c csrf https://meusite.com
```

- Requisições POST sem token
- Referer/Origin externos
- Bypass via Content-Type
- Verificação de SameSite em cookies

---

## 💡 Exemplos

### Teste completo (sem portas - rápido)

```bash
./head-test.sh https://meusite.com.br
```

### Teste completo COM scan de portas

```bash
./head-test.sh --with-ports https://meusite.com.br
```

### Teste com filtro (apenas falhas)

```bash
./head-test.sh -f fail https://meusite.com.br
```

### Teste de 403 Bypass

```bash
./head-test.sh -c 403bypass https://meusite.com.br
```

### Teste de Security Headers

```bash
./head-test.sh -c secheaders https://meusite.com.br
```

### Teste de segurança de sessão

```bash
./head-test.sh -c session https://meusite.com.br
```

### Teste de painéis admin expostos

```bash
./head-test.sh -c credentials https://meusite.com.br
```

### Teste de portas expostas (paralelo, ~5-10s)

```bash
./head-test.sh -c ports https://meusite.com.br
```

### Múltiplas opções

```bash
./head-test.sh -v -f fail -o resultado.txt -c all https://meusite.com.br
```

---

## 📊 Interpretando Resultados

### Códigos de Status

| Símbolo | Status | Significado |
|---------|--------|-------------|
| ✓ PASS | Verde | Servidor bloqueou corretamente o ataque |
| ✓ PASS (444) | Verde | Nginx fechou conexão (bloqueio efetivo) |
| ✗ FAIL | Vermelho | Servidor NÃO bloqueou - **vulnerável!** |
| ? WARN | Amarelo | Comportamento inesperado - investigar |

### Taxa de Sucesso

| Taxa | Avaliação |
|------|-----------|
| 80-100% | ✅ Excelente - servidor bem protegido |
| 50-79% | ⚠️ Médio - necessita melhorias |
| 0-49% | ❌ Crítico - servidor vulnerável |

### Para Portas Expostas

| Resultado | Significado |
|-----------|-------------|
| ✓ PROTEGIDA | Porta fechada/filtrada - **correto!** |
| ✗ EXPOSTA | Porta aberta externamente - **risco!** |

> **⚚️ Nota**: O teste de portas agora executa em paralelo (até 20 conexões simultâneas), 
> reduzindo o tempo de ~2 minutos para ~5-10 segundos. Por padrão, não é incluído no `all` 
> para manter a execução rápida. Use `-p, --with-ports` ou `-c ports` explicitamente.

---

## 🔧 Configuração do Servidor

### Nginx - Security Headers

```nginx
# Headers de Segurança Essenciais
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none';" always;

# Remover headers que revelam informações
server_tokens off;
more_clear_headers Server;
more_clear_headers X-Powered-By;
```

### Nginx - 403 Bypass Protection

```nginx
# Bloquear headers de IP spoofing
set $block_spoof 0;
if ($http_x_forwarded_for) { set $block_spoof 1; }
if ($http_x_real_ip) { set $block_spoof 1; }
if ($http_true_client_ip) { set $block_spoof 1; }
if ($http_cf_connecting_ip) { set $block_spoof 1; }
# Permitir apenas de proxies confiáveis

# Bloquear path traversal
if ($request_uri ~* "(\.\./|\.\.\\|%2e%2e|%252e)") {
    return 400;
}

# Bloquear null bytes
if ($request_uri ~* "%00") {
    return 400;
}
```

### PHP - Cookies Seguros

```ini
; php.ini - Configuração de Sessão Segura
session.cookie_httponly = On
session.cookie_secure = On
session.cookie_samesite = Strict
session.use_strict_mode = On
session.use_only_cookies = On
```

### Firewall (nftables)

```bash
#!/usr/sbin/nft -f
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Permitir localhost
        iif lo accept
        
        # Permitir conexões estabelecidas
        ct state established,related accept
        
        # HTTP/HTTPS
        tcp dport { 80, 443 } accept
        
        # SSH com rate limiting
        tcp dport 22 ct state new limit rate 3/minute accept
        
        # BLOQUEAR serviços internos de acesso externo
        tcp dport { 3306, 5432, 6379, 27017, 9200 } drop
    }
}
```

---

## 📁 Estrutura do Projeto

```
hardening-test/
├── head-test.sh                    # Script principal (2700+ testes)
├── xss-tester.sh                   # 🎨 Módulo XSS (250+ testes)
├── sqli-tester.sh                  # 💉 Módulo SQLi (300+ testes)
├── cmdi-tester.sh                  # ⚙️ Módulo CMDi (250+ testes)
├── lfi-rfi-tester.sh               # 📁 Módulo LFI/RFI (250+ testes)
├── Dockerfile                      # Docker com suporte a HTTP/3
├── docker-run.sh                   # Script auxiliar Docker
├── .dockerignore                   # Exclusões para o build
├── .gitignore                      # Exclusões para o git
├── README.md                       # Esta documentação
├── XSS-TESTER-README.md            # 📖 Documentação do módulo XSS
├── SQLI-TESTER-README.md           # 📖 Documentação do módulo SQLi
├── CMDI-TESTER-README.md           # 📖 Documentação do módulo CMDi
├── LFI-RFI-TESTER-README.md        # 📖 Documentação do módulo LFI/RFI
├── LICENSE                         # Licença MIT
├── lists/                          # Listas de payloads
│   ├── bad-user-agents.txt
│   ├── referers-spam.txt
│   ├── referers-seo-blackhat.txt
│   └── referers-injection.txt
└── PayloadsAllTheThings/           # Repositório externo (git clone)
    ├── XSS Injection/
    ├── SQL Injection/
    ├── Command Injection/
    └── File Inclusion/
```

### 🔧 Instalação Completa

```bash
# 1. Clone o repositório
git clone https://github.com/seu-usuario/hardening-test.git
cd hardening-test

# 2. Clone os payloads externos
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git

# 3. Dar permissões de execução
chmod +x *.sh

# 4. Executar testes
./head-test.sh -u https://example.com
```

---

## 📝 Changelog

### v6.0.0 (2026-01-07)
- 🎉 **ARQUITETURA MODULAR** - Introdução de 4 módulos especializados
- 🎨 **XSS Tester** (250+ testes)
  - 10 categorias: Básico, HTML5, Wrappers, Polyglot, WAF Bypass, DOM, File-based, Advanced, Blind
  - Baseado em PayloadsAllTheThings/XSS Injection
  - README dedicado com técnicas, exemplos e prevenção
  - Categorias: `-c xss`
- 💉 **SQLi Tester** (300+ testes)
  - 10 categorias: Classic, UNION, Error-based, Blind, Auth Bypass, Stacked, WAF Bypass, Polyglot, DB-Specific, Advanced
  - Suporte a 6+ bancos de dados (MySQL, MSSQL, PostgreSQL, Oracle, SQLite, MongoDB)
  - 40 técnicas de bypass de WAF
  - Categorias: `-c sqli`, `-c sql`, `-c sqlinjection`
- ⚙️ **CMDi Tester** (250+ testes)
  - 8 categorias: Basic, Bypass, Time-based, Data Exfil, Polyglot, Argument Injection, Reverse Shell, Advanced
  - 50 técnicas de bypass de filtros
  - 15 variantes de reverse shell
  - Categorias: `-c cmdi`, `-c rce`, `-c commandinjection`
- 📁 **LFI/RFI Tester** (250+ testes)
  - 7 categorias: Basic LFI, Bypass, PHP Wrappers, RFI, LFI-to-RCE, Path Traversal, Advanced
  - 25 PHP wrappers (php://filter, data://, expect://, zip://, etc.)
  - Log poisoning para 6 serviços
  - Categorias: `-c lfi`, `-c rfi`, `-c fileinclusion`
- 📚 **Documentação Completa**
  - 4 READMEs especializados (XSS, SQLi, CMDi, LFI/RFI)
  - Mais de 100 páginas de documentação
  - Comparações comferramentas profissionais (SQLmap, Commix, Kadimus, LFISuite)
  - Guias de prevenção e remediação
  - Casos de uso em CI/CD
- 🔧 **PayloadsAllTheThings Integration**
  - Repositório externo integrado via git clone
  - Acesso a 1000+ payloads community-driven
  - Atualização fácil via git pull
- 📊 **Estatísticas**
  - **2700+ testes** totais (+63% vs v5.1.0)
  - **5 arquivos de script** (1 principal + 4 módulos)
  - **5 READMEs** (+100 páginas documentação)
  - **65+ categorias** de testes
  - **4 módulos** independentes e reutilizáveis

### v5.1.0 (2024-12-29)
- 🆕 **Obfuscated Payloads** (140+ testes)
  - XSS com case toggling, URL encoding, double encoding, Unicode, HTML entities
  - XSS com comments, junk chars, whitespace/tabs/newlines, dynamic payloads
  - SQLi com case toggling, encoding, comments, whitespace alternatives
  - Command Injection com wildcards, variable injection, quote concatenation, backslash
  - Path Traversal com encoding, Unicode overlong UTF-8, null bytes
  - SSTI, XXE, LDAP, Open Redirect com variantes ofuscadas
- 🔧 **Otimização de teste de portas**:
  - Execução paralela (20 conexões simultâneas) - de ~2min para ~5-10s
  - Nova flag `-p, --with-ports` para incluir no `all` (opcional)
  - Por padrão, `-c all` não inclui port scan para maior velocidade
- 🔧 Expansão para 1650+ testes totais (60 funções de teste)
- 🔧 Atualização da categoria WAF Evasion com bypasses específicos

### v5.0.0 (2024-12-29)
- 🆕 **JWT Attacks** (30 testes)
  - none algorithm attack, HS256/RS256 confusion
  - Claim tampering, kid/jku/x5u injection
- 🆕 **NoSQL Injection** (30 testes)
  - MongoDB operators ($ne, $gt, $regex, $where)
  - CouchDB, Redis injection
- 🆕 **LDAP Injection** (20 testes)
  - Filter injection, attribute extraction
  - Blind LDAP injection
- 🆕 **XPath Injection** (20 testes)
  - Node extraction, blind XPath
  - OOB/Error based attacks
- 🆕 **Insecure Deserialization** (30 testes)
  - PHP unserialize, Java gadgets, Python Pickle
  - .NET ViewState, Ruby Marshal, YAML
- 🆕 **File Upload Security** (30 testes)
  - Extension bypass, double extension
  - MIME spoofing, path traversal in filename
- 🆕 **Open Redirect** (25 testes)
  - Protocol-less, encoded URLs
  - Host header injection
- 🆕 **IDOR/Privilege Escalation** (30 testes)
  - Sequential ID access, mass assignment
  - GraphQL authorization bypass
- 🆕 **Time-based Blind Injection** (20 testes)
  - SQL SLEEP, NoSQL sleep, CMDi delays
- 🆕 **Prototype Pollution** (20 testes)
  - __proto__, constructor.prototype attacks
- 🆕 **WAF Evasion Techniques** (150+ testes)
  - Case toggling, URL/Double/Unicode encoding
  - Comments, whitespace, null bytes obfuscation
  - Wildcard obfuscation, variable injection
  - HTTP Parameter Pollution, charset tricks
  - Bypasses específicos: Cloudflare, Imperva, ModSecurity, AWS WAF, F5 BIG-IP, Sucuri, Wordfence, Barracuda, Kona/Akamai
- 🆕 **403 Bypass Tests** (100+ testes de bypass para erro 403)
  - IP Spoofing Headers (40+ headers)
  - Port Bypass via X-Forwarded-Port
  - URL Encoding Bypass (80+ payloads)
  - SQLi libinjection Bypass
- 🆕 **Clickjacking Protection** (10 testes)
- 🆕 **Security Headers Check** (15 testes)
- 🆕 **Session Security** (15 testes)
- 🆕 **CSS Injection** (12 testes)
- 🆕 **Email Injection** (15 testes SMTP/IMAP)
- 🆕 **Default Credentials** (50+ endpoints)
- 🆕 **Account Enumeration** (10 testes)
- 🆕 **Format String Injection** (12 testes)
- 🆕 **CSRF Protection** (15 testes)
- 🔧 Expansão para 1500+ testes totais (59 funções de teste)
- 🔧 Filtros de resultado (--filter pass/fail)
- 🔧 Recomendações de hardening integradas

### v4.1.0 (2024-12-12)
- 🆕 Verificação de portas expostas com netcat (45 portas)
- 🆕 Testes de serviços sensíveis (MySQL, Redis, MongoDB, Docker, K8s)
- 🔧 Recomendações de hardening integradas

### v4.0.0 (2024-12-12)
- 🆕 Testes de protocolo HTTP (1.0, 1.1, 2, 3)
- 🆕 Hop-by-Hop Headers abuse (25 testes)
- 🆕 Cache Poisoning/Deception (30 testes)
- 🆕 HTTP Connection Contamination (20 testes)
- 🆕 HTTP Response Smuggling/Desync (25 testes)
- 🆕 H2C Smuggling (20 testes)
- 🆕 SSI/ESI Injection (30 testes)
- 🆕 CDN/Cloudflare Bypass (25 testes)
- 🆕 XSLT Server-Side Injection (20 testes)
- 🆕 WAF/Proxy Bypass (35 testes)
- 🔧 Expansão para 800+ testes

### v3.5.0
- 🆕 Path/URL Bypass (70+ testes)
- 🆕 Rate Limiting tests
- 🆕 Injection vulnerabilities (Template, LDAP, XML)

### v3.4.0
- Adicionados testes de SSRF
- Expandidos testes de Database attacks
- Fake Bots detection

### v3.0.0
- Expansão para 500+ testes
- Referers categorizados (SPAM, SEO, Injection)
- 15 User-Agents modernos

---

## 🤝 Contribuindo

Contribuições são bem-vindas! Por favor:

1. Fork o projeto
2. Crie uma branch (`git checkout -b feature/nova-funcionalidade`)
3. Commit suas mudanças (`git commit -m 'Adiciona nova funcionalidade'`)
4. Push para a branch (`git push origin feature/nova-funcionalidade`)
5. Abra um Pull Request

### Ideias para contribuição

- [ ] Relatório em HTML/PDF
- [ ] Integração com CI/CD
- [x] Testes paralelos para melhor performance (port scanning)
- [ ] Suporte a proxy/SOCKS
- [ ] Integração com Nuclei templates
- [ ] API REST para automação
- [ ] Dashboard web para visualização

---

## ⚠️ Aviso Legal

Esta ferramenta é destinada **apenas para testes autorizados**. Use apenas em sistemas que você possui ou tem permissão explícita para testar. O uso não autorizado pode ser ilegal.

**O autor não se responsabiliza pelo uso indevido desta ferramenta.**

---

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

## 👨‍💻 Autor

Desenvolvido com ❤️ para a comunidade de segurança.

---

<p align="center">
  <strong>⭐ Se este projeto foi útil, considere dar uma estrela!</strong>
</p>
