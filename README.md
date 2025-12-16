# 🛡️ HTTP Header Security Testing Suite

<p align="center">
  <img src="https://img.shields.io/badge/version-5.0.1-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/bash-5.0%2B-orange.svg" alt="Bash">
  <img src="https://img.shields.io/badge/tests-1200%2B-brightgreen.svg" alt="Tests">
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
- [Novidades v5.0.1](#-novidades-v501)
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

---

## ✨ Funcionalidades

### 🎯 1200+ Testes de Segurança

| Categoria | Quantidade | Descrição |
|-----------|------------|-----------|
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
| `ports` | `exposedports`, `portscan` | Exposed ports check |
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
| `useragent` | - | User-Agent tests |
| `referer` | `referer-all` | Todos os referers maliciosos |
| `referer-spam` | `spam` | Apenas referers SPAM |
| `referer-seo` | `seoblackhat` | Apenas SEO Black Hat |
| `referer-injection` | `injection-referer` | Apenas injection payloads |
| `fakebots` | - | Fake bot detection |

---

## 🆕 Novidades v5.0.0

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

### Teste completo

```bash
./head-test.sh https://meusite.com.br
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
├── head-test.sh           # Script principal (1200+ testes)
├── README.md              # Esta documentação
├── LICENSE                # Licença MIT
└── lists/                 # Listas de payloads
    ├── bad-user-agents.txt
    ├── referers-spam.txt
    ├── referers-seo-blackhat.txt
    └── referers-injection.txt
```

---

## 📝 Changelog

### v5.0.1 (2024-12-16)
- 🔧 **Correção SSL/TLS**: Testes de protocolo agora usam `curl` com flags coretas
  - TLS 1.0/1.1 rejeitados pelo servidor são corretamente identificados como BLOQUEADOS
- 🔧 **Correção Cipher Suites**: Força TLS 1.2 para evitar falsos positivos
  - Ciphers fracos não mais aparecem como "vulneráveis" quando TLS 1.3 negocia automaticamente
- 🔧 **Correção Curvas ECDH**: Verifica a curva realmente usada pelo servidor
  - Curvas fracas são corretamente identificadas como BLOQUEADAS quando servidor usa curva mais forte
- 🆕 **Atalhos nas Seções**: Cada seção de teste agora mostra o atalho `-c`
  - Exemplo: `🔒 TESTES DE SEGURANÇA SSL/TLS (-c ssl)`
  - Facilita encontrar o comando para executar teste específico

### v5.0.0 (2024-12-16)
- 🆕 **403 Bypass Tests** (100+ testes de bypass para erro 403)
  - IP Spoofing Headers (40+ headers)
  - Port Bypass via X-Forwarded-Port
  - URL Encoding Bypass (80+ payloads)
  - SQLi libinjection Bypass
- 🆕 **Clickjacking Protection** (10 testes)
  - X-Frame-Options verification
  - CSP frame-ancestors check
- 🆕 **Security Headers Check** (15 testes)
  - Headers essenciais presentes
  - Headers de disclosure ausentes
- 🆕 **Session Security** (15 testes)
  - Cookie flags (HttpOnly, Secure, SameSite)
  - Session Fixation tests
- 🆕 **CSS Injection** (12 testes)
- 🆕 **Email Injection** (15 testes SMTP/IMAP)
- 🆕 **Default Credentials** (50+ endpoints)
  - Admin panels, sensitive files, backups
- 🆕 **Account Enumeration** (10 testes)
- 🆕 **Format String Injection** (12 testes)
- 🆕 **CSRF Protection** (15 testes)
- 🔧 Expansão para 1200+ testes totais
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
- [ ] Testes paralelos para melhor performance
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
