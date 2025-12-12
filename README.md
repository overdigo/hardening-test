# 🛡️ HTTP Header Security Testing Suite

<p align="center">
  <img src="https://img.shields.io/badge/version-4.1.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/bash-5.0%2B-orange.svg" alt="Bash">
  <img src="https://img.shields.io/badge/tests-800%2B-brightgreen.svg" alt="Tests">
</p>

<p align="center">
  <strong>Uma ferramenta abrangente para testar a segurança de cabeçalhos HTTP, protocolos e portas expostas em servidores web.</strong>
</p>

---

## 📋 Índice

- [Sobre](#-sobre)
- [Funcionalidades](#-funcionalidades)
- [Requisitos](#-requisitos)
- [Instalação](#-instalação)
- [Uso](#-uso)
- [Categorias de Testes](#-categorias-de-testes)
- [Novidades v4.1.0](#-novidades-v410)
- [Exemplos](#-exemplos)
- [Interpretando Resultados](#-interpretando-resultados)
- [Configuração do Servidor](#-configuração-do-servidor)
- [Contribuindo](#-contribuindo)
- [Licença](#-licença)

---

## 📖 Sobre

O **HTTP Header Security Testing Suite** é uma ferramenta de linha de comando projetada para avaliar a robustez das configurações de segurança de servidores web. Ela simula diversos tipos de ataques através de cabeçalhos HTTP maliciosos, testa protocolos HTTP/1.0, 1.1, 2 e 3, e verifica portas de serviços que não devem estar expostas externamente.

### Por que usar?

- ✅ Verificar configurações de WAF (Web Application Firewall)
- ✅ Testar regras de segurança do Nginx/Apache
- ✅ Validar proteções contra injeções (SQL, XSS, Command, XSLT, SSI/ESI)
- ✅ Auditar conformidade com boas práticas de segurança
- ✅ Identificar vulnerabilidades antes de atacantes
- ✅ Testar técnicas de bypass de filtros e WAF
- ✅ Verificar versões de protocolo HTTP suportadas
- ✅ Detectar portas de serviços expostas indevidamente (MySQL, Redis, etc.)
- ✅ Testar ataques avançados (Cache Poisoning, HTTP Smuggling, H2C, etc.)

---

## ✨ Funcionalidades

### 🎯 800+ Testes de Segurança

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
| **🆕 HTTP Protocols** | **20** | HTTP/1.0, 1.1, 2 e 3 version tests |
| **🆕 Hop-by-Hop Headers** | **25** | Connection header abuse, bypass |
| **🆕 Cache Poisoning** | **30** | Cache key manipulation, deception |
| **🆕 Connection Contamination** | **20** | Pipeline pollution, queue poisoning |
| **🆕 Response Smuggling** | **25** | Response splitting, desync |
| **🆕 H2C Smuggling** | **20** | HTTP/2 Cleartext smuggling |
| **🆕 SSI/ESI Injection** | **30** | Server/Edge Side Includes |
| **🆕 CDN/Cloudflare Bypass** | **25** | Origin IP discovery |
| **🆕 XSLT Injection** | **20** | XSLT server-side injection |
| **🆕 WAF Bypass** | **35** | Encoding, method, path bypass |
| **🆕 Exposed Ports** | **45** | MySQL, Redis, Docker, K8s, etc. |
| User-Agents | 100+ | Bots maliciosos, scrapers, scanners |
| Referers | 100+ | SPAM, SEO Black Hat, Injection |
| Fake Bots | 10 | Impostores de Googlebot/Bingbot |

### 🛠️ Recursos

- **Modo Verbose**: Detalhes de cada requisição
- **Exportação de Resultados**: Salva em arquivo para análise
- **Seleção de Categorias**: Execute apenas os testes necessários
- **15 User-Agents**: Desktop, Mobile, Tablets de diferentes navegadores
- **Resultados Coloridos**: Fácil identificação de falhas
- **Resumo Estatístico**: Taxa de sucesso e métricas
- **Listas Externas**: Suporte a listas customizadas
- **Port Scanning**: Verificação de portas sensíveis com netcat
- **Protocol Testing**: Suporte a HTTP/1.0, 1.1, 2 e 3

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
| **🆕 `protocol`** | `protocols`, `http` | HTTP/1.0, 1.1, 2 e 3 tests |
| **🆕 `hopbyhop`** | `hbh` | Hop-by-Hop headers abuse |
| **🆕 `cache`** | `cachepoisoning`, `cachedeception` | Cache poisoning/deception |
| **🆕 `contamination`** | `connectioncontamination` | HTTP connection contamination |
| **🆕 `responsesmuggling`** | `desync` | HTTP response smuggling |
| **🆕 `h2c`** | `h2csmuggling` | H2C (HTTP/2 Cleartext) smuggling |
| **🆕 `ssi`** | `esi`, `ssiesi` | SSI/ESI injection |
| **🆕 `cdn`** | `cloudflare`, `cdnbypass` | CDN/Cloudflare bypass |
| **🆕 `xslt`** | `xsltinjection` | XSLT server-side injection |
| **🆕 `waf`** | `wafbypass`, `proxy` | WAF/Proxy bypass |
| **🆕 `ports`** | `exposedports`, `portscan` | Exposed ports check |
| `useragent` | - | User-Agent tests |
| `referer` | `referer-all` | Todos os referers maliciosos |
| `referer-spam` | `spam` | Apenas referers SPAM |
| `referer-seo` | `seoblackhat` | Apenas SEO Black Hat |
| `referer-injection` | `injection-referer` | Apenas injection payloads |
| `fakebots` | - | Fake bot detection |

---

## 🆕 Novidades v4.1.0

### 🌐 Testes de Protocolo HTTP

Verifica suporte e segurança para diferentes versões do protocolo HTTP:

```bash
./head-test.sh -c protocol https://meusite.com
```

| Protocolo | Comportamento Esperado |
|-----------|----------------------|
| HTTP/1.0 | Deve ser bloqueado ou limitado (obsoleto) |
| HTTP/1.1 | Deve funcionar (padrão) |
| HTTP/2 | Deve funcionar se suportado |
| HTTP/3 | Experimental (QUIC) |

### 🔗 Hop-by-Hop Headers Abuse

Testa manipulação de headers Connection para bypass de segurança:

```bash
./head-test.sh -c hopbyhop https://meusite.com
```

### 💉 Cache Poisoning / Cache Deception

Testa vulnerabilidades de envenenamento de cache:

```bash
./head-test.sh -c cache https://meusite.com
```

- X-Forwarded-Host poisoning
- Fat GET requests
- Cache deception via path extensions
- Response splitting

### 🔀 HTTP Smuggling Avançado

Múltiplas técnicas de smuggling:

```bash
./head-test.sh -c smuggling https://meusite.com      # Request smuggling
./head-test.sh -c responsesmuggling https://meusite.com  # Response smuggling
./head-test.sh -c h2c https://meusite.com            # H2C smuggling
./head-test.sh -c contamination https://meusite.com  # Connection contamination
```

### 📄 SSI/ESI Injection

Server-Side Includes e Edge Side Includes:

```bash
./head-test.sh -c ssi https://meusite.com
```

- `<!--#exec cmd="id"-->`
- `<esi:include src="/admin"/>`
- Varnish/Akamai specific tests

### ☁️ CDN/Cloudflare Bypass

Tentativas de descobrir IP real atrás de CDN:

```bash
./head-test.sh -c cdn https://meusite.com
```

- CF-Connecting-IP, True-Client-IP spoofing
- Headers de debug de CDN
- Origin discovery via Host header

### 🛡️ WAF Bypass

Técnicas avançadas de bypass de WAF:

```bash
./head-test.sh -c waf https://meusite.com
```

- Double/Triple URL encoding
- UTF-8 overlong encoding
- SQL injection bypass (comentários, tabs, newlines)
- XSS bypass (event handlers, data URIs)
- HTTP Parameter Pollution

### 🔌 Verificação de Portas Expostas

Verifica se serviços que devem estar limitados a localhost estão expostos:

```bash
./head-test.sh -c ports https://meusite.com
```

| Categoria | Portas | Serviços |
|-----------|--------|----------|
| Bancos de Dados | 3306, 5432, 27017, 1433, 1521 | MySQL, PostgreSQL, MongoDB, MSSQL, Oracle |
| Cache/Queue | 6379, 11211, 5672, 15672 | Redis, Memcached, RabbitMQ |
| Search | 9200, 9300 | Elasticsearch |
| Container | 2375, 2376, 6443, 10250 | Docker, Kubernetes |
| Dev | 9000, 8080, 3000, 5000 | PHP-FPM, Tomcat, Node.js, Flask |
| Remote | 22, 3389, 5900 | SSH, RDP, VNC |

---

## 💡 Exemplos

### Teste completo

```bash
./head-test.sh https://meusite.com.br
```

### Teste com resultados em arquivo

```bash
./head-test.sh -o resultados.txt https://meusite.com.br
```

### Teste de protocolos HTTP

```bash
./head-test.sh -c protocol https://meusite.com.br
```

### Teste de portas expostas

```bash
./head-test.sh -c ports https://meusite.com.br
```

### Teste de cache poisoning

```bash
./head-test.sh -c cache https://meusite.com.br
```

### Teste de bypass de WAF

```bash
./head-test.sh -c waf https://meusite.com.br
```

### Múltiplas opções

```bash
./head-test.sh -v -u 1 -o resultado.txt -c all https://meusite.com.br
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

### Nginx - Hardening Completo

```nginx
# Bloquear HTTP/1.0
if ($server_protocol = HTTP/1.0) {
    return 444;
}

# Normalizar múltiplas barras
merge_slashes on;

# Bloquear null bytes
if ($request_uri ~* "%00") {
    return 400;
}

# Bloquear caracteres suspeitos no path
if ($request_uri ~* "(%2e|%2f|%5c|%00|%c0%af|%ef%bc%8f)") {
    return 400;
}

# Bloquear hosts inválidos
if ($host !~ ^(meusite\.com\.br|www\.meusite\.com\.br)$ ) {
    return 444;
}

# Bloquear métodos não permitidos
if ($request_method !~ ^(GET|HEAD|POST)$ ) {
    return 405;
}

# Remover headers hop-by-hop perigosos
proxy_set_header Upgrade "";
proxy_set_header Connection "";

# Proteção contra cache poisoning
proxy_ignore_headers X-Forwarded-Host X-Host X-Forwarded-Server;
```

### Serviços - Limitação ao Localhost

```bash
# MySQL/MariaDB - /etc/mysql/my.cnf
bind-address = 127.0.0.1

# Redis - /etc/redis/redis.conf
bind 127.0.0.1
requirepass sua_senha_forte

# PostgreSQL - /etc/postgresql/*/main/postgresql.conf
listen_addresses = 'localhost'

# MongoDB - /etc/mongod.conf
net:
  bindIp: 127.0.0.1

# PHP-FPM - /etc/php/*/fpm/pool.d/www.conf
listen = /run/php/php-fpm.sock  # Usar socket ao invés de porta
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
├── head-test.sh           # Script principal (800+ testes)
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
