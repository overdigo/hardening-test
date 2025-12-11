# 🛡️ HTTP Header Security Testing Suite

<p align="center">
  <img src="https://img.shields.io/badge/version-3.2.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/bash-5.0%2B-orange.svg" alt="Bash">
  <img src="https://img.shields.io/badge/tests-500%2B-brightgreen.svg" alt="Tests">
</p>

<p align="center">
  <strong>Uma ferramenta abrangente para testar a segurança de cabeçalhos HTTP em servidores web.</strong>
</p>

---

## 📋 Índice

- [Sobre](#-sobre)
- [Funcionalidades](#-funcionalidades)
- [Requisitos](#-requisitos)
- [Instalação](#-instalação)
- [Uso](#-uso)
- [Categorias de Testes](#-categorias-de-testes)
- [Exemplos](#-exemplos)
- [Interpretando Resultados](#-interpretando-resultados)
- [Contribuindo](#-contribuindo)
- [Licença](#-licença)

---

## 📖 Sobre

O **HTTP Header Security Testing Suite** é uma ferramenta de linha de comando projetada para avaliar a robustez das configurações de segurança de servidores web. Ela simula diversos tipos de ataques através de cabeçalhos HTTP maliciosos para verificar se o servidor está adequadamente protegido.

### Por que usar?

- ✅ Verificar configurações de WAF (Web Application Firewall)
- ✅ Testar regras de segurança do Nginx/Apache
- ✅ Validar proteções contra injeções (SQL, XSS, Command)
- ✅ Auditar conformidade com boas práticas de segurança
- ✅ Identificar vulnerabilidades antes de atacantes
- ✅ Testar técnicas de bypass de filtros e WAF

---

## ✨ Funcionalidades

### 🎯 500+ Testes de Segurança

| Categoria | Quantidade | Descrição |
|-----------|------------|-----------|
| Host Inválido | 10 | Testes de Host header spoofing |
| Cookie Malicioso | 30 | XSS, SQL Injection, overflow, encoding attacks |
| Método HTTP | 50 | TRACE, PUT, DELETE, WebDAV, métodos customizados |
| Query String | 50 | SQL Injection, XSS, LFI, RFI, CMDi |
| URI Maliciosa | 50 | WordPress, arquivos sensíveis, backups |
| Referer Malicioso | 100+ | SPAM, SEO Black Hat, Injection payloads |
| User-Agent | 100+ | Bots maliciosos, scrapers, scanners |
| Header Injection | 20 | CRLF, X-Forwarded, override attacks |
| Content-Type | 20 | XXE, XSS, MIME type attacks |
| X-Forwarded-For | 20 | IP spoofing, bypass de WAF |
| Range Header | 20 | DoS via range requests |
| Accept-Encoding | 20 | Encoding attacks, overflow |
| HTTP Smuggling | 20 | CL.TE, TE.CL, header obfuscation |
| Nginx Attacks | 20 | Path traversal, buffer overflow, config exposure |
| PHP Attacks | 20 | Wrappers, deserialization, code injection |
| Database Attacks | 20 | MySQL/MariaDB specific SQLi |
| SSRF Attacks | 15 | Cloud metadata, internal networks |
| **Path/URL Bypass** | **70+** | **🆕 Null byte, encoding, protocol switch, ports** |
| Fake Bots | 10 | Impostores de Googlebot/Bingbot |

### 🛠️ Recursos

- **Modo Verbose**: Detalhes de cada requisição
- **Exportação de Resultados**: Salva em arquivo para análise
- **Seleção de Categorias**: Execute apenas os testes necessários
- **15 User-Agents**: Desktop, Mobile, Tablets de diferentes navegadores
- **Resultados Coloridos**: Fácil identificação de falhas
- **Resumo Estatístico**: Taxa de sucesso e métricas
- **Listas Externas**: Suporte a listas customizadas de User-Agents e Referers

---

## 📦 Requisitos

- **Bash** 4.0 ou superior
- **curl** (geralmente pré-instalado)
- **Sistema operacional**: Linux, macOS, WSL

### Verificar requisitos:

```bash
bash --version
curl --version
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

### Categorias Disponíveis

| Categoria | Alias | Descrição |
|-----------|-------|-----------|
| `all` | - | Executa todos os testes |
| `method` | - | Métodos HTTP |
| `cookie` | - | Cookies maliciosos |
| `query` | - | Query strings maliciosas |
| `host` | - | Host headers inválidos |
| `uri` | - | URIs maliciosas (WordPress, arquivos) |
| `header` | - | Header injection |
| `contenttype` | - | Content-Type attacks |
| `encoding` | - | Accept-Encoding attacks |
| `xff` | - | X-Forwarded-For spoofing |
| `range` | - | Range header attacks |
| `smuggling` | - | HTTP smuggling |
| `nginx` | - | Nginx specific attacks |
| `php` | - | PHP specific attacks |
| `database` | `db` | Database/SQL injection |
| `ssrf` | - | SSRF attacks |
| `pathbypass` | `bypass` | 🆕 Path/URL bypass techniques |
| `useragent` | - | User-Agent tests |
| `referer` | `referer-all` | Todos os referers maliciosos |
| `referer-spam` | `spam` | Apenas referers SPAM |
| `referer-seo` | `seoblackhat` | Apenas SEO Black Hat |
| `referer-injection` | `injection-referer` | Apenas injection payloads |
| `fakebots` | - | Fake bot detection |

---

## 🆕 Path/URL Bypass (v3.2.0)

Nova categoria com **70+ testes** de técnicas de bypass de filtros:

### Técnicas Testadas

| Técnica | Exemplo | Descrição |
|---------|---------|-----------|
| Null Byte Injection | `/admin.php%00.html` | Trunca extensão de arquivos |
| HTTP Version Downgrade | `--http1.0` | Bypass via protocolo antigo |
| Parameter Tampering | `/admin?unused=1` | Bypass de filtros de path exato |
| Case Manipulation | `/Admin`, `/ADMIN` | Bypass de filtros case-sensitive |
| Trailing Slash/Dot | `/admin/`, `/admin.` | Bypass de match exato |
| Path Confusion | `/..;/admin`, `/;/admin` | Confusão de parsers |
| Double Slashes | `//admin//` | Bypass de normalização |
| URL Encoding | `/admin%2f`, `/%2fadmin` | Bypass com encoding |
| Unicode Tricks | `/admin%c0%af`, `／admin` | Bypass com caracteres Unicode |
| Random Extensions | `/admin.php`, `/admin.json` | Bypass de extensões desconhecidas |
| Backslash/Mixed | `\admin`, `/admin\/` | Confusão de path parsers |
| Semicolon/Space | `/admin;`, `/admin%20` | Bypass de parsers permissivos |
| Path Fuzzing | `/%2e%2e/admin` | Encoded path traversal |
| HTTP/HTTPS Switch | `http://` vs `https://` | Bypass de regras por protocolo |
| Alternate Ports | `:8080`, `:8443`, `:8000` | Serviços em portas alternativas |
| Subdomain Spoofing | `Host: admin.example.com` | Virtual host bypass |

### Exemplo de uso

```bash
# Executar apenas testes de path bypass
./head-test.sh -c pathbypass https://meusite.com

# Ou usando alias
./head-test.sh -c bypass https://meusite.com
```

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

### Teste verboso de uma categoria

```bash
./head-test.sh -v -c query https://meusite.com.br
```

### Teste automatizado (sem seleção de UA)

```bash
./head-test.sh -u 1 https://meusite.com.br
```

### Testar técnicas de bypass

```bash
./head-test.sh -c pathbypass https://meusite.com.br
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
| ✗ FAIL | Vermelho | Servidor NÃO bloqueou - **vulnerável!** |
| ? WARN | Amarelo | Comportamento inesperado - investigar |
| ! TIMEOUT | Amarelo | Requisição expirou |

### Taxa de Sucesso

| Taxa | Avaliação |
|------|-----------|
| 80-100% | ✅ Excelente - servidor bem protegido |
| 50-79% | ⚠️ Médio - necessita melhorias |
| 0-49% | ❌ Crítico - servidor vulnerável |

### Exemplo de saída

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔓 TESTES DE PATH/URL BYPASS (70+ testes)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ── Null Byte Injection ──
  [✓] Null Byte: admin.php%00.html            PASS (HTTP 400)
  [✓] Null Byte: admin%00                     PASS (HTTP 400)
  
  ── Case Manipulation ──
  [✓] Case: /Admin                            PASS (HTTP 404)
  [✗] Case: /ADMIN                            FAIL (HTTP 200)
```

---

## 🔧 Configuração do Servidor

### Nginx - Proteção contra bypass

```nginx
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

# Case-insensitive blocking para paths sensíveis
location ~* ^/(admin|wp-admin|phpmyadmin) {
    deny all;
}
```

### ModSecurity - Proteção avançada

O script testa muitos vetores que o ModSecurity com OWASP CRS pode bloquear automaticamente.

---

## 📁 Estrutura do Projeto

```
hardening-test/
├── head-test.sh           # Script principal
├── README.md              # Esta documentação
├── LICENSE                # Licença MIT
└── lists/                 # Listas de payloads
    ├── bad-user-agents.txt
    ├── referers-spam.txt
    ├── referers-seo-blackhat.txt
    └── referers-injection.txt
```

---

## 🤝 Contribuindo

Contribuições são bem-vindas! Por favor:

1. Fork o projeto
2. Crie uma branch (`git checkout -b feature/nova-funcionalidade`)
3. Commit suas mudanças (`git commit -m 'Adiciona nova funcionalidade'`)
4. Push para a branch (`git push origin feature/nova-funcionalidade`)
5. Abra um Pull Request

### Ideias para contribuição

- [ ] Adicionar mais vetores de ataque
- [ ] Suporte a autenticação HTTP
- [ ] Relatório em HTML
- [ ] Integração com CI/CD
- [ ] Testes paralelos para melhor performance
- [ ] Suporte a proxy

---

## 📝 Changelog

### v3.2.0 (2024-12-11)
- 🆕 Nova categoria `pathbypass` com 70+ testes de bypass
- 🆕 Null Byte Injection tests
- 🆕 HTTP Version Downgrade tests
- 🆕 Parameter Tampering tests
- 🆕 Case Manipulation tests
- 🆕 Unicode/Encoding bypass techniques
- 🆕 HTTP/HTTPS protocol switch tests
- 🆕 Alternate ports scanning (8080, 8443, 8000, 3000, 9000)
- 🆕 Subdomain spoofing via Host header

### v3.1.0
- Adicionados testes de SSRF
- Expandidos testes de Database attacks
- Adicionados Fake Bots detection

### v3.0.0
- Expansão para 500+ testes
- Referers categorizados (SPAM, SEO, Injection)
- Testes específicos para Nginx, PHP, Database
- 15 User-Agents modernos

---

## ⚠️ Aviso Legal

Esta ferramenta é destinada **apenas para testes autorizados**. Use apenas em sistemas que você possui ou tem permissão explícita para testar. O uso não autorizado pode ser ilegal.

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
