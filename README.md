# 🛡️ HTTP Header Security Testing Suite

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/bash-5.0%2B-orange.svg" alt="Bash">
  <img src="https://img.shields.io/badge/tests-116%2B-brightgreen.svg" alt="Tests">
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

---

## ✨ Funcionalidades

### 🎯 116+ Testes de Segurança

| Categoria | Quantidade | Descrição |
|-----------|------------|-----------|
| Host Inválido | 10 | Testes de Host header spoofing |
| Cookie Malicioso | 10 | XSS, SQL Injection, overflow em cookies |
| Método HTTP | 10 | TRACE, PUT, DELETE, WebDAV, etc. |
| Query String | 10 | SQL Injection, XSS, LFI, RFI |
| URI Maliciosa | 10 | Acesso a arquivos sensíveis |
| Referer Malicioso | 10 | Spam SEO, injection via referer |
| User-Agent | 15 | Bots maliciosos e legítimos |
| Header Injection | 10 | CRLF, X-Forwarded, override |
| Content-Type | 10 | XXE, XSS, MIME type attacks |
| X-Forwarded-For | 10 | IP spoofing, bypass de WAF |
| Range Header | 8 | DoS via range requests |
| Accept-Encoding | 8 | Encoding attacks |
| HTTP Smuggling | 5 | Request smuggling básico |

### 🛠️ Recursos Adicionais

- **Modo Verbose**: Detalhes de cada requisição
- **Exportação de Resultados**: Salva em arquivo para análise
- **Seleção de Categorias**: Execute apenas os testes necessários
- **User-Agent Customizável**: Escolha entre 10 UAs populares
- **Resultados Coloridos**: Fácil identificação de falhas
- **Resumo Estatístico**: Taxa de sucesso e métricas

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
git clone https://github.com/seu-usuario/http-header-security-test.git
cd http-header-security-test
chmod +x head-test.sh
```

### Opção 2: Download direto

```bash
curl -O https://raw.githubusercontent.com/seu-usuario/http-header-security-test/main/head-test.sh
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
| `-u, --user-agent <num>` | Seleciona User-Agent (1-10) |
| `-c, --category <cat>` | Executa categoria específica |
| `--version` | Mostra a versão |
| `--list-categories` | Lista categorias disponíveis |

---

## 🧪 Categorias de Testes

### 1. 🏠 Host Inválido (`host`)
Testa manipulação do header Host para bypass de controles.

```bash
./head-test.sh -c host https://example.com
```

**Vetores testados:**
- `127.0.0.1`, `localhost`, `[::1]`
- AWS metadata IP (`169.254.169.254`)
- Domínios maliciosos
- XSS no Host header

### 2. 🍪 Cookie Malicioso (`cookie`)
Verifica proteções contra cookies maliciosos.

```bash
./head-test.sh -c cookie https://example.com
```

**Vetores testados:**
- XSS (URL encoded, Unicode)
- SQL Injection
- Command Injection
- Cookie overflow (4KB+)
- CRLF Injection

### 3. 📝 Método HTTP (`method`)
Testa métodos HTTP que devem ser bloqueados.

```bash
./head-test.sh -c method https://example.com
```

**Métodos testados:**
- TRACE, OPTIONS, PUT, DELETE, PATCH
- CONNECT, PROPFIND, MKCOL, COPY, MOVE

### 4. 🔍 Query String Maliciosa (`query`)
Verifica proteção contra injeções em parâmetros.

```bash
./head-test.sh -c query https://example.com
```

**Vetores testados:**
- SQL Injection (UNION, DROP, OR 1=1)
- XSS refletido
- LFI/RFI (Local/Remote File Inclusion)
- Command Injection
- PHP eval() injection

### 5. 🔗 URI Maliciosa (`uri`)
Testa acesso a arquivos e diretórios sensíveis.

```bash
./head-test.sh -c uri https://example.com
```

**Arquivos testados:**
- `.htaccess`, `.env`, `.git/config`
- `config.php.bak`, `dump.sql`, `backup.zip`
- `wp-config.php`, `phpinfo.php`
- `.DS_Store`, `vendor/autoload.php`

### 6. 🔙 Referer Malicioso (`referer`)
Verifica manipulação do header Referer.

```bash
./head-test.sh -c referer https://example.com
```

**Vetores testados:**
- SQL Injection/XSS no Referer
- Spam SEO (semalt, buttons-for-website)
- Referer overflow
- CRLF Injection

### 7. 🤖 User-Agent (`useragent`)
Testa detecção de bots maliciosos e legítimos.

```bash
./head-test.sh -c useragent https://example.com
```

**Bots maliciosos:**
- `curl`, `wget`, `python-requests`
- `AhrefsBot`, `MJ12bot`, `SemrushBot`
- `Nikto`, `sqlmap`

**Bots legítimos:**
- `Googlebot`, `Bingbot`
- `DuckDuckBot`, `Facebot`

### 8. 💉 Header Injection (`header`)
Testa injeção de cabeçalhos maliciosos.

```bash
./head-test.sh -c header https://example.com
```

**Vetores testados:**
- CRLF Injection
- X-Forwarded-Host spoofing
- X-Original-URL bypass
- X-HTTP-Method-Override
- Header com null byte

### 9. 📄 Content-Type (`contenttype`)
Testa manipulação de Content-Type.

```bash
./head-test.sh -c contenttype https://example.com
```

**Vetores testados:**
- XXE via XML
- XSS via SVG
- Charset malicioso (UTF-7)
- Content-Type duplo

### 10. 🌐 X-Forwarded-For (`forwarded`)
Testa spoofing de IP de origem.

```bash
./head-test.sh -c forwarded https://example.com
```

**Vetores testados:**
- IPs privados/localhost
- AWS metadata IP
- SQL Injection/XSS no XFF
- X-Real-IP e X-Client-IP

### 11. 📊 Range Header (`range`)
Testa ataques via Range header.

```bash
./head-test.sh -c range https://example.com
```

**Vetores testados:**
- Multiple ranges (DoS)
- Range overflow
- Range invertido
- Caracteres inválidos

### 12. 🗜️ Accept-Encoding (`encoding`)
Testa manipulação de encoding.

```bash
./head-test.sh -c encoding https://example.com
```

**Vetores testados:**
- Encoding inválido
- SQL Injection no header
- Null byte e CRLF

### 13. 🚢 HTTP Smuggling (`smuggling`)
Testa técnicas básicas de request smuggling.

```bash
./head-test.sh -c smuggling https://example.com
```

**Vetores testados:**
- Content-Length + Transfer-Encoding
- Transfer-Encoding com espaço
- Content-Length negativo/muito grande

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
🏠 TESTES DE HOST INVÁLIDO
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [✓] Host: 127.0.0.1                           PASS (HTTP 403)
  [✓] Host: localhost                            PASS (HTTP 403)
  [✗] Host: evil.com                             FAIL (HTTP 200)
```

---

## 🔧 Configuração do Servidor

### Nginx - Exemplo de proteção

```nginx
# Bloquear hosts inválidos
if ($host !~ ^(meusite\.com\.br|www\.meusite\.com\.br)$ ) {
    return 444;
}

# Bloquear métodos não permitidos
if ($request_method !~ ^(GET|HEAD|POST)$ ) {
    return 405;
}

# Bloquear bots maliciosos
if ($http_user_agent ~* (curl|wget|python|nikto|sqlmap) ) {
    return 403;
}
```

### ModSecurity - Proteção avançada

O script testa muitos vetores que o ModSecurity com OWASP CRS pode bloquear automaticamente.

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
