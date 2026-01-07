# CSRF Tester - Módulo de Testes CSRF

## Descrição

O `csrf-tester.sh` é um módulo separado do `head-test.sh` dedicado exclusivamente a testes de **CSRF (Cross-Site Request Forgery)**. Este módulo utiliza as melhores práticas e técnicas do repositório **PayloadsAllTheThings/Cross-Site Request Forgery** para fornecer testes abrangentes de proteção CSRF.

## O que é CSRF?

**Cross-Site Request Forgery (CSRF)** é um ataque que força um usuário autenticado a executar ações indesejadas em uma aplicação web na qual está autenticado. O ataque explora a confiança que a aplicação tem no navegador do usuário.

### Como funciona?

1. A vítima está autenticada no site `example.com`
2. A vítima visita um site malicioso `evil.com`
3. O site malicioso envia uma requisição para `example.com` usando a sessão da vítima
4. Se não houver proteção CSRF, a ação é executada como se a vítima tivesse solicitado

### Exemplo de Ataque

```html
<!-- Site malicioso evil.com -->
<img src="https://bank.com/transfer?to=attacker&amount=1000">
```

Ou um formulário auto-submit:

```html
<form action="https://bank.com/transfer" method="POST" id="csrf">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="1000">
</form>
<script>document.getElementById('csrf').submit();</script>
```

## Motivação

A separação dos testes CSRF em um módulo dedicado oferece várias vantagens:

1. **Cobertura Completa**: Testa todas as principais técnicas de proteção e bypass CSRF
2. **Organização**: Código modular e focado em um tipo específico de vulnerabilidade
3. **Atualização Facilitada**: Fácil adicionar novos testes e técnicas
4. **Reutilização**: Pode ser adaptado para outros projetos de segurança
5. **Utilização de Payloads Profissionais**: Baseado no PayloadsAllTheThings

## Estrutura

O módulo está organizado nas seguintes categorias de testes:

### 1. CSRF Token Validation (20 testes)

Testa se a aplicação valida corretamente tokens CSRF:

- **Missing Token**: Requisições sem token CSRF
- **Empty Token**: Token vazio ou nulo
- **Invalid Token**: Token com valor incorreto/aleatório
- **Wrong Parameter Name**: Token em parâmetro diferente
- **Method Switching**: GET em vez de POST (bypass comum)
- **Case Sensitivity**: Variações de maiúsculas/minúsculas
- **Token in Header vs Body**: Validação de localização
- **Token Duplication**: Token duplicado em cookie e body
- **Token Reuse**: Tentativa de reusar tokens antigos
- **Length Manipulation**: Tokens muito curtos ou longos
- **Null Byte Injection**: `%00` no token
- **Array/Object Confusion**: `csrf_token[]=value`

**Exemplo de código vulnerável (Python/Flask):**

```python
@app.route('/update', methods=['POST'])
def update():
    # VULNERÁVEL: Não valida token CSRF
    user_id = request.form.get('user_id')
    new_email = request.form.get('email')
    update_user_email(user_id, new_email)
    return "Email updated"
```

**Código seguro:**

```python
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

@app.route('/update', methods=['POST'])
@csrf.protect
def update():
    # SEGURO: Flask-WTF valida token automaticamente
    user_id = request.form.get('user_id')
    new_email = request.form.get('email')
    update_user_email(user_id, new_email)
    return "Email updated"
```

### 2. CSRF Referer Validation (20 testes)

Testa a validação do cabeçalho `Referer`:

- **Missing Referer**: Requisições sem cabeçalho Referer
- **Empty Referer**: Referer vazio
- **Evil Domain**: Referer de domínio malicioso
- **Subdomain Bypass**: `https://example.com.evil.com/`
- **Path Suffix**: `https://evil.com/example.com`
- **Query/Fragment Bypass**: `https://evil.com/?victim=example.com`
- **Case Sensitivity**: Variações de case
- **Protocol Bypass**: HTTP em vez de HTTPS
- **Null Origin**: `Origin: null`
- **Malformed URLs**: URLs mal formadas
- **URL Encoding**: Encoding no Referer
- **Whitelist Bypass com @**: `https://example.com@evil.com/`
- **Port Variation**: Portas diferentes

**Código vulnerável (PHP):**

```php
// VULNERÁVEL: Validação fraca de Referer
if (strpos($_SERVER['HTTP_REFERER'], 'example.com') !== false) {
    // Permite https://example.com.evil.com/
    process_payment();
}
```

**Código seguro (PHP):**

```php
// SEGURO: Validação rigorosa de Referer
$allowed_hosts = ['example.com', 'www.example.com'];
$referer = parse_url($_SERVER['HTTP_REFERER'] ?? '', PHP_URL_HOST);

if (!in_array($referer, $allowed_hosts, true)) {
    http_response_code(403);
    exit('Invalid referer');
}
```

### 3. CSRF SameSite Cookie (15 testes)

Testa a proteção via atributo `SameSite` em cookies:

- **No SameSite Attribute**: Cookie sem atributo SameSite
- **SameSite=None sem Secure**: Configuração insegura
- **Cross-site Context**: Requisições cross-origin
- **Top-level Navigation**: Navegação Lax
- **iframe Context**: Embeds em iframes
- **XHR/Fetch Context**: Requisições AJAX cross-site
- **Subdomain Requests**: Requisições entre subdomínios
- **Method Variations**: GET vs POST
- **HTTPS→HTTP Downgrade**: Downgrade de protocolo
- **Cookie Prefixes**: `__Host-` e `__Secure-`
- **WebSocket Origin**: Proteção WebSocket
- **Fetch Metadata**: `Sec-Fetch-Site` headers

**Atributos SameSite:**

- `SameSite=Strict`: Cookie nunca enviado em contexto cross-site
- `SameSite=Lax`: Cookie enviado apenas em navegação top-level (GET)
- `SameSite=None`: Cookie enviado em qualquer contexto (requer `Secure`)

**Configuração segura (PHP):**

```php
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => 'example.com',
    'secure' => true,      // Apenas HTTPS
    'httponly' => true,    // Não acessível via JS
    'samesite' => 'Strict' // Proteção CSRF
]);
session_start();
```

**Nginx:**

```nginx
# Configuração de cookies seguros
proxy_cookie_path / "/; HTTPOnly; Secure; SameSite=Strict";
```

### 4. CSRF Content-Type (20 testes)

Testa bypass via manipulação de `Content-Type`:

- **Simple Request Types**: `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`
- **JSON as text/plain**: Bypass de preflight CORS
- **JSON with charset**: `application/json;charset=UTF-8`
- **Missing Content-Type**: Requisição sem header
- **Invalid MIME**: Tipos MIME inválidos
- **Case Variation**: UPPERCASE/MixedCase
- **Charset Variations**: UTF-8, ISO-8859-1
- **XML**: `application/xml`, `text/xml`
- **Custom Types**: `application/x-custom`
- **Flash (legacy)**: `application/x-amf`
- **Malformed**: Espaços extras, trailing semicolon
- **Binary**: `application/octet-stream`
- **Double Header**: Múltiplos headers Content-Type

**Ataque via text/plain (bypass de preflight):**

```javascript
// ATAQUE: Usa text/plain para evitar preflight CORS
fetch('https://bank.com/transfer', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'text/plain' },
  body: JSON.stringify({ to: 'attacker', amount: 1000 })
});
```

**Defesa (Node.js/Express):**

```javascript
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.post('/transfer', csrfProtection, (req, res) => {
  // Valida Content-Type
  const ct = req.get('Content-Type');
  if (!ct || !ct.includes('application/json')) {
    return res.status(415).send('Unsupported Media Type');
  }
  
  // Processa transferência
  const { to, amount } = req.body;
  transfer(to, amount);
  res.send('OK');
});
```

### 5. CSRF CORS & Origin (15 testes)

Testa a validação do cabeçalho `Origin`:

- **Missing Origin**: Sem cabeçalho Origin
- **Null Origin**: `Origin: null`
- **Evil Origin**: Domínio malicioso
- **Subdomain Bypass**: Tentativas de bypass
- **Wildcard CORS**: `Access-Control-Allow-Origin: *`
- **Credentials com Wildcard**: Configuração insegura
- **Port Variations**: Portas diferentes
- **HTTP vs HTTPS**: Protocolo diferente
- **Malformed Origin**: Origin mal formado
- **File Protocol**: `Origin: file://`
- **Case Sensitivity**: Variações de case
- **Preflight Bypass**: Requisições simples
- **WebSocket**: `ws://` protocol

**Configuração CORS insegura (Express):**

```javascript
// VULNERÁVEL: Wildcard com credentials
app.use(cors({
  origin: '*',
  credentials: true  // PERIGOSO com wildcard!
}));
```

**Configuração segura:**

```javascript
const allowedOrigins = ['https://example.com', 'https://app.example.com'];

app.use(cors({
  origin: function(origin, callback) {
    // Permite requisições sem Origin (mobile apps, Postman)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) === -1) {
      return callback(new Error('Not allowed by CORS'));
    }
    return callback(null, true);
  },
  credentials: true
}));
```

## Uso

### Executar apenas testes CSRF

```bash
./head-test.sh -u https://example.com -c csrf
```

### Executar todos os testes (incluindo CSRF)

```bash
./head-test.sh -u https://example.com -c all
```

### Com filtro (apenas falhas)

```bash
./head-test.sh -u https://example.com -c csrf -f fail
```

### Modo verbose

```bash
./head-test.sh -u https://example.com -c csrf -v
```

## Arquitetura

```
head-test.sh
├── source csrf-tester.sh
│   ├── test_csrf_token_validation()
│   ├── test_csrf_referer_validation()
│   ├── test_csrf_samesite()
│   ├── test_csrf_content_type()
│   ├── test_csrf_cors_origin()
│   └── run_all_csrf_tests() [função principal]
└── PayloadsAllTheThings/Cross-Site Request Forgery/
    └── README.md
```

## Quantidade de Testes

**Total: 90 testes de CSRF**

Distribuídos em:
- 20 testes de Token Validation
- 20 testes de Referer Validation
- 15 testes de SameSite Cookie
- 20 testes de Content-Type
- 15 testes de CORS & Origin

## Proteções Recomendadas

### 1. CSRF Tokens (Synchronizer Token Pattern)

**Implementação básica (PHP):**

```php
session_start();

// Gerar token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Validar token
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
        http_response_code(403);
        exit('CSRF token validation failed');
    }
}
```

**No formulário HTML:**

```html
<form method="POST" action="/update">
  <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
  <input type="email" name="email">
  <button type="submit">Update</button>
</form>
```

### 2. SameSite Cookies

```http
Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Strict
```

### 3. Double Submit Cookie

```javascript
// Gerar token
const csrfToken = crypto.randomUUID();
document.cookie = `csrf_token=${csrfToken}; Secure; SameSite=Strict`;

// Enviar em requisições
fetch('/api/update', {
  method: 'POST',
  headers: {
    'X-CSRF-Token': csrfToken,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify(data)
});
```

### 4. Verificação de Origin/Referer

**Express middleware:**

```javascript
function validateOrigin(req, res, next) {
  const origin = req.get('Origin') || req.get('Referer');
  const allowed = ['https://example.com'];
  
  if (!origin || !allowed.some(url => origin.startsWith(url))) {
    return res.status(403).send('Invalid origin');
  }
  next();
}

app.use('/api', validateOrigin);
```

### 5. Custom Request Headers

```javascript
// Cliente adiciona header customizado
fetch('/api/update', {
  method: 'POST',
  headers: {
    'X-Requested-With': 'XMLHttpRequest',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify(data)
});

// Servidor valida
if (!req.get('X-Requested-With')) {
  return res.status(403).send('Invalid request');
}
```

## Frameworks com Proteção CSRF Integrada

### Django (Python)

```python
from django.views.decorators.csrf import csrf_protect

@csrf_protect
def update_view(request):
    # Automático: Django valida token CSRF
    pass
```

```html
<!-- Template -->
<form method="post">
  {% csrf_token %}
  <!-- campos -->
</form>
```

### Laravel (PHP)

```php
// Middleware CSRF ativo por padrão para rotas web
Route::post('/update', [UserController::class, 'update']);
```

```blade
<!-- Blade template -->
<form method="POST" action="/update">
  @csrf
  <!-- campos -->
</form>
```

### Spring (Java)

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http.csrf().csrfTokenRepository(
            CookieCsrfTokenRepository.withHttpOnlyFalse()
        );
        return http.build();
    }
}
```

### ASP.NET Core (C#)

```csharp
services.AddAntiforgery(options => {
    options.HeaderName = "X-CSRF-TOKEN";
});
```

```html
@Html.AntiForgeryToken()
```

## Casos de Uso

### 1. Auditoria de Segurança

```bash
# Verificar proteções CSRF em aplicação
./head-test.sh -u https://myapp.com -c csrf
```

### 2. Testes de Penetração

```bash
# Testar bypass de proteções
./head-test.sh -u https://target.com -c csrf -v
```

### 3. CI/CD Pipeline

```bash
# Integrar em pipeline de CI
./head-test.sh -u https://staging.example.com -c csrf -f fail || exit 1
```

## Comparação com Outras Ferramentas

| Ferramenta | Propósito | CSRF Testing |
|------------|-----------|--------------|
| **CSRF Tester** | Script focado em CSRF | ✅ 90 testes especializados |
| **Burp Suite** | Proxy interceptor | ✅ Scanner CSRF, manual testing |
| **OWASP ZAP** | Security scanner | ✅ Active/Passive CSRF scanning |
| **CSRFTester** | CSRF PoC generator | ✅ PoC generation, não testes automáticos |

**Vantagens do csrf-tester.sh:**
- ✅ Testes automatizados e rápidos
- ✅ Integração fácil em CI/CD
- ✅ Cobertura de cases edge
- ✅ Baseado em PayloadsAllTheThings
- ✅ Sem necessidade de GUI

## Interpretando Resultados

| Resultado | Significado | Ação Recomendada |
|-----------|-------------|------------------|
| ✓ PASS | Servidor bloqueou (403, 400) | ✅ Proteção OK |
| ✗ FAIL | Servidor aceitou (200, 302) | ❌ Implementar proteção CSRF |
| ? WARN | Comportamento inesperado | ⚠️ Investigar manualmente |

**Taxa de sucesso recomendada: 95-100%**

## Limitações

1. **Não testa lógica de negócio**: O script apenas valida se o servidor bloqueia requisições suspeitas
2. **Não gera PoCs funcionais**: Não cria exploit completo HTML
3. **Sem autenticação**: Não testa cenários autenticados (precisa de customização)
4. **Testes superficiais**: Não verifica se ações foram realmente executadas

## Próximos Passos

Possíveis melhorias futuras:

1. **Modo Autenticado**: Suporte a cookies de sessão
2. **PoC Generator**: Gerar HTML de exploit CSRF
3. **Custom Endpoints**: Testar endpoints específicos
4. **Reporting**: Relatórios detalhados de CSRF
5. **Integration**: Integração com Burp Collaborator

## Contribuindo

Para adicionar novos testes CSRF:

1. Edite `csrf-tester.sh`
2. Adicione testes na categoria apropriada
3. Siga o padrão existente: `test_curl "Descrição" "block" ...`
4. Execute testes para validar

## Referências

- [PayloadsAllTheThings - CSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Cross-Site%20Request%20Forgery)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger - CSRF](https://portswigger.net/web-security/csrf)
- [MDN - SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
- [CSRF Token Best Practices](https://security.stackexchange.com/questions/tagged/csrf)

## Licença

MIT License - Veja [LICENSE](LICENSE) para mais detalhes.
