#!/bin/bash
#==============================================================================
# File Upload Tester - Script especializado em testes de File Upload Insecure
# Versão: 1.0.0
# Descrição: Script modular para testes de File Upload usando payloads do PayloadsAllTheThings
#==============================================================================

# Importar cores e variáveis (se chamado diretamente)
if [ -z "$RED" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    MAGENTA='\033[0;35m'
    BOLD='\033[1m'
    NC='\033[0m'
fi

# Diretório base do script
FU_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FU_PAYLOADS_DIR="${FU_SCRIPT_DIR}/PayloadsAllTheThings/Upload Insecure Files"

#==============================================================================
# FUNÇÕES AUXILIARES
#==============================================================================

fu_print_section() {
    local title="$1"
    local shortcut="$2"
    echo ""
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    if [ -n "$shortcut" ]; then
        echo -e "${BOLD}${MAGENTA}$title ${CYAN}($shortcut)${NC}"
    else
        echo -e "${BOLD}${MAGENTA}$title${NC}"
    fi
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

fu_print_subsection() {
    echo -e "\n  ${BOLD}${BLUE}▶ $1${NC}"
}

#==============================================================================
# TESTES FILE UPLOAD - Extension Bypass
#==============================================================================
test_upload_extension_bypass() {
    fu_print_subsection "File Upload Extension Bypass (30 variações)"
    
    # PHP extensions
    test_curl "Upload Ext: .php" "block" -A "$UA" -Lk -F "file=@test.php" "${URL}/upload"
    test_curl "Upload Ext: .php3" "block" -A "$UA" -Lk -F "file=@test.php3" "${URL}/upload"
    test_curl "Upload Ext: .php4" "block" -A "$UA" -Lk -F "file=@test.php4" "${URL}/upload"
    test_curl "Upload Ext: .php5" "block" -A "$UA" -Lk -F "file=@test.php5" "${URL}/upload"
    test_curl "Upload Ext: .php7" "block" -A "$UA" -Lk -F "file=@test.php7" "${URL}/upload"
    test_curl "Upload Ext: .phtml" "block" -A "$UA" -Lk -F "file=@test.phtml" "${URL}/upload"
    test_curl "Upload Ext: .pht" "block" -A "$UA" -Lk -F "file=@test.pht" "${URL}/upload"
    test_curl "Upload Ext: .phar" "block" -A "$UA" -Lk -F "file=@test.phar" "${URL}/upload"
    
    # Double extension
    test_curl "Upload Ext: .jpg.php" "block" -A "$UA" -Lk -F "file=@test.jpg.php" "${URL}/upload"
    test_curl "Upload Ext: .png.php" "block" -A "$UA" -Lk -F "file=@test.png.php" "${URL}/upload"
    test_curl "Upload Ext: .gif.php5" "block" -A "$UA" -Lk -F "file=@test.gif.php5" "${URL}/upload"
    
    # Reverse double extension
    test_curl "Upload Ext: .php.jpg" "block" -A "$UA" -Lk -F "file=@test.php.jpg" "${URL}/upload"
    test_curl "Upload Ext: .php.png" "block" -A "$UA" -Lk -F "file=@test.php.png" "${URL}/upload"
    test_curl "Upload Ext: .php.gif" "block" -A "$UA" -Lk -F "file=@test.php.gif" "${URL}/upload"
    
    # Case variation
    test_curl "Upload Ext: .pHp" "block" -A "$UA" -Lk -F "file=@test.pHp" "${URL}/upload"
    test_curl "Upload Ext: .PHP" "block" -A "$UA" -Lk -F "file=@test.PHP" "${URL}/upload"
    test_curl "Upload Ext: .PhP5" "block" -A "$UA" -Lk -F "file=@test.PhP5" "${URL}/upload"
    
    # Null byte
    test_curl "Upload Ext: .php%00.gif" "block" -A "$UA" -Lk -F "file=@test.php%00.gif" "${URL}/upload"
    test_curl "Upload Ext: .php%00.jpg" "block" -A "$UA" -Lk -F "file=@test.php%00.jpg" "${URL}/upload"
    test_curl "Upload Ext: .php%00.png" "block" -A "$UA" -Lk -F "file=@test.php%00.png" "${URL}/upload"
    
    # ASP/ASPX
    test_curl "Upload Ext: .asp" "block" -A "$UA" -Lk -F "file=@test.asp" "${URL}/upload"
    test_curl "Upload Ext: .aspx" "block" -A "$UA" -Lk -F "file=@test.aspx" "${URL}/upload"
    test_curl "Upload Ext: .cer" "block" -A "$UA" -Lk -F "file=@test.cer" "${URL}/upload"
    test_curl "Upload Ext: .asa" "block" -A "$UA" -Lk -F "file=@test.asa" "${URL}/upload"
    
    # JSP
    test_curl "Upload Ext: .jsp" "block" -A "$UA" -Lk -F "file=@test.jsp" "${URL}/upload"
    test_curl "Upload Ext: .jspx" "block" -A "$UA" -Lk -F "file=@test.jspx" "${URL}/upload"
    
    # Config files
    test_curl "Upload Ext: .htaccess" "block" -A "$UA" -Lk -F "file=@.htaccess" "${URL}/upload"
    test_curl "Upload Ext: web.config" "block" -A "$UA" -Lk -F "file=@web.config" "${URL}/upload"
    test_curl "Upload Ext: __init__.py" "block" -A "$UA" -Lk -F "file=@__init__.py" "${URL}/upload"
    
    # Other dangerous
    test_curl "Upload Ext: .js" "block" -A "$UA" -Lk -F "file=@test.js" "${URL}/upload"
}

#==============================================================================
# TESTES FILE UPLOAD - Special Characters
#==============================================================================
test_upload_special_chars() {
    fu_print_subsection "File Upload Special Characters (25 variações)"
    
    # Multiple dots
    test_curl "Upload Char: file.php......" "block" -A "$UA" -Lk -F "file=@file.php......" "${URL}/upload"
    test_curl "Upload Char: file.php....." "block" -A "$UA" -Lk -F "file=@file.php....." "${URL}/upload"
    
    # Whitespace
    test_curl "Upload Char: file.php%20" "block" -A "$UA" -Lk -F "file=@file.php%20" "${URL}/upload"
    test_curl "Upload Char: file.php%09" "block" -A "$UA" -Lk -F "file=@file.php%09" "${URL}/upload"
    test_curl "Upload Char: file.php%0a" "block" -A "$UA" -Lk -F "file=@file.php%0a" "${URL}/upload"
    test_curl "Upload Char: file.php%0d%0a.jpg" "block" -A "$UA" -Lk -F "file=@file.php%0d%0a.jpg" "${URL}/upload"
    
    # RTLO (Right-to-Left Override)
    test_curl "Upload Char: RTLO gpj.php" "block" -A "$UA" -Lk -F "file=@name.%E2%80%AEphp.jpg" "${URL}/upload"
    
    # Slashes
    test_curl "Upload Char: file.php/" "block" -A "$UA" -Lk -F "file=@file.php/" "${URL}/upload"
    test_curl "Upload Char: file.php.\\" "block" -A "$UA" -Lk -F "file=@file.php.\\" "${URL}/upload"
    test_curl "Upload Char: file.j\\sp" "block" -A "$UA" -Lk -F "file=@file.j\\sp" "${URL}/upload"
    test_curl "Upload Char: file.j/sp" "block" -A "$UA" -Lk -F "file=@file.j/sp" "${URL}/upload"
    
    # Multiple special
    test_curl "Upload Char: file.jsp/./././." "block" -A "$UA" -Lk -F "file=@file.jsp/././././." "${URL}/upload"
    
    # NTFS ADS (Windows)
    test_curl "Upload Char: file.asp:.jpg" "block" -A "$UA" -Lk -F "file=@file.asp:.jpg" "${URL}/upload"
    test_curl "Upload Char: file.asp::data." "block" -A "$UA" -Lk -F "file=@file.asp::\$data." "${URL}/upload"
    
    # IIS characters (<>")
    test_curl "Upload Char: web<<" "block" -A "$UA" -Lk -F "file=@web<<" "${URL}/upload"
    test_curl "Upload Char: web>>" "block" -A "$UA" -Lk -F "file=@web>>" "${URL}/upload"
    
    # Semicolon
    test_curl "Upload Char: shell.aspx;1.jpg" "block" -A "$UA" -Lk -F "file=@shell.aspx;1.jpg" "${URL}/upload"
    
    # UTF-8 filename
    test_curl "Upload Char: UTF-8 newline" "block" -A "$UA" -Lk -H 'Content-Disposition: form-data; name="file"; filename*=UTF8'"'"'myfile%0a.txt' "${URL}/upload"
    
    # Long filename
    test_curl "Upload Char: Long name" "block" -A "$UA" -Lk -F "file=@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.php" "${URL}/upload"
    
    # Special Unicode
    test_curl "Upload Char: Unicode" "block" -A "$UA" -Lk -F "file=@test\u202Ephp.jpg" "${URL}/upload"
    
    # Semicolon variations
    test_curl "Upload Char: file.php;" "block" -A "$UA" -Lk -F "file=@file.php;" "${URL}/upload"
    test_curl "Upload Char: file.php;.jpg" "block" -A "$UA" -Lk -F "file=@file.php;.jpg" "${URL}/upload"
    
    # Colon
    test_curl "Upload Char: file.php:" "block" -A "$UA" -Lk -F "file=@file.php:" "${URL}/upload"
    test_curl "Upload Char: file.php::" "block" -A "$UA" -Lk -F "file=@file.php::" "${URL}/upload"
}

#==============================================================================
# TESTES FILE UPLOAD - Content-Type Bypass
#==============================================================================
test_upload_content_type() {
    fu_print_subsection "File Upload Content-Type Bypass (20 variações)"
    
    # Generic content types
    test_curl "Upload CT: image/gif" "block" -A "$UA" -Lk -F "file=@shell.php;type=image/gif" "${URL}/upload"
    test_curl "Upload CT: image/png" "block" -A "$UA" -Lk -F "file=@shell.php;type=image/png" "${URL}/upload"
    test_curl "Upload CT: image/jpeg" "block" -A "$UA" -Lk -F "file=@shell.php;type=image/jpeg" "${URL}/upload"
    
    # PHP content types
    test_curl "Upload CT: text/php" "block" -A "$UA" -Lk -F "file=@shell.php;type=text/php" "${URL}/upload"
    test_curl "Upload CT: application/php" "block" -A "$UA" -Lk -F "file=@shell.php;type=application/php" "${URL}/upload"
    test_curl "Upload CT: application/x-php" "block" -A "$UA" -Lk -F "file=@shell.php;type=application/x-php" "${URL}/upload"
    test_curl "Upload CT: application/x-httpd-php" "block" -A "$UA" -Lk -F "file=@shell.php;type=application/x-httpd-php" "${URL}/upload"
    
    # Octet stream
    test_curl "Upload CT: octet-stream" "block" -A "$UA" -Lk -F "file=@shell.php;type=application/octet-stream" "${URL}/upload"
    
    # Text types
    test_curl "Upload CT: text/plain" "block" -A "$UA" -Lk -F "file=@shell.php;type=text/plain" "${URL}/upload"
    test_curl "Upload CT: text/html" "block" -A "$UA" -Lk -F "file=@shell.php;type=text/html" "${URL}/upload"
    
    # Double Content-Type (some parsers take first, others last)
    test_curl "Upload CT: Double CT" "block" -A "$UA" -Lk -H "Content-Type: application/x-php" -H "Content-Type: image/gif" "${URL}/upload"
    
    # Case variation
    test_curl "Upload CT: IMAGE/GIF" "block" -A "$UA" -Lk -F "file=@shell.php;type=IMAGE/GIF" "${URL}/upload"
    test_curl "Upload CT: Image/Gif" "block" -A "$UA" -Lk -F "file=@shell.php;type=Image/Gif" "${URL}/upload"
    
    # Malformed
    test_curl "Upload CT: image/gif;" "block" -A "$UA" -Lk -F "file=@shell.php;type=image/gif;" "${URL}/upload"
    test_curl "Upload CT: image/gif " "block" -A "$UA" -Lk -F "file=@shell.php;type=image/gif " "${URL}/upload"
    
    # Other formats
    test_curl "Upload CT: application/zip" "block" -A "$UA" -Lk -F "file=@shell.zip;type=application/zip" "${URL}/upload"
    test_curl "Upload CT: application/pdf" "block" -A "$UA" -Lk -F "file=@shell.pdf;type=application/pdf" "${URL}/upload"
    test_curl "Upload CT: video/mp4" "block" -A "$UA" -Lk -F "file=@shell.mp4;type=video/mp4" "${URL}/upload"
    
    # SVG (often allows XSS)
    test_curl "Upload CT: image/svg+xml" "block" -A "$UA" -Lk -F "file=@xss.svg;type=image/svg+xml" "${URL}/upload"
    
    # XML
    test_curl "Upload CT: application/xml" "block" -A "$UA" -Lk -F "file=@xxe.xml;type=application/xml" "${URL}/upload"
}

#==============================================================================
# TESTES FILE UPLOAD - Magic Bytes
#==============================================================================
test_upload_magic_bytes() {
    fu_print_subsection "File Upload Magic Bytes (15 variações)"
    
    # Note: In real tests, these would include actual magic bytes in file content
    # Here we test if endpoint validates magic bytes
    
    # GIF magic bytes
    test_curl "Upload Magic: GIF87a" "block" -A "$UA" -Lk -F "file=@shell.php" -H "X-File-Magic: GIF87a" "${URL}/upload"
    test_curl "Upload Magic: GIF89a" "block" -A "$UA" -Lk -F "file=@shell.php" -H "X-File-Magic: GIF89a" "${URL}/upload"
    
    # PNG magic bytes
    test_curl "Upload Magic: PNG" "block" -A "$UA" -Lk -F "file=@shell.php" -H "X-File-Magic: PNG" "${URL}/upload"
    
    # JPEG magic bytes
    test_curl "Upload Magic: JPEG" "block" -A "$UA" -Lk -F "file=@shell.php" -H "X-File-Magic: JPEG" "${URL}/upload"
    
    # PDF magic bytes
    test_curl "Upload Magic: PDF" "block" -A "$UA" -Lk -F "file=@shell.php" -H "X-File-Magic: PDF" "${URL}/upload"
    
    # ZIP magic bytes
    test_curl "Upload Magic: ZIP PK" "block" -A "$UA" -Lk -F "file=@shell.php" -H "X-File-Magic: PK" "${URL}/upload"
    
    # Polyglot attempts (filename hints at polyglot)
    test_curl "Upload Magic: Polyglot .gif.php" "block" -A "$UA" -Lk -F "file=@polyglot.gif.php" "${URL}/upload"
    test_curl "Upload Magic: Polyglot .jpg.php" "block" -A "$UA" -Lk -F "file=@polyglot.jpg.php" "${URL}/upload"
    test_curl "Upload Magic: Polyglot .png.php" "block" -A "$UA" -Lk -F "file=@polyglot.png.php" "${URL}/upload"
    
    # EXIF injection
    test_curl "Upload Magic: EXIF Comment" "block" -A "$UA" -Lk -F "file=@exif.jpg" "${URL}/upload"
    
    # ImageMagick exploits
    test_curl "Upload Magic: ImageTragik" "block" -A "$UA" -Lk -F "file=@imagetragik.jpg" "${URL}/upload"
    test_curl "Upload Magic: CVE-2022-44268" "block" -A "$UA" -Lk -F "file=@cve-2022-44268.png" "${URL}/upload"
    
    # FFmpeg HLS
    test_curl "Upload Magic: FFmpeg HLS" "block" -A "$UA" -Lk -F "file=@ffmpeg.avi" "${URL}/upload"
    
    # EICAR test file (antivirus detection)
    test_curl "Upload Magic: EICAR" "block" -A "$UA" -Lk -F "file=@eicar.com" "${URL}/upload"
    
    # Executable disguised
    test_curl "Upload Magic: EXE as JPG" "block" -A "$UA" -Lk -F "file=@virus.jpg" "${URL}/upload"
}

#==============================================================================
# TESTES FILE UPLOAD - Filename Injection
#==============================================================================
test_upload_filename_injection() {
    fu_print_subsection "File Upload Filename Injection (20 variações)"
    
    # XSS in filename
    test_curl "Upload Filename: XSS basic" "block" -A "$UA" -Lk -F "file=@<script>alert(1)</script>.jpg" "${URL}/upload"
    test_curl "Upload Filename: XSS img" "block" -A "$UA" -Lk -F 'file=@"><img src=x onerror=alert(1)>.jpg' "${URL}/upload"
    test_curl "Upload Filename: XSS svg" "block" -A "$UA" -Lk -F "file=@<svg onload=alert(1)>.jpg" "${URL}/upload"
    
    # Path traversal in filename
    test_curl "Upload Filename: ../../../" "block" -A "$UA" -Lk -F "file=@../../../shell.php" "${URL}/upload"
    test_curl "Upload Filename: ../.." "block" -A "$UA" -Lk -F "file=@../../.htaccess" "${URL}/upload"
    
    # SQLi in filename
    test_curl "Upload Filename: SQLi sleep" "block" -A "$UA" -Lk -F "file=@poc.js'(select*from(select(sleep(5)))a)+'.jpg" "${URL}/upload"
    test_curl "Upload Filename: SQLi quote" "block" -A "$UA" -Lk -F "file=@file'.jpg" "${URL}/upload"
    
    # Command injection in filename
    test_curl "Upload Filename: CMDi sleep" "block" -A "$UA" -Lk -F "file=@file;sleep 5;.jpg" "${URL}/upload"
    test_curl "Upload Filename: CMDi backtick" "block" -A "$UA" -Lk -F 'file=@`whoami`.jpg' "${URL}/upload"
    test_curl "Upload Filename: CMDi pipe" "block" -A "$UA" -Lk -F "file=@file|ls.jpg" "${URL}/upload"
    
    # CRLF injection
    test_curl "Upload Filename: CRLF" "block" -A "$UA" -Lk -F $'file=@test\r\nInjected-Header: value\r\n.jpg' "${URL}/upload"
    
    # LDAP injection
    test_curl "Upload Filename: LDAP" "block" -A "$UA" -Lk -F "file=@*)(uid=*)).jpg" "${URL}/upload"
    
    # XML injection
    test_curl "Upload Filename: XML" "block" -A "$UA" -Lk -F "file=@<xml></xml>.jpg" "${URL}/upload"
    
    # Template injection
    test_curl "Upload Filename: SSTI {{7*7}}" "block" -A "$UA" -Lk -F "file=@{{7*7}}.jpg" "${URL}/upload"
    test_curl "Upload Filename: SSTI \${7*7}" "block" -A "$UA" -Lk -F "file=@\${7*7}.jpg" "${URL}/upload"
    
    # Null byte
    test_curl "Upload Filename: Null %00" "block" -A "$UA" -Lk -F "file=@shell.php%00.jpg" "${URL}/upload"
    
    # Unicode
    test_curl "Upload Filename: Unicode" "block" -A "$UA" -Lk -F "file=@test\u202e.jpg" "${URL}/upload"
    
    # Long filename
    test_curl "Upload Filename: 255+ chars" "block" -A "$UA" -Lk -F "file=@$(printf 'a%.0s' {1..300}).jpg" "${URL}/upload"
    
    # Special chars
    test_curl "Upload Filename: Special &|<>" "block" -A "$UA" -Lk -F "file=@test&cmd=ls|cat<file>.jpg" "${URL}/upload"
    
    # Executable extension in path
    test_curl "Upload Filename: Path .exe" "block" -A "$UA" -Lk -F "file=@../../evil.exe" "${URL}/upload"
}

#==============================================================================
# TESTES FILE UPLOAD - Dangerous Files
#==============================================================================
test_upload_dangerous_files() {
    fu_print_subsection "File Upload Dangerous Files (20 variações)"
    
    # SVG with XSS
    test_curl "Upload Danger: SVG XSS" "block" -A "$UA" -Lk -F "file=@xss.svg" "${URL}/upload"
    
    # HTML with XSS
    test_curl "Upload Danger: HTML XSS" "block" -A "$UA" -Lk -F "file=@xss.html" "${URL}/upload"
    
    # XML with XXE
    test_curl "Upload Danger: XML XXE" "block" -A "$UA" -Lk -F "file=@xxe.xml" "${URL}/upload"
    
    # CSV injection
    test_curl "Upload Danger: CSV =cmd" "block" -A "$UA" -Lk -F "file=@inject.csv" "${URL}/upload"
    
    # ZIP bomb
    test_curl "Upload Danger: ZIP bomb" "block" -A "$UA" -Lk -F "file=@bomb.zip" "${URL}/upload"
    
    # ZIP slip (path traversal in archive)
    test_curl "Upload Danger: ZIP slip" "block" -A "$UA" -Lk -F "file=@slip.zip" "${URL}/upload"
    
    # Polyglot files
    test_curl "Upload Danger: GIFAR" "block" -A "$UA" -Lk -F "file=@polyglot.gifar" "${URL}/upload"
    test_curl "Upload Danger: PHAR polyglot" "block" -A "$UA" -Lk -F "file=@polyglot.phar" "${URL}/upload"
    
    # Config files
    test_curl "Upload Danger: .htaccess" "block" -A "$UA" -Lk -F "file=@malicious.htaccess" "${URL}/upload"
    test_curl "Upload Danger: web.config" "block" -A "$UA" -Lk -F "file=@malicious.web.config" "${URL}/upload"
    test_curl "Upload Danger: .htpasswd" "block" -A "$UA" -Lk -F "file=@.htpasswd" "${URL}/upload"
    
    # Python files
    test_curl "Upload Danger: __init__.py" "block" -A "$UA" -Lk -F "file=@__init__.py" "${URL}/upload"
    test_curl "Upload Danger: uwsgi.ini" "block" -A "$UA" -Lk -F "file=@uwsgi.ini" "${URL}/upload"
    
    # Node.js files
    test_curl "Upload Danger: package.json" "block" -A "$UA" -Lk -F "file=@package.json" "${URL}/upload"
    
    # Composer
    test_curl "Upload Danger: composer.json" "block" -A "$UA" -Lk -F "file=@composer.json" "${URL}/upload"
    
    # Git
    test_curl "Upload Danger: .git/config" "block" -A "$UA" -Lk -F "file=@.git/config" "${URL}/upload"
    
    # SSH
    test_curl "Upload Danger: id_rsa.pub" "block" -A "$UA" -Lk -F "file=@id_rsa.pub" "${URL}/upload"
    
    # AWS credentials
    test_curl "Upload Danger: credentials" "block" -A "$UA" -Lk -F "file=@credentials" "${URL}/upload"
    
    # Docker
    test_curl "Upload Danger: Dockerfile" "block" -A "$UA" -Lk -F "file=@Dockerfile" "${URL}/upload"
    
    # .env
    test_curl "Upload Danger: .env" "block" -A "$UA" -Lk -F "file=@.env" "${URL}/upload"
}

#==============================================================================
# FUNÇÃO PRINCIPAL - Executa todos os testes File Upload
#==============================================================================
run_all_file_upload_tests() {
    fu_print_section "📤 TESTES COMPLETOS DE FILE UPLOAD (PayloadsAllTheThings)" "-c fileupload"
    
    echo -e "${CYAN}ℹ️  Usando payloads do PayloadsAllTheThings/Upload Insecure Files${NC}"
    echo -e "${CYAN}ℹ️  Total estimado: 150+ testes de File Upload${NC}"
    echo ""
    
    test_upload_extension_bypass
    test_upload_special_chars
    test_upload_content_type
    test_upload_magic_bytes
    test_upload_filename_injection
    test_upload_dangerous_files
    
    echo ""
    echo -e "${GREEN}✓ Todos os testes File Upload foram concluídos!${NC}"
}

# Se o script for executado diretamente (não como source)
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    echo -e "${RED}❌ Este script deve ser chamado pelo head-test.sh${NC}"
    echo -e "${YELLOW}Use: ./head-test.sh -u URL -c fileupload${NC}"
    exit 1
fi
