#!/bin/bash
#==============================================================================
# CSRF Tester - Script especializado em testes de CSRF (Cross-Site Request Forgery)
# Versão: 1.0.0
# Descrição: Script modular para testes de CSRF usando payloads do PayloadsAllTheThings
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
CSRF_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CSRF_PAYLOADS_DIR="${CSRF_SCRIPT_DIR}/PayloadsAllTheThings/Cross-Site Request Forgery"

#==============================================================================
# FUNÇÕES AUXILIARES
#==============================================================================

csrf_print_section() {
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

csrf_print_subsection() {
    echo -e "\n  ${BOLD}${BLUE}▶ $1${NC}"
}

#==============================================================================
# TESTES CSRF - Token Validation
#==============================================================================
test_csrf_token_validation() {
    csrf_print_subsection "CSRF Token Validation (20 variações)"
    
    # Missing CSRF token
    test_curl "CSRF Token: Missing token" "block" -A "$UA" -Lk -X POST "${URL}/api/update" --data "action=delete&id=123"
    test_curl "CSRF Token: Empty token" "block" -A "$UA" -Lk -X POST "${URL}/api/update" --data "csrf_token=&action=delete"
    
    # Invalid token
    test_curl "CSRF Token: Invalid token" "block" -A "$UA" -Lk -X POST "${URL}/api/update" --data "csrf_token=invalid123&action=delete"
    test_curl "CSRF Token: Random token" "block" -A "$UA" -Lk -X POST "${URL}/api/update" --data "csrf_token=AAAABBBBCCCCDDDD&action=delete"
    
    # Token in different parameter
    test_curl "CSRF Token: Wrong param name" "block" -A "$UA" -Lk -X POST "${URL}/api/update" --data "token=valid&action=delete"
    test_curl "CSRF Token: _token" "block" -A "$UA" -Lk -X POST "${URL}/api/update" --data "_token=&action=delete"
    test_curl "CSRF Token: authenticity_token" "block" -A "$UA" -Lk -X POST "${URL}/api/update" --data "authenticity_token=&action=delete"
    
    # Method switching (token check only on POST)
    test_curl "CSRF Token: GET instead POST" "block" -A "$UA" -Lk "${URL}/api/update?action=delete&id=123"
    test_curl "CSRF Token: PUT method" "block" -A "$UA" -Lk -X PUT "${URL}/api/update" --data "action=delete&id=123"
    test_curl "CSRF Token: DELETE method" "block" -A "$UA" -Lk -X DELETE "${URL}/api/update?id=123"
    
    # Case sensitivity
    test_curl "CSRF Token: UPPERCASE param" "block" -A "$UA" -Lk -X POST "${URL}/api/update" --data "CSRF_TOKEN=&action=delete"
    test_curl "CSRF Token: lowercase param" "block" -A "$UA" -Lk -X POST "${URL}/api/update" --data "csrf_token=&action=delete"
    
    # Token in header vs body
    test_curl "CSRF Token: Header only" "block" -A "$UA" -Lk -X POST -H "X-CSRF-Token: " "${URL}/api/update" --data "action=delete"
    test_curl "CSRF Token: X-XSRF-Token" "block" -A "$UA" -Lk -X POST -H "X-XSRF-Token: invalid" "${URL}/api/update" --data "action=delete"
    
    # Token duplication
    test_curl "CSRF Token: Duplicate in cookie" "block" -A "$UA" -Lk -X POST -b "csrf_token=abc123" "${URL}/api/update" --data "csrf_token=abc123&action=delete"
    
    # Token not tied to session
    test_curl "CSRF Token: Reused token" "block" -A "$UA" -Lk -X POST "${URL}/api/update" --data "csrf_token=OLD_TOKEN_HERE&action=delete"
    
    # Token length manipulation
    test_curl "CSRF Token: Short token" "block" -A "$UA" -Lk -X POST "${URL}/api/update" --data "csrf_token=123&action=delete"
    test_curl "CSRF Token: Long token" "block" -A "$UA" -Lk -X POST "${URL}/api/update" --data "csrf_token=$(printf 'A%.0s' {1..1000})&action=delete"
    
    # Null byte
    test_curl "CSRF Token: Null byte" "block" -A "$UA" -Lk -X POST "${URL}/api/update" --data "csrf_token=%00&action=delete"
    
    # Array/Object confusion
    test_curl "CSRF Token: Array[]" "block" -A "$UA" -Lk -X POST "${URL}/api/update" --data "csrf_token[]=value&action=delete"
}

#==============================================================================
# TESTES CSRF - Referer Validation
#==============================================================================
test_csrf_referer_validation() {
    csrf_print_subsection "CSRF Referer Validation (20 variações)"
    
    # Missing Referer
    test_curl "CSRF Referer: No Referer" "block" -A "$UA" -Lk -X POST "${URL}/api/update" --data "action=delete"
    
    # Empty Referer
    test_curl "CSRF Referer: Empty" "block" -A "$UA" -Lk -X POST -H "Referer: " "${URL}/api/update" --data "action=delete"
    
    # Invalid domain
    test_curl "CSRF Referer: Evil domain" "block" -A "$UA" -Lk -X POST -H "Referer: https://evil.com/" "${URL}/api/update" --data "action=delete"
    test_curl "CSRF Referer: Attacker site" "block" -A "$UA" -Lk -X POST -H "Referer: https://attacker.com/csrf.html" "${URL}/api/update" --data "action=delete"
    
    # Subdomain bypass
    test_curl "CSRF Referer: Subdomain" "block" -A "$UA" -Lk -X POST -H "Referer: https://example.com.evil.com/" "${URL}/api/update" --data "action=delete"
    test_curl "CSRF Referer: Path suffix" "block" -A "$UA" -Lk -X POST -H "Referer: https://evil.com/example.com" "${URL}/api/update" --data "action=delete"
    
    # Regex bypass
    test_curl "CSRF Referer: Query param" "block" -A "$UA" -Lk -X POST -H "Referer: https://evil.com/?victim=example.com" "${URL}/api/update" --data "action=delete"
    test_curl "CSRF Referer: Fragment" "block" -A "$UA" -Lk -X POST -H "Referer: https://evil.com/#example.com" "${URL}/api/update" --data "action=delete"
    
    # Case sensitivity
    test_curl "CSRF Referer: UPPERCASE" "block" -A "$UA" -Lk -X POST -H "Referer: HTTPS://EVIL.COM/" "${URL}/api/update" --data "action=delete"
    test_curl "CSRF Referer: MixedCase" "block" -A "$UA" -Lk -X POST -H "Referer: HtTpS://EvIl.CoM/" "${URL}/api/update" --data "action=delete"
    
    # Protocol bypass
    test_curl "CSRF Referer: HTTP not HTTPS" "block" -A "$UA" -Lk -X POST -H "Referer: http://example.com/" "${URL}/api/update" --data "action=delete"
    test_curl "CSRF Referer: data: URI" "block" -A "$UA" -Lk -X POST -H "Referer: data:text/html,<html></html>" "${URL}/api/update" --data "action=delete"
    
    # Null origin
    test_curl "CSRF Referer: null origin" "block" -A "$UA" -Lk -X POST -H "Origin: null" "${URL}/api/update" --data "action=delete"
    
    # Malformed
    test_curl "CSRF Referer: Malformed URL" "block" -A "$UA" -Lk -X POST -H "Referer: ://evil.com" "${URL}/api/update" --data "action=delete"
    test_curl "CSRF Referer: Space in URL" "block" -A "$UA" -Lk -X POST -H "Referer: https://evil .com/" "${URL}/api/update" --data "action=delete"
    
    # Encoding
    test_curl "CSRF Referer: URL encoded" "block" -A "$UA" -Lk -X POST -H "Referer: https://evil.com%2f" "${URL}/api/update" --data "action=delete"
    test_curl "CSRF Referer: Double encoded" "block" -A "$UA" -Lk -X POST -H "Referer: https://evil.com%252f" "${URL}/api/update" --data "action=delete"
    
    # Whitelist bypass with @
    test_curl "CSRF Referer: @ symbol" "block" -A "$UA" -Lk -X POST -H "Referer: https://example.com@evil.com/" "${URL}/api/update" --data "action=delete"
    
    # Port variation
    test_curl "CSRF Referer: Different port" "block" -A "$UA" -Lk -X POST -H "Referer: https://example.com:8080/" "${URL}/api/update" --data "action=delete"
    
    # Partial match
    test_curl "CSRF Referer: Partial domain" "block" -A "$UA" -Lk -X POST -H "Referer: https://example/" "${URL}/api/update" --data "action=delete"
}

#==============================================================================
# TESTES CSRF - SameSite Cookie
#==============================================================================
test_csrf_samesite() {
    csrf_print_subsection "CSRF SameSite Cookie (15 variações)"
    
    # Cookies without SameSite
    test_curl "CSRF SameSite: No attribute" "block" -A "$UA" -Lk -b "session=abc123" -X POST "${URL}/api/update" --data "action=delete"
    
    # SameSite=None without Secure
    test_curl "CSRF SameSite: None no Secure" "block" -A "$UA" -Lk -b "session=abc123; SameSite=None" -X POST "${URL}/api/update" --data "action=delete"
    
    # Cross-site context
    test_curl "CSRF SameSite: Cross-site GET" "block" -A "$UA" -Lk -H "Referer: https://evil.com/" "${URL}/api/getCurrentUser"
    test_curl "CSRF SameSite: Cross-site POST" "block" -A "$UA" -Lk -H "Referer: https://evil.com/" -X POST "${URL}/api/update" --data "action=delete"
    
    # Top-level navigation
    test_curl "CSRF SameSite: Top nav Lax" "block" -A "$UA" -Lk -H "Sec-Fetch-Site: cross-site" -H "Sec-Fetch-Mode: navigate" "${URL}/api/update?action=delete"
    
    # iframe context
    test_curl "CSRF SameSite: iframe embed" "block" -A "$UA" -Lk -H "Sec-Fetch-Site: cross-site" -H "Sec-Fetch-Dest: iframe" "${URL}/api/update"
    
    # XHR/Fetch context
    test_curl "CSRF SameSite: XHR cross-site" "block" -A "$UA" -Lk -H "Sec-Fetch-Site: cross-site" -H "Sec-Fetch-Mode: cors" -X POST "${URL}/api/update" --data "action=delete"
    
    # Different subdomains
    test_curl "CSRF SameSite: Subdomain" "block" -A "$UA" -Lk -H "Referer: https://sub.example.com/" -X POST "${URL}/api/update" --data "action=delete"
    
    # Method variations
    test_curl "CSRF SameSite: GET safe" "block" -A "$UA" -Lk -H "Sec-Fetch-Site: cross-site" "${URL}/api/getCurrentUser"
    test_curl "CSRF SameSite: POST unsafe" "block" -A "$UA" -Lk -H "Sec-Fetch-Site: cross-site" -X POST "${URL}/api/update" --data "action=delete"
    
    # HTTPS to HTTP downgrade
    test_curl "CSRF SameSite: HTTPS→HTTP" "block" -A "$UA" -Lk -H "Referer: https://example.com/" "http://example.com/api/update?action=delete"
    
    # Cookie prefixes
    test_curl "CSRF SameSite: __Host- prefix" "block" -A "$UA" -Lk -b "__Host-session=abc123" -X POST "${URL}/api/update" --data "action=delete"
    test_curl "CSRF SameSite: __Secure- prefix" "block" -A "$UA" -Lk -b "__Secure-session=abc123" -X POST "${URL}/api/update" --data "action=delete"
    
    # WebSocket
    test_curl "CSRF SameSite: WebSocket origin" "block" -A "$UA" -Lk -H "Origin: https://evil.com" -H "Upgrade: websocket" "${URL}/ws"
    
    # Fetch metadata
    test_curl "CSRF SameSite: Fetch metadata" "block" -A "$UA" -Lk -H "Sec-Fetch-Site: same-origin" -H "Sec-Fetch-Mode: no-cors" -X POST "${URL}/api/update" --data "action=delete"
}

#==============================================================================
# TESTES CSRF - Content-Type
#==============================================================================
test_csrf_content_type() {
    csrf_print_subsection "CSRF Content-Type (20 variações)"
    
    # Form content types (simple requests, no preflight)
    test_curl "CSRF CT: application/x-www-form-urlencoded" "block" -A "$UA" -Lk -X POST -H "Content-Type: application/x-www-form-urlencoded" "${URL}/api/update" --data "action=delete"
    test_curl "CSRF CT: multipart/form-data" "block" -A "$UA" -Lk -X POST -H "Content-Type: multipart/form-data" "${URL}/api/update" --data "action=delete"
    test_curl "CSRF CT: text/plain" "block" -A "$UA" -Lk -X POST -H "Content-Type: text/plain" "${URL}/api/update" --data '{"action":"delete"}'
    
    # JSON (triggers preflight, but can bypass with text/plain)
    test_curl "CSRF CT: JSON as text/plain" "block" -A "$UA" -Lk -X POST -H "Content-Type: text/plain" "${URL}/api/update" --data '{"role":"admin"}'
    test_curl "CSRF CT: JSON charset" "block" -A "$UA" -Lk -X POST -H "Content-Type: application/json;charset=UTF-8" "${URL}/api/update" --data '{"role":"admin"}'
    
    # No Content-Type
    test_curl "CSRF CT: Missing header" "block" -A "$UA" -Lk -X POST "${URL}/api/update" --data "action=delete"
    
    # Invalid Content-Type
    test_curl "CSRF CT: Invalid MIME" "block" -A "$UA" -Lk -X POST -H "Content-Type: invalid/type" "${URL}/api/update" --data "action=delete"
    
    # Case variation
    test_curl "CSRF CT: UPPERCASE" "block" -A "$UA" -Lk -X POST -H "Content-Type: TEXT/PLAIN" "${URL}/api/update" --data "action=delete"
    test_curl "CSRF CT: MixedCase" "block" -A "$UA" -Lk -X POST -H "Content-Type: Text/Plain" "${URL}/api/update" --data "action=delete"
    
    # Charset variations
    test_curl "CSRF CT: UTF-8" "block" -A "$UA" -Lk -X POST -H "Content-Type: text/plain; charset=utf-8" "${URL}/api/update" --data "action=delete"
    test_curl "CSRF CT: ISO-8859-1" "block" -A "$UA" -Lk -X POST -H "Content-Type: text/plain; charset=iso-8859-1" "${URL}/api/update" --data "action=delete"
    
    # Boundary (multipart)
    test_curl "CSRF CT: Multipart boundary" "block" -A "$UA" -Lk -X POST -H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary" "${URL}/api/update" --data "action=delete"
    
    # XML
    test_curl "CSRF CT: application/xml" "block" -A "$UA" -Lk -X POST -H "Content-Type: application/xml" "${URL}/api/update" --data '<root><action>delete</action></root>'
    test_curl "CSRF CT: text/xml" "block" -A "$UA" -Lk -X POST -H "Content-Type: text/xml" "${URL}/api/update" --data '<root><action>delete</action></root>'
    
    # Custom
    test_curl "CSRF CT: application/x-custom" "block" -A "$UA" -Lk -X POST -H "Content-Type: application/x-custom" "${URL}/api/update" --data "action=delete"
    
    # Flash (legacy)
    test_curl "CSRF CT: application/x-amf" "block" -A "$UA" -Lk -X POST -H "Content-Type: application/x-amf" "${URL}/api/update" --data "action=delete"
    
    # Spaces/malformed
    test_curl "CSRF CT: Extra spaces" "block" -A "$UA" -Lk -X POST -H "Content-Type:  text/plain  " "${URL}/api/update" --data "action=delete"
    test_curl "CSRF CT: Trailing semicolon" "block" -A "$UA" -Lk -X POST -H "Content-Type: text/plain;" "${URL}/api/update" --data "action=delete"
    
    # Binary
    test_curl "CSRF CT: octet-stream" "block" -A "$UA" -Lk -X POST -H "Content-Type: application/octet-stream" "${URL}/api/update" --data "action=delete"
    
    # Double header
    test_curl "CSRF CT: Double header" "block" -A "$UA" -Lk -X POST -H "Content-Type: text/plain" -H "Content-Type: application/json" "${URL}/api/update" --data '{"action":"delete"}'
}

#==============================================================================
# TESTES CSRF - CORS & Origin
#==============================================================================
test_csrf_cors_origin() {
    csrf_print_subsection "CSRF CORS & Origin (15 variações)"
    
    # Missing Origin
    test_curl "CSRF Origin: No Origin" "block" -A "$UA" -Lk -X POST "${URL}/api/update" --data "action=delete"
    
    # Null origin
    test_curl "CSRF Origin: null" "block" -A "$UA" -Lk -X POST -H "Origin: null" "${URL}/api/update" --data "action=delete"
    
    # Evil origin
    test_curl "CSRF Origin: evil.com" "block" -A "$UA" -Lk -X POST -H "Origin: https://evil.com" "${URL}/api/update" --data "action=delete"
    
    # Subdomain bypass
    test_curl "CSRF Origin: Subdomain" "block" -A "$UA" -Lk -X POST -H "Origin: https://example.com.evil.com" "${URL}/api/update" --data "action=delete"
    
    # Wildcard CORS
    test_curl "CSRF Origin: Wildcard check" "block" -A "$UA" -Lk -X POST -H "Origin: https://anything.com" "${URL}/api/update" --data "action=delete"
    
    # Credentials with wildcard (should fail)
    test_curl "CSRF Origin: withCredentials" "block" -A "$UA" -Lk -X POST -H "Origin: https://evil.com" -b "session=abc123" "${URL}/api/update" --data "action=delete"
    
    # Different ports
    test_curl "CSRF Origin: Port 8080" "block" -A "$UA" -Lk -X POST -H "Origin: https://example.com:8080" "${URL}/api/update" --data "action=delete"
    test_curl "CSRF Origin: Port 443" "block" -A "$UA" -Lk -X POST -H "Origin: https://example.com:443" "${URL}/api/update" --data "action=delete"
    
    # HTTP vs HTTPS
    test_curl "CSRF Origin: HTTP not HTTPS" "block" -A "$UA" -Lk -X POST -H "Origin: http://example.com" "${URL}/api/update" --data "action=delete"
    
    # Malformed
    test_curl "CSRF Origin: No protocol" "block" -A "$UA" -Lk -X POST -H "Origin: example.com" "${URL}/api/update" --data "action=delete"
    test_curl "CSRF Origin: Malformed" "block" -A "$UA" -Lk -X POST -H "Origin: ://evil.com" "${URL}/api/update" --data "action=delete"
    
    # File protocol
    test_curl "CSRF Origin: file://" "block" -A "$UA" -Lk -X POST -H "Origin: file://" "${URL}/api/update" --data "action=delete"
    
    # Case sensitivity
    test_curl "CSRF Origin: UPPERCASE" "block" -A "$UA" -Lk -X POST -H "Origin: HTTPS://EVIL.COM" "${URL}/api/update" --data "action=delete"
    
    # Preflight bypass
    test_curl "CSRF Origin: Simple req bypass" "block" -A "$UA" -Lk -X POST -H "Content-Type: text/plain" -H "Origin: https://evil.com" "${URL}/api/update" --data "action=delete"
    
    # WebSocket
    test_curl "CSRF Origin: ws:// protocol" "block" -A "$UA" -Lk -H "Origin: ws://evil.com" "${URL}/ws"
}

#==============================================================================
# FUNÇÃO PRINCIPAL - Executa todos os testes CSRF
#==============================================================================
run_all_csrf_tests() {
    csrf_print_section "🔒 TESTES COMPLETOS DE CSRF (PayloadsAllTheThings)" "-c csrf"
    
    echo -e "${CYAN}ℹ️  Usando payloads do PayloadsAllTheThings/Cross-Site Request Forgery${NC}"
    echo -e "${CYAN}ℹ️  Total estimado: 125+ testes de CSRF${NC}"
    echo ""
    
    test_csrf_token_validation
    test_csrf_referer_validation
    test_csrf_samesite
    test_csrf_content_type
    test_csrf_cors_origin
    
    echo ""
    echo -e "${GREEN}✓ Todos os testes CSRF foram concluídos!${NC}"
}

# Se o script for executado diretamente (não como source)
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    echo -e "${RED}❌ Este script deve ser chamado pelo head-test.sh${NC}"
    echo -e "${YELLOW}Use: ./head-test.sh -u URL -c csrf${NC}"
    exit 1
fi
