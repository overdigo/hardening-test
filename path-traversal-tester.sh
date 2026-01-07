#!/bin/bash
#==============================================================================
# Path Traversal Tester - Script especializado em testes de Path/Directory Traversal
# Versão: 1.0.0
# Descrição: Script modular para testes de Path Traversal usando payloads do PayloadsAllTheThings
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
PT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PT_PAYLOADS_DIR="${PT_SCRIPT_DIR}/PayloadsAllTheThings/Directory Traversal"

#==============================================================================
# FUNÇÕES AUXILIARES
#============================================================================== 

pt_print_section() {
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

pt_print_subsection() {
    echo -e "\n  ${BOLD}${BLUE}▶ $1${NC}"
}

#==============================================================================
# TESTES PATH TRAVERSAL BÁSICO - Linux
#==============================================================================
test_pt_basic_linux() {
    pt_print_subsection "Path Traversal Básico - Linux (25 variações)"
    
    # Basic ../ traversal
    test_curl "PT Linux: ../../../etc/passwd" "block" -A "$UA" -Lk "${URL}?file=../../../etc/passwd"
    test_curl "PT Linux: ../../../../etc/passwd" "block" -A "$UA" -Lk "${URL}?file=../../../../etc/passwd"
    test_curl "PT Linux: ../../../../../etc/passwd" "block" -A "$UA" -Lk "${URL}?file=../../../../../etc/passwd"
    test_curl "PT Linux: ../../../../../../etc/passwd" "block" -A "$UA" -Lk "${URL}?file=../../../../../../etc/passwd"
    test_curl "PT Linux: ../../../../../../../etc/passwd" "block" -A "$UA" -Lk "${URL}?file=../../../../../../../etc/passwd"
    
    # Absolute path
    test_curl "PT Linux: /etc/passwd absolute" "block" -A "$UA" -Lk "${URL}?file=/etc/passwd"
    test_curl "PT Linux: /etc/shadow" "block" -A "$UA" -Lk "${URL}?file=/etc/shadow"
    test_curl "PT Linux: /etc/hosts" "block" -A "$UA" -Lk "${URL}?file=/etc/hosts"
    test_curl "PT Linux: /etc/group" "block" -A "$UA" -Lk "${URL}?file=/etc/group"
    test_curl "PT Linux: /etc/issue" "block" -A "$UA" -Lk "${URL}?file=/etc/issue"
    
    # /proc filesystem
    test_curl "PT Linux: /proc/version" "block" -A "$UA" -Lk "${URL}?file=/proc/version"
    test_curl "PT Linux: /proc/self/environ" "block" -A "$UA" -Lk "${URL}?file=/proc/self/environ"
    test_curl "PT Linux: /proc/self/cmdline" "block" -A "$UA" -Lk "${URL}?file=/proc/self/cmdline"
    test_curl "PT Linux: /proc/mounts" "block" -A "$UA" -Lk "${URL}?file=/proc/mounts"
    
    # Network info
    test_curl "PT Linux: /proc/net/arp" "block" -A "$UA" -Lk "${URL}?file=/proc/net/arp"
    test_curl "PT Linux: /proc/net/route" "block" -A "$UA" -Lk "${URL}?file=/proc/net/route"
    test_curl "PT Linux: /proc/net/tcp" "block" -A "$UA" -Lk "${URL}?file=/proc/net/tcp"
    
    # SSH keys
    test_curl "PT Linux: SSH id_rsa" "block" -A "$UA" -Lk "${URL}?file=/root/.ssh/id_rsa"
    test_curl "PT Linux: SSH authorized_keys" "block" -A "$UA" -Lk "${URL}?file=/root/.ssh/authorized_keys"
    
    # Bash history
    test_curl "PT Linux: bash_history" "block" -A "$UA" -Lk "${URL}?file=/root/.bash_history"
    
    # Current working directory
    test_curl "PT Linux: cwd index.php" "block" -A "$UA" -Lk "${URL}?file=/proc/self/cwd/index.php"
    test_curl "PT Linux: cwd config.php" "block" -A "$UA" -Lk "${URL}?file=/proc/self/cwd/config.php"
    
    # MySQL config
    test_curl "PT Linux: MySQL my.cnf" "block" -A "$UA" -Lk "${URL}?file=/etc/mysql/my.cnf"
    
    # Kubernetes secrets
    test_curl "PT Linux: K8s token" "block" -A "$UA" -Lk "${URL}?file=/run/secrets/kubernetes.io/serviceaccount/token"
    test_curl "PT Linux: K8s namespace" "block" -A "$UA" -Lk "${URL}?file=/run/secrets/kubernetes.io/serviceaccount/namespace"
}

#==============================================================================
# TESTES PATH TRAVERSAL BÁSICO - Windows
#==============================================================================
test_pt_basic_windows() {
    pt_print_subsection "Path Traversal Básico - Windows (20 variações)"
    
    # Basic ..\ traversal
    test_curl "PT Windows: ..\\..\\..\\windows\\win.ini" "block" -A "$UA" -Lk "${URL}?file=..\\..\\..\\windows\\win.ini"
    test_curl "PT Windows: ..\\..\\..\\..\\windows\\win.ini" "block" -A "$UA" -Lk "${URL}?file=..\\..\\..\\..\\windows\\win.ini"
    test_curl "PT Windows: ..\\..\\..\\..\\..\\windows\\win.ini" "block" -A "$UA" -Lk "${URL}?file=..\\..\\..\\..\\..\\windows\\win.ini"
    
    # Absolute paths
    test_curl "PT Windows: C:\\windows\\win.ini" "block" -A "$UA" -Lk "${URL}?file=C:\\windows\\win.ini"
    test_curl "PT Windows: C:\\windows\\system32\\license.rtf" "block" -A "$UA" -Lk "${URL}?file=C:\\windows\\system32\\license.rtf"
    
    # IIS paths
    test_curl "PT Windows: web.config" "block" -A "$UA" -Lk "${URL}?file=C:\\inetpub\\wwwroot\\web.config"
    test_curl "PT Windows: global.asa" "block" -A "$UA" -Lk "${URL}?file=C:\\inetpub\\wwwroot\\global.asa"
    test_curl "PT Windows: metabase.xml" "block" -A "$UA" -Lk "${URL}?file=C:\\windows\\system32\\inetsrv\\metabase.xml"
    
    # System files
    test_curl "PT Windows: boot.ini" "block" -A "$UA" -Lk "${URL}?file=C:\\boot.ini"
    test_curl "PT Windows: unattend.xml" "block" -A "$UA" -Lk "${URL}?file=C:\\unattend.xml"
    test_curl "PT Windows: sysprep.inf" "block" -A "$UA" -Lk "${URL}?file=C:\\sysprep.inf"
    test_curl "PT Windows: sysprep.xml" "block" -A "$UA" -Lk "${URL}?file=C:\\sysprep.xml"
    
    # SAM/SYSTEM
    test_curl "PT Windows: SAM" "block" -A "$UA" -Lk "${URL}?file=C:\\windows\\repair\\sam"
    test_curl "PT Windows: SYSTEM" "block" -A "$UA" -Lk "${URL}?file=C:\\windows\\repair\\system"
    
    # IIS logs
    test_curl "PT Windows: IIS logs" "block" -A "$UA" -Lk "${URL}?file=C:\\inetpub\\logs\\logfiles"
    
    # Mixed slashes
    test_curl "PT Windows: Mixed /" "block" -A "$UA" -Lk "${URL}?file=C:/windows/win.ini"
    test_curl "PT Windows: Mixed \\" "block" -A "$UA" -Lk "${URL}?file=C:\\windows/win.ini"
    
    # UNC paths
    test_curl "PT Windows: UNC localhost" "block" -A "$UA" -Lk "${URL}?file=\\\\localhost\\c\$\\windows\\win.ini"
    test_curl "PT Windows: UNC share" "block" -A "$UA" -Lk "${URL}?file=\\\\\\127.0.0.1\\c\$\\windows\\win.ini"
    
    # Long paths
    test_curl "PT Windows: Long path" "block" -A "$UA" -Lk "${URL}?file=C:\\windows\\..\\windows\\..\\windows\\win.ini"
}

#==============================================================================
# TESTES PATH TRAVERSAL ENCODING - URL, Double, Unicode
#==============================================================================
test_pt_encoding() {
    pt_print_subsection "Path Traversal Encoding (30 variações)"
    
    # URL encoding
    test_curl "PT Encoding: %2e%2e%2f (../)" "block" -A "$UA" -Lk "${URL}?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"
    test_curl "PT Encoding: %2e%2e/ mixed" "block" -A "$UA" -Lk "${URL}?file=%2e%2e/%2e%2e/%2e%2e/etc/passwd"
    test_curl "PT Encoding: ..%2f mixed" "block" -A "$UA" -Lk "${URL}?file=..%2f..%2f..%2fetc/passwd"
    
    # Windows URL encoding
    test_curl "PT Encoding: %2e%2e%5c (..\)" "block" -A "$UA" -Lk "${URL}?file=%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows\\win.ini"
    
    # Double URL encoding
    test_curl "PT Encoding: %252e%252e%252f" "block" -A "$UA" -Lk "${URL}?file=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd"
    test_curl "PT Encoding: %252e%252e%255c" "block" -A "$UA" -Lk "${URL}?file=%252e%252e%255c%252e%252e%255c%252e%252e%255cwindows\\win.ini"
    
    # Spring MVC bypass (CVE-2018-1271)
    test_curl "PT Encoding: Spring %255c" "block" -A "$UA" -Lk "${URL}/static/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/etc/passwd"
    
    # Unicode encoding
    test_curl "PT Encoding: Unicode %u002e" "block" -A "$UA" -Lk "${URL}?file=%u002e%u002e%u2215%u002e%u002e%u2215etc/passwd"
    test_curl "PT Encoding: Unicode %u2216" "block" -A "$UA" -Lk "${URL}?file=%u002e%u002e%u2216%u002e%u002e%u2216windows\\win.ini"
    
    # Openfire bypass (CVE-2023-32315)
    test_curl "PT Encoding: Openfire" "block" -A "$UA" -Lk "${URL}/setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp"
    
    # Overlong UTF-8
    test_curl "PT Encoding: UTF-8 %c0%2e" "block" -A "$UA" -Lk "${URL}?file=%c0%2e%c0%2e%c0%2fetc/passwd"
    test_curl "PT Encoding: UTF-8 %e0%40%ae" "block" -A "$UA" -Lk "${URL}?file=%e0%40%ae%e0%40%ae%c0%afetc/passwd"
    test_curl "PT Encoding: UTF-8 %c0%ae" "block" -A "$UA" -Lk "${URL}?file=%c0%ae%c0%ae%c0%afetc/passwd"
    
    # Mixed encoding
    test_curl "PT Encoding: Mix 1" "block" -A "$UA" -Lk "${URL}?file=%2e%2e/%2e%2e%2fetc/passwd"
    test_curl "PT Encoding: Mix 2" "block" -A "$UA" -Lk "${URL}?file=..%2f%2e%2e/etc/passwd"
    test_curl "PT Encoding: Mix 3" "block" -A "$UA" -Lk "${URL}?file=%2e%2e%2f..%2fetc/passwd"
    
    # Encode only dots
    test_curl "PT Encoding: Dots %2e%2e/" "block" -A "$UA" -Lk "${URL}?file=%2e%2e/%2e%2e/%2e%2e/etc/passwd"
    
    # Encode only slashes
    test_curl "PT Encoding: Slash ..%2f" "block" -A "$UA" -Lk "${URL}?file=..%2f..%2f..%2fetc/passwd"
    test_curl "PT Encoding: Backslash ..%5c" "block" -A "$UA" -Lk "${URL}?file=..%5c..%5c..%5cwindows\\win.ini"
    
    # Triple encoding
    test_curl "PT Encoding: Triple %25252e" "block" -A "$UA" -Lk "${URL}?file=%25252e%25252e%25252fetc/passwd"
    
    # Hex encoding
    test_curl "PT Encoding: Hex \\x2e\\x2e\\x2f" "block" -A "$UA" -Lk "${URL}?file=\\x2e\\x2e\\x2f\\x2e\\x2e\\x2fetc/passwd"
    
    # UTF-16
    test_curl "PT Encoding: UTF-16" "block" -A "$UA" -Lk "${URL}?file=%uff0e%uff0e%u2215etc/passwd"
    test_curl "PT Encoding: UTF-16 backslash" "block" -A "$UA" -Lk "${URL}?file=%uff0e%uff0e%u2216windows\\win.ini"
    
    # HTML entities
    test_curl "PT Encoding: HTML &lt;" "block" -A "$UA" -Lk "${URL}?file=..&lt;/..&lt;/etc/passwd"
    
    # Base64 (less common)
    test_curl "PT Encoding: Base64 hint" "block" -A "$UA" -Lk "${URL}?file=Li4vLi4vLi4vZXRjL3Bhc3N3ZA=="
    
    # Null byte variants
    test_curl "PT Encoding: %00" "block" -A "$UA" -Lk "${URL}?file=../../../etc/passwd%00"
    test_curl "PT Encoding: %00.jpg" "block" -A "$UA" -Lk "${URL}?file=../../../etc/passwd%00.jpg"
    test_curl "PT Encoding: .%00." "block" -A "$UA" -Lk "${URL}?file=.%00./.%00./etc/passwd"
}

#==============================================================================
# TESTES PATH TRAVERSAL FILTER BYPASS
#==============================================================================
test_pt_filter_bypass() {
    pt_print_subsection "Path Traversal Filter Bypass (25 variações)"
    
    # Mangled path - duplicate ../
    test_curl "PT Bypass: ..././" "block" -A "$UA" -Lk "${URL}?file=..././..././..././etc/passwd"
    test_curl "PT Bypass: .../.../.../" "block" -A "$UA" -Lk "${URL}?file=.../.../.../etc/passwd"
    test_curl "PT Bypass: ....//....//..../" "block" -A "$UA" -Lk "${URL}?file=....//....//..../etc/passwd"
    test_curl "PT Bypass: ...\\.\\.\\.\\.\\" "block" -A "$UA" -Lk "${URL}?file=...\\.\\...\\.\\.\\windows\\win.ini"
    
    # Mirasys DVMS bypass
    test_curl "PT Bypass: .../.../.../" "block" -A "$UA" -Lk "${URL}/.../.../.../.../.../.../.../windows/win.ini"
    
    # Reverse path
    test_curl "PT Bypass: /etc/../etc/passwd" "block" -A "$UA" -Lk "${URL}?file=/etc/../etc/passwd"
    test_curl "PT Bypass: /var/../etc/passwd" "block" -A "$UA" -Lk "${URL}?file=/var/../etc/passwd"
    
    # Null byte variations
    test_curl "PT Bypass: Null Homematic" "block" -A "$UA" -Lk "${URL}/.%00./.%00./etc/passwd"
    test_curl "PT Bypass: Null Kyocera" "block" -A "$UA" -Lk "${URL}/wlmeng/../../../../../../../etc/passwd%00index.htm"
    
    # Nginx ..;/ bypass (Reverse Proxy)
    test_curl "PT Bypass: ..;/" "block" -A "$UA" -Lk "${URL}?file=..;/..;/..;/etc/passwd"
    test_curl "PT Bypass: ..;/ Pascom" "block" -A "$UA" -Lk "${URL}/services/pluginscript/..;/..;/..;/etc/passwd"
    
    # ASP.NET Cookieless bypass
    test_curl "PT Bypass: ASPNET /(S(X))/" "block" -A "$UA" -Lk "${URL}/(S(X))/protected/admin.aspx"
    test_curl "PT Bypass: ASPNET /(Y(Z))/" "block" -A "$UA" -Lk "${URL}/(Y(Z))/admin/main.aspx"
    test_curl "PT Bypass: ASPNET split" "block" -A "$UA" -Lk "${URL}/admin/(S(X))/main.aspx"
    test_curl "PT Bypass: ASPNET CVE-2023-36899" "block" -A "$UA" -Lk "${URL}/WebForm/(S(X))/prot/(S(X))ected/target.aspx"
    test_curl "PT Bypass: ASPNET bin" "block" -A "$UA" -Lk "${URL}/(S(x))/b/(S(x))in/Navigator.dll"
    
    # IIS 8.3 Short Name
    test_curl "PT Bypass: IIS ~1" "block" -A "$UA" -Lk "${URL}/PROGRA~1/"
    test_curl "PT Bypass: IIS short ::INDEX" "block" -A "$UA" -Lk "${URL}/bin::\$INDEX_ALLOCATION/"
    
    # Java URL protocol
    test_curl "PT Bypass: Java url:file" "block" -A "$UA" -Lk "${URL}?file=url:file:///etc/passwd"
    test_curl "PT Bypass: Java url:http" "block" -A "$UA" -Lk "${URL}?file=url:http://evil.com/file"
    
    # Different parameters
    test_curl "PT Bypass: param path" "block" -A "$UA" -Lk "${URL}?path=../../../etc/passwd"
    test_curl "PT Bypass: param document" "block" -A "$UA" -Lk "${URL}?document=../../../etc/passwd"
    test_curl "PT Bypass: param page" "block" -A "$UA" -Lk "${URL}?page=../../../etc/passwd"
    test_curl "PT Bypass: param filename" "block" -A "$UA" -Lk "${URL}?filename=../../../etc/passwd"
    test_curl "PT Bypass: param load" "block" -A "$UA" -Lk "${URL}?load=../../../etc/passwd"
}

#==============================================================================
# TESTES PATH TRAVERSAL WEB APPS - WordPress, etc
#==============================================================================
test_pt_web_apps() {
    pt_print_subsection "Path Traversal Web Applications (20 variações)"
    
    # WordPress
    test_curl "PT WebApp: wp-config.php" "block" -A "$UA" -Lk "${URL}?file=../../../wp-config.php"
    test_curl "PT WebApp: wp-load.php" "block" -A "$UA" -Lk "${URL}?file=../wp-load.php"
    test_curl "PT WebApp: .htaccess" "block" -A "$UA" -Lk "${URL}?file=../.htaccess"
    
    # Common config files
    test_curl "PT WebApp: config.php" "block" -A "$UA" -Lk "${URL}?file=../config.php"
    test_curl "PT WebApp: configuration.php" "block" -A "$UA" -Lk "${URL}?file=../configuration.php"
    test_curl "PT WebApp: settings.php" "block" -A "$UA" -Lk "${URL}?file=../settings.php"
    test_curl "PT WebApp: database.php" "block" -A "$UA" -Lk "${URL}?file=../database.php"
    
    # Environment files
    test_curl "PT WebApp: .env" "block" -A "$UA" -Lk "${URL}?file=../.env"
    test_curl "PT WebApp: .env.local" "block" -A "$UA" -Lk "${URL}?file=../.env.local"
    test_curl "PT WebApp: .env.production" "block" -A "$UA" -Lk "${URL}?file=../.env.production"
    
    # Git
    test_curl "PT WebApp: .git/config" "block" -A "$UA" -Lk "${URL}?file=../.git/config"
    test_curl "PT WebApp: .git/HEAD" "block" -A "$UA" -Lk "${URL}?file=../.git/HEAD"
    
    # Logs
    test_curl "PT WebApp: error_log" "block" -A "$UA" -Lk "${URL}?file=../error_log"
    test_curl "PT WebApp: access.log" "block" -A "$UA" -Lk "${URL}?file=../../logs/access.log"
    test_curl "PT WebApp: error.log" "block" -A "$UA" -Lk "${URL}?file=../../logs/error.log"
    
    # PHP info
    test_curl "PT WebApp: phpinfo.php" "block" -A "$UA" -Lk "${URL}?file=../phpinfo.php"
    
    # Composer/NPM
    test_curl "PT WebApp: composer.json" "block" -A "$UA" -Lk "${URL}?file=../composer.json"
    test_curl "PT WebApp: package.json" "block" -A "$UA" -Lk "${URL}?file=../package.json"
    
    # Docker
    test_curl "PT WebApp: Dockerfile" "block" -A "$UA" -Lk "${URL}?file=../Dockerfile"
    test_curl "PT WebApp: docker-compose.yml" "block" -A "$UA" -Lk "${URL}?file=../docker-compose.yml"
}

#==============================================================================
# FUNÇÃO PRINCIPAL - Executa todos os testes Path Traversal
#==============================================================================
run_all_path_traversal_tests() {
    pt_print_section "📂 TESTES COMPLETOS DE PATH TRAVERSAL (PayloadsAllTheThings)" "-c pathtraversal"
    
    echo -e "${CYAN}ℹ️  Usando payloads do PayloadsAllTheThings/Directory Traversal${NC}"
    echo -e "${CYAN}ℹ️  Total estimado: 140+ testes de Path Traversal${NC}"
    echo ""
    
    test_pt_basic_linux
    test_pt_basic_windows
    test_pt_encoding
    test_pt_filter_bypass
    test_pt_web_apps
    
    echo ""
    echo -e "${GREEN}✓ Todos os testes Path Traversal foram concluídos!${NC}"
}

# Se o script for executado diretamente (não como source)
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    echo -e "${RED}❌ Este script deve ser chamado pelo head-test.sh${NC}"
    echo -e "${YELLOW}Use: ./head-test.sh -u URL -c pathtraversal${NC}"
    exit 1
fi
