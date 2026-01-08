#!/bin/bash
#==============================================================================
# SQLi Tester - Script especializado em testes de SQL Injection
# Versão: 1.0.0
# Descrição: Script modular para testes de SQL Injection usando payloads do PayloadsAllTheThings
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
SQLI_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SQLI_PAYLOADS_DIR="${SQLI_SCRIPT_DIR}/PayloadsAllTheThings/SQL Injection"
SQLI_INTRUDER_DIR="${SQLI_PAYLOADS_DIR}/Intruder"

#==============================================================================
# FUNÇÕES AUXILIARES
#==============================================================================

sqli_print_section() {
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

sqli_print_subsection() {
    echo -e "\n  ${BOLD}${BLUE}▶ $1${NC}"
}

#==============================================================================
# TESTES SQLi CLÁSSICO - Payloads de entrada básicos
#==============================================================================
test_sqli_classic() {
    sqli_print_subsection "SQL Injection Clássico (30 variações)"
    
    # OR-based injection
    test_curl "SQLi Classic: OR 1=1" "block" -A "$UA" -Lk "${URL}?id=1%20OR%201=1"
    test_curl "SQLi Classic: ' OR '1'='1" "block" -A "$UA" -Lk "${URL}?id='%20OR%20'1'='1"
    test_curl "SQLi Classic: \" OR \"1\"=\"1" "block" -A "$UA" -Lk "${URL}?id=\"%20OR%20\"1\"=\"1"
    test_curl "SQLi Classic: OR 1=1--" "block" -A "$UA" -Lk "${URL}?id=1%20OR%201=1--"
    test_curl "SQLi Classic: OR 1=1#" "block" -A "$UA" -Lk "${URL}?id=1%20OR%201=1%23"
    test_curl "SQLi Classic: OR 1=1/*" "block" -A "$UA" -Lk "${URL}?id=1%20OR%201=1/*"
    test_curl "SQLi Classic: ' OR 'x'='x" "block" -A "$UA" -Lk "${URL}?id='%20OR%20'x'='x"
    test_curl "SQLi Classic: ' OR 1=1 LIMIT 1--" "block" -A "$UA" -Lk "${URL}?id='%20OR%201=1%20LIMIT%201--"
    test_curl "SQLi Classic: admin'--" "block" -A "$UA" -Lk "${URL}?username=admin'--"
    test_curl "SQLi Classic: admin' #" "block" -A "$UA" -Lk "${URL}?username=admin'%20%23"
    
    # AND-based injection
    test_curl "SQLi Classic: AND 1=1" "block" -A "$UA" -Lk "${URL}?id=1%20AND%201=1"
    test_curl "SQLi Classic: AND 1=2" "block" -A "$UA" -Lk "${URL}?id=1%20AND%201=2"
    test_curl "SQLi Classic: ' AND '1'='1" "block" -A "$UA" -Lk "${URL}?id='%20AND%20'1'='1"
    test_curl "SQLi Classic: ' AND 'a'='a" "block" -A "$UA" -Lk "${URL}?id='%20AND%20'a'='a"
    
    # Simple quote variations
    test_curl "SQLi Classic: Single quote" "block" -A "$UA" -Lk "${URL}?id='"
    test_curl "SQLi Classic: Double quote" "block" -A "$UA" -Lk "${URL}?id=\""
    test_curl "SQLi Classic: Backtick" "block" -A "$UA" -Lk "${URL}?id=\`"
    test_curl "SQLi Classic: Semicolon" "block" -A "$UA" -Lk "${URL}?id=;"
    test_curl "SQLi Classic: Asterisk" "block" -A "$UA" -Lk "${URL}?id=*"
    test_curl "SQLi Classic: Parenthesis" "block" -A "$UA" -Lk "${URL}?id=)"
    
    # Error-based detection
    test_curl "SQLi Classic: ' || '1" "block" -A "$UA" -Lk "${URL}?id='%20||%20'1"
    test_curl "SQLi Classic: ' + '1" "block" -A "$UA" -Lk "${URL}?id='%20+%20'1"
    test_curl "SQLi Classic: ' && '1" "block" -A "$UA" -Lk "${URL}?id='%20&&%20'1"
    
    # Tautology
    test_curl "SQLi Classic: 1'1" "block" -A "$UA" -Lk "${URL}?id=1'1"
    test_curl "SQLi Classic: 1' or '1' = '1" "block" -A "$UA" -Lk "${URL}?id=1'%20or%20'1'%20=%20'1"
    test_curl "SQLi Classic: 1' or 1=1--" "block" -A "$UA" -Lk "${URL}?id=1'%20or%201=1--"
    test_curl "SQLi Classic: x' OR 1=1 OR 'x'='y" "block" -A "$UA" -Lk "${URL}?id=x'%20OR%201=1%20OR%20'x'='y"
    
    # Integer variations
    test_curl "SQLi Classic: 1 or 1=1" "block" -A "$UA" -Lk "${URL}?id=1%20or%201=1"
    test_curl "SQLi Classic: 1) or (1=1" "block" -A "$UA" -Lk "${URL}?id=1)%20or%20(1=1"
    test_curl "SQLi Classic: 1)) or ((1=1" "block" -A "$UA" -Lk "${URL}?id=1))%20or%20((1=1"
}

#==============================================================================
# TESTES SQLi UNION-BASED - Extração de dados via UNION
#==============================================================================
test_sqli_union() {
    sqli_print_subsection "SQL Injection UNION-Based (25 variações)"
    
    # UNION SELECT básico
    test_curl "SQLi UNION: 1 col" "block" -A "$UA" -Lk "${URL}?id=1%20UNION%20SELECT%20NULL--"
    test_curl "SQLi UNION: 2 cols" "block" -A "$UA" -Lk "${URL}?id=1%20UNION%20SELECT%20NULL,NULL--"
    test_curl "SQLi UNION: 3 cols" "block" -A "$UA" -Lk "${URL}?id=1%20UNION%20SELECT%20NULL,NULL,NULL--"
    test_curl "SQLi UNION: 4 cols" "block" -A "$UA" -Lk "${URL}?id=1%20UNION%20SELECT%20NULL,NULL,NULL,NULL--"
    test_curl "SQLi UNION: 5 cols" "block" -A "$UA" -Lk "${URL}?id=1%20UNION%20SELECT%20NULL,NULL,NULL,NULL,NULL--"
    
    # UNION ALL SELECT
    test_curl "SQLi UNION ALL: 2 cols" "block" -A "$UA" -Lk "${URL}?id=1%20UNION%20ALL%20SELECT%20NULL,NULL--"
    test_curl "SQLi UNION ALL: 3 cols" "block" -A "$UA" -Lk "${URL}?id=1%20UNION%20ALL%20SELECT%20NULL,NULL,NULL--"
    
    # Data extraction
    test_curl "SQLi UNION: version()" "block" -A "$UA" -Lk "${URL}?id=-1%20UNION%20SELECT%20version()--"
    test_curl "SQLi UNION: database()" "block" -A "$UA" -Lk "${URL}?id=-1%20UNION%20SELECT%20database()--"
    test_curl "SQLi UNION: user()" "block" -A "$UA" -Lk "${URL}?id=-1%20UNION%20SELECT%20user()--"
    test_curl "SQLi UNION: @@version" "block" -A "$UA" -Lk "${URL}?id=-1%20UNION%20SELECT%20@@version--"
    test_curl "SQLi UNION: table_name" "block" -A "$UA" -Lk "${URL}?id=-1%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables--"
    test_curl "SQLi UNION: column_name" "block" -A "$UA" -Lk "${URL}?id=-1%20UNION%20SELECT%20column_name%20FROM%20information_schema.columns--"
    
    # UNION with strings
    test_curl "SQLi UNION: concat users" "block" -A "$UA" -Lk "${URL}?id=-1%20UNION%20SELECT%20CONCAT(username,0x3a,password)%20FROM%20users--"
    test_curl "SQLi UNION: group_concat" "block" -A "$UA" -Lk "${URL}?id=-1%20UNION%20SELECT%20GROUP_CONCAT(username)%20FROM%20users--"
    
    # ORDER BY detection
    test_curl "SQLi UNION: ORDER BY 1" "block" -A "$UA" -Lk "${URL}?id=1%20ORDER%20BY%201--"
    test_curl "SQLi UNION: ORDER BY 5" "block" -A "$UA" -Lk "${URL}?id=1%20ORDER%20BY%205--"
    test_curl "SQLi UNION: ORDER BY 10" "block" -A "$UA" -Lk "${URL}?id=1%20ORDER%20BY%2010--"
    test_curl "SQLi UNION: ORDER BY 20" "block" -A "$UA" -Lk "${URL}?id=1%20ORDER%20BY%2020--"
    
    # UNION variations
    test_curl "SQLi UNION: negative ID" "block" -A "$UA" -Lk "${URL}?id=-1%20UNION%20SELECT%201,2,3--"
    test_curl "SQLi UNION: 0 ID" "block" -A "$UA" -Lk "${URL}?id=0%20UNION%20SELECT%201,2,3--"
    test_curl "SQLi UNION: quotes" "block" -A "$UA" -Lk "${URL}?id='%20UNION%20SELECT%201,2,3--"
    
    # Information Schema
    test_curl "SQLi UNION: info_schema tables" "block" -A "$UA" -Lk "${URL}?id=-1%20UNION%20SELECT%201,table_name%20FROM%20information_schema.tables--"
    test_curl "SQLi UNION: current_database" "block" -A "$UA" -Lk "${URL}?id=-1%20UNION%20SELECT%20current_database(),NULL--"
    test_curl "SQLi UNION: schema tables" "block" -A "$UA" -Lk "${URL}?id=-1%20UNION%20SELECT%20*%20FROM%20INFORMATION_SCHEMA.TABLES--"
}

#==============================================================================
# TESTES SQLi ERROR-BASED - Extração via mensagens de erro
#==============================================================================
test_sqli_error_based() {
    sqli_print_subsection "SQL Injection Error-Based (20 variações)"
    
    # MySQL Error-Based
    test_curl "SQLi Error: extractvalue()" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20extractvalue(1,concat(0x7e,version()))"
    test_curl "SQLi Error: updatexml()" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20updatexml(1,concat(0x7e,version()),1)"
    test_curl "SQLi Error: floor()" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20(SELECT%201%20FROM%20(SELECT%20COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x%20FROM%20users%20GROUP%20BY%20x)a)"
    test_curl "SQLi Error: exp()" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20exp(~(SELECT%20*%20FROM%20(SELECT%20version())a))"
    test_curl "SQLi Error: geometrycollection()" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20geometrycollection((SELECT%20*%20FROM(SELECT%20*%20FROM(SELECT%20version())a)b))"
    test_curl "SQLi Error: polygon()" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20polygon((SELECT%20*%20FROM(SELECT%20*%20FROM(SELECT%20version())a)b))"
    test_curl "SQLi Error: multipoint()" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20multipoint((SELECT%20*%20FROM(SELECT%20*%20FROM(SELECT%20version())a)b))"
    test_curl "SQLi Error: multilinestring()" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20multilinestring((SELECT%20*%20FROM(SELECT%20*%20FROM(SELECT%20version())a)b))"
    test_curl "SQLi Error: linestring()" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20linestring((SELECT%20*%20FROM(SELECT%20*%20FROM(SELECT%20version())a)b))"
    test_curl "SQLi Error: multipolygon()" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20multipolygon((SELECT%20*%20FROM(SELECT%20*%20FROM(SELECT%20version())a)b))"
    
    # MSSQL Error-Based
    test_curl "SQLi Error MSSQL: convert()" "block" -A "$UA" -Lk "${URL}?id=1%20AND%201=CONVERT(INT,(SELECT%20@@version))"
    test_curl "SQLi Error MSSQL: cast()" "block" -A "$UA" -Lk "${URL}?id=1%20AND%201=CAST((SELECT%20@@version)%20AS%20INT)"
    
    # PostgreSQL Error-Based
    test_curl "SQLi Error PostgreSQL: cast numeric" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20CAST((SELECT%20version())%20AS%20NUMERIC)"
    test_curl "SQLi Error PostgreSQL: cast int" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20CAST((SELECT%20version())%20AS%20INT)"
    
    # Oracle Error-Based
    test_curl "SQLi Error Oracle: utl_inaddr" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20(SELECT%20UTL_INADDR.get_host_address((SELECT%20banner%20FROM%20v\$version%20WHERE%20ROWNUM=1))%20FROM%20DUAL)=1"
    test_curl "SQLi Error Oracle: ctxsys" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20(SELECT%20ctxsys.drithsx.sn(1,(SELECT%20banner%20FROM%20v\$version%20WHERE%20ROWNUM=1))%20FROM%20DUAL)=1"
    
    # Generic triggers
    test_curl "SQLi Error: division by zero" "block" -A "$UA" -Lk "${URL}?id=1%20AND%201/(SELECT%200)"
    test_curl "SQLi Error: invalid cast" "block" -A "$UA" -Lk "${URL}?id=1%20AND%201=CAST('abc'%20AS%20INT)"
    test_curl "SQLi Error: XML path" "block" -A "$UA" -Lk "${URL}?id=1%20AND%201=(SELECT%20TOP%201%20table_name%20FROM%20information_schema.tables%20FOR%20XML%20PATH(''))"
    test_curl "SQLi Error: double query" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20(SELECT%201%20FROM%20(SELECT%20COUNT(*),CONCAT((SELECT%20database()),0x23,FLOOR(RAND(0)*2))x%20FROM%20information_schema.tables%20GROUP%20BY%20x)y)"
}

#==============================================================================
# TESTES SQLi BLIND - Boolean e Time-Based
#==============================================================================
test_sqli_blind() {
    sqli_print_subsection "SQL Injection Blind (Boolean + Time-Based) - 25 variações"
    
    # Boolean-Based
    test_curl "SQLi Blind Boolean: AND 1=1" "block" -A "$UA" -Lk "${URL}?id=1%20AND%201=1"
    test_curl "SQLi Blind Boolean: AND 1=2" "block" -A "$UA" -Lk "${URL}?id=1%20AND%201=2"
    test_curl "SQLi Blind Boolean: substring true" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20SUBSTRING(version(),1,1)='5'"
    test_curl "SQLi Blind Boolean: substring false" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20SUBSTRING(version(),1,1)='4'"
    test_curl "SQLi Blind Boolean: length" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20LENGTH(database())=5"
    test_curl "SQLi Blind Boolean: ascii" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20ASCII(SUBSTRING(database(),1,1))>100"
    test_curl "SQLi Blind Boolean: exists" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20EXISTS(SELECT%20*%20FROM%20users)"
    test_curl "SQLi Blind Boolean: case when" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20CASE%20WHEN%201=1%20THEN%201%20ELSE%200%20END"
    
    # Time-Based MySQL
    test_curl "SQLi Blind Time: SLEEP(5)" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20SLEEP(5)"
    test_curl "SQLi Blind Time: IF SLEEP" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20IF(1=1,SLEEP(5),0)"
    test_curl "SQLi Blind Time: BENCHMARK" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20BENCHMARK(10000000,MD5('test'))"
    test_curl "SQLi Blind Time: conditional" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20IF(SUBSTRING(version(),1,1)='5',SLEEP(5),0)"
    
    # Time-Based MSSQL
    test_curl "SQLi Blind Time MSSQL: WAITFOR" "block" -A "$UA" -Lk "${URL}?id=1;WAITFOR%20DELAY%20'0:0:5'--"
    test_curl "SQLi Blind Time MSSQL: IF WAITFOR" "block" -A "$UA" -Lk "${URL}?id=1;IF(1=1)%20WAITFOR%20DELAY%20'0:0:5'--"
    
    # Time-Based PostgreSQL
    test_curl "SQLi Blind Time PostgreSQL: pg_sleep" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20pg_sleep(5)"
    test_curl "SQLi Blind Time PostgreSQL: case pg_sleep" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20CASE%20WHEN%201=1%20THEN%20pg_sleep(5)%20ELSE%20pg_sleep(0)%20END"
    
    # Time-Based Oracle
    test_curl "SQLi Blind Time Oracle: dbms_pipe" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20dbms_pipe.receive_message(('a'),5)=1"
    
    # Blind Error-Based (SQLite example)
    test_curl "SQLi Blind Error: json() true" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20CASE%20WHEN%201=1%20THEN%201%20ELSE%20json('')%20END"
    test_curl "SQLi Blind Error: json() false" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20CASE%20WHEN%201=2%20THEN%201%20ELSE%20json('')%20END"
    
    # Advanced Boolean
    test_curl "SQLi Blind Boolean: LIKE" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20user()%20LIKE%20'root%25'"
    test_curl "SQLi Blind Boolean: REGEXP" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20version()%20REGEXP%20'^5'"
    test_curl "SQLi Blind Boolean: IN" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20SUBSTRING(version(),1,1)%20IN%20('5','8')"
    test_curl "SQLi Blind Boolean: BETWEEN" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20ASCII(SUBSTRING(database(),1,1))%20BETWEEN%2097%20AND%20122"
    
    # Nested queries
    test_curl "SQLi Blind Boolean: nested" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20(SELECT%20COUNT(*)%20FROM%20users)>0"
    test_curl "SQLi Blind Boolean: table exists" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20(SELECT%20COUNT(*)%20FROM%20information_schema.tables%20WHERE%20table_name='users')>0"
}

#==============================================================================
# TESTES SQLi AUTHENTICATION BYPASS - Bypass de autenticação
#==============================================================================
test_sqli_auth_bypass() {
    sqli_print_subsection "SQL Injection Auth Bypass (30 variações da lista)"
    
    local auth_file="${SQLI_INTRUDER_DIR}/Auth_Bypass.txt"
    
    if [ ! -f "$auth_file" ]; then
        echo -e "${YELLOW}  ⚠ Arquivo de payloads não encontrado: $auth_file${NC}"
        return
    fi
    
    local count=0
    while IFS= read -r payload || [ -n "$payload" ]; do
        [ -z "$payload" ] && continue
        [ "${payload:0:1}" == "#" ] && continue
        
        count=$((count + 1))
        
        # URL encode o payload
        local encoded_payload=$(echo -n "$payload" | jq -sRr @uri 2>/dev/null || echo "$payload")
        
        # Testar em campo de username
        test_curl "SQLi Auth Bypass #$count: ${payload:0:40}..." "block" -A "$UA" -Lk "${URL}?username=${encoded_payload}"
        
        [ $count -ge 30 ] && break
    done < "$auth_file"
    
    echo -e "\n  ${CYAN}Total de payloads Auth Bypass testados: $count${NC}"
}

#==============================================================================
# TESTES SQLi STACKED QUERIES - Consultas empilhadas
#==============================================================================
test_sqli_stacked() {
    sqli_print_subsection "SQL Injection Stacked Queries (15 variações)"
    
    # MySQL Stacked
    test_curl "SQLi Stacked: SELECT;SELECT" "block" -A "$UA" -Lk "${URL}?id=1;SELECT%20version()"
    test_curl "SQLi Stacked: INSERT" "block" -A "$UA" -Lk "${URL}?id=1;INSERT%20INTO%20users%20VALUES('hacker','pass')"
    test_curl "SQLi Stacked: UPDATE" "block" -A "$UA" -Lk "${URL}?id=1;UPDATE%20users%20SET%20password='pwned'%20WHERE%20id=1"
    test_curl "SQLi Stacked: DELETE" "block" -A "$UA" -Lk "${URL}?id=1;DELETE%20FROM%20users%20WHERE%20id=1"
    test_curl "SQLi Stacked: DROP TABLE" "block" -A "$UA" -Lk "${URL}?id=1;DROP%20TABLE%20users"
    test_curl "SQLi Stacked: CREATE TABLE" "block" -A "$UA" -Lk "${URL}?id=1;CREATE%20TABLE%20backdoor(cmd%20TEXT)"
    
    # MSSQL Stacked
    test_curl "SQLi Stacked MSSQL: xp_cmdshell" "block" -A "$UA" -Lk "${URL}?id=1;EXEC%20xp_cmdshell('whoami')"
    test_curl "SQLi Stacked MSSQL: sp_executesql" "block" -A "$UA" -Lk "${URL}?id=1;EXEC%20sp_executesql%20N'SELECT%20@@VERSION'"
    test_curl "SQLi Stacked MSSQL: enable xp_cmdshell" "block" -A "$UA" -Lk "${URL}?id=1;EXEC%20sp_configure%20'xp_cmdshell',1;RECONFIGURE"
    
    # PostgreSQL Stacked
    test_curl "SQLi Stacked PostgreSQL: COPY" "block" -A "$UA" -Lk "${URL}?id=1;COPY%20users%20TO%20'/tmp/users.txt'"
    test_curl "SQLi Stacked PostgreSQL: CREATE" "block" -A "$UA" -Lk "${URL}?id=1;CREATE%20TABLE%20backdoor(cmd%20TEXT)"
    
    # Multiple statements
    test_curl "SQLi Stacked: Multiple;" "block" -A "$UA" -Lk "${URL}?id=1;SELECT%201;SELECT%202;SELECT%203"
    test_curl "SQLi Stacked: Mixed DML" "block" -A "$UA" -Lk "${URL}?id=1;SELECT%20*%20FROM%20users;UPDATE%20users%20SET%20admin=1"
    
    # Oracle Stacked (limited support)
    test_curl "SQLi Stacked Oracle: EXECUTE" "block" -A "$UA" -Lk "${URL}?id=1;EXECUTE%20IMMEDIATE%20'SELECT%20banner%20FROM%20v\$version'"
    test_curl "SQLi Stacked Oracle: DBMS_OUTPUT" "block" -A "$UA" -Lk "${URL}?id=1;DBMS_OUTPUT.PUT_LINE('pwned')"
}

#==============================================================================
# TESTES SQLi WAF BYPASS - Técnicas de evasão de WAF
#==============================================================================
test_sqli_waf_bypass() {
    sqli_print_subsection "SQL Injection WAF Bypass (40 variações)"
    
    # No Space - Alternative whitespace
    test_curl "SQLi WAF Bypass: Tab %09" "block" -A "$UA" -Lk "${URL}?id=1%09AND%091=1"
    test_curl "SQLi WAF Bypass: Newline %0A" "block" -A "$UA" -Lk "${URL}?id=1%0AAND%0A1=1"
    test_curl "SQLi WAF Bypass: Carriage return %0D" "block" -A "$UA" -Lk "${URL}?id=1%0DAND%0D1=1"
    test_curl "SQLi WAF Bypass: Vertical tab %0B" "block" -A "$UA" -Lk "${URL}?id=1%0BAND%0B1=1"
    test_curl "SQLi WAF Bypass: Form feed %0C" "block" -A "$UA" -Lk "${URL}?id=1%0CAND%0C1=1"
    test_curl "SQLi WAF Bypass: Non-breaking space %A0" "block" -A "$UA" -Lk "${URL}?id=1%A0AND%A01=1"
    
    # Comment-based bypass
    test_curl "SQLi WAF Bypass: /**/ comment" "block" -A "$UA" -Lk "${URL}?id=1/**/AND/**/1=1"
    test_curl "SQLi WAF Bypass: /*!50000*/ version" "block" -A "$UA" -Lk "${URL}?id=1/*!50000AND*//*!50000*/1=1"
    test_curl "SQLi WAF Bypass: Inline comment" "block" -A "$UA" -Lk "${URL}?id=1/*comment*/UNION/*comment*/SELECT/*comment*/1"
    test_curl "SQLi WAF Bypass: Multiple /**/" "block" -A "$UA" -Lk "${URL}?id=1/**/UN/**/ION/**/SE/**/LECT/**/1"
    
    # Parenthesis bypass
    test_curl "SQLi WAF Bypass: (1)and(1)=(1)" "block" -A "$UA" -Lk "${URL}?id=(1)and(1)=(1)"
    test_curl "SQLi WAF Bypass: (SELECT(1))" "block" -A "$UA" -Lk "${URL}?id=-1%20UNION(SELECT(1),2,3)"
    
    # Case variation
    test_curl "SQLi WAF Bypass: Mixed case UnIoN" "block" -A "$UA" -Lk "${URL}?id=1%20UnIoN%20SeLeCt%201"
    test_curl "SQLi WAF Bypass: Uppercase UNION" "block" -A "$UA" -Lk "${URL}?id=1%20UNION%20SELECT%201"
    test_curl "SQLi WAF Bypass: Random case" "block" -A "$UA" -Lk "${URL}?id=1%20uNiOn%20sElEcT%201"
    
    # Encoding bypass
    test_curl "SQLi WAF Bypass: URL encode once" "block" -A "$UA" -Lk "${URL}?id=1%20%55%4E%49%4F%4E%20%53%45%4C%45%43%54%201"
    test_curl "SQLi WAF Bypass: Double URL encode" "block" -A "$UA" -Lk "${URL}?id=1%2520UNION%2520SELECT%25201"
    test_curl "SQLi WAF Bypass: Unicode encode" "block" -A "$UA" -Lk "${URL}?id=1%u0055NION%u0053ELECT%u0031"
    
    # No comma bypass
    test_curl "SQLi WAF Bypass: LIMIT OFFSET" "block" -A "$UA" -Lk "${URL}?id=1%20UNION%20SELECT%201%20LIMIT%201%20OFFSET%200"
    test_curl "SQLi WAF Bypass: SUBSTR FROM FOR" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20SUBSTR(version()%20FROM%201%20FOR%201)='5'"
    test_curl "SQLi WAF Bypass: JOIN SELECT" "block" -A "$UA" -Lk "${URL}?id=-1%20UNION%20SELECT%20*%20FROM%20(SELECT%201)a%20JOIN%20(SELECT%202)b"
    
    # No equal bypass
    test_curl "SQLi WAF Bypass: LIKE instead =" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20version()%20LIKE%20'5%25'"
    test_curl "SQLi WAF Bypass: REGEXP instead =" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20version()%20REGEXP%20'^5'"
    test_curl "SQLi WAF Bypass: IN instead =" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20SUBSTRING(version(),1,1)%20IN%20(5)"
    test_curl "SQLi WAF Bypass: BETWEEN instead =" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20ASCII(SUBSTRING(version(),1,1))%20BETWEEN%2053%20AND%2053"
    
    # Logical operators bypass
    test_curl "SQLi WAF Bypass: && instead AND" "block" -A "$UA" -Lk "${URL}?id=1%20&&%201=1"
    test_curl "SQLi WAF Bypass: || instead OR" "block" -A "$UA" -Lk "${URL}?id=1%20||%201=1"
    
    # Scientific notation
    test_curl "SQLi WAF Bypass: 1e0UNION" "block" -A "$UA" -Lk "${URL}?id=1e0UNION%20SELECT%201"
    test_curl "SQLi WAF Bypass: Scientific 2e1" "block" -A "$UA" -Lk "${URL}?id=2e1%20AND%201=1"
    
    # Null byte injection
    test_curl "SQLi WAF Bypass: %00 null byte" "block" -A "$UA" -Lk "${URL}?id=1%00%20UNION%20SELECT%201"
    test_curl "SQLi WAF Bypass: Null in middle" "block" -A "$UA" -Lk "${URL}?id=1%20UN%00ION%20SELECT%201"
    
    # HPP (HTTP Parameter Pollution)
    test_curl "SQLi WAF Bypass: HPP id twice" "block" -A "$UA" -Lk "${URL}?id=1&id=%20UNION%20SELECT%201"
    
    # Keyword splitting
    test_curl "SQLi WAF Bypass: UN/**/ION" "block" -A "$UA" -Lk "${URL}?id=1%20UN/**/ION%20SE/**/LECT%201"
    test_curl "SQLi WAF Bypass: Keyword split +" "block" -A "$UA" -Lk "${URL}?id=1%20UNI+ON%20SEL+ECT%201"
    
    # Special bypass techniques
    test_curl "SQLi WAF Bypass: Reverse function" "block" -A "$UA" -Lk "${URL}?id=1%20UNION%20SELECT%20REVERSE('tceles')"
    test_curl "SQLi WAF Bypass: CONCAT evasion" "block" -A "$UA" -Lk "${URL}?id=1%20UNION%20SELECT%20CONCAT(CHAR(85),CHAR(83),CHAR(69),CHAR(82))"
    test_curl "SQLi WAF Bypass: HEX encoding" "block" -A "$UA" -Lk "${URL}?id=1%20UNION%20SELECT%200x61646d696e"
    test_curl "SQLi WAF Bypass: CHAR() function" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20CHAR(49)=1"
    test_curl "SQLi WAF Bypass: ASCII() abuse" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20ASCII(CHAR(49))=49"
}

#==============================================================================
# TESTES SQLi POLYGLOT - Payloads universais
#==============================================================================
test_sqli_polyglot() {
    sqli_print_subsection "SQL Injection Polyglot (10 variações da lista)"
    
    local polyglot_file="${SQLI_INTRUDER_DIR}/SQLi_Polyglots.txt"
    
    if [ ! -f "$polyglot_file" ]; then
        echo -e "${YELLOW}  ⚠ Arquivo de polyglots não encontrado: $polyglot_file${NC}"
        return
    fi
    
    local count=0
    while IFS= read -r payload || [ -n "$payload" ]; do
        [ -z "$payload" ] && continue
        [ "${payload:0:1}" == "#" ] && continue
        
        count=$((count + 1))
        
        # URL encode o payload
        local encoded_payload=$(echo -n "$payload" | jq -sRr @uri 2>/dev/null || echo "$payload")
        test_curl "SQLi Polyglot #$count: ${payload:0:40}..." "block" -A "$UA" -Lk "${URL}?id=${encoded_payload}"
        
        [ $count -ge 10 ] && break
    done < "$polyglot_file"
    
    echo -e "\n  ${CYAN}Total de polyglots testados: $count${NC}"
}

#==============================================================================
# TESTES SQLi ADVANCED - Payloads de listas específicas
#==============================================================================
test_sqli_from_intruders() {
    sqli_print_subsection "SQL Injection Payloads Avançados (50 da lista Generic_ErrorBased)"
    
    local error_file="${SQLI_INTRUDER_DIR}/Generic_ErrorBased.txt"
    
    if [ ! -f "$error_file" ]; then
        echo -e "${YELLOW}  ⚠ Arquivo de payloads não encontrado: $error_file${NC}"
        return
    fi
    
    local count=0
    while IFS= read -r payload || [ -n "$payload" ]; do
        [ -z "$payload" ] && continue
        [ "${payload:0:1}" == "#" ] && continue
        
        count=$((count + 1))
        
        # URL encode o payload
        local encoded_payload=$(echo -n "$payload" | jq -sRr @uri 2>/dev/null || echo "$payload")
        test_curl "SQLi Advanced #$count: ${payload:0:40}..." "block" -A "$UA" -Lk "${URL}?id=${encoded_payload}"
        
        [ $count -ge 50 ] && break
    done < "$error_file"
    
    echo -e "\n  ${CYAN}Total de payloads avançados testados: $count${NC}"
}

#==============================================================================
# TESTES SQLi DATABASE SPECIFIC - Testes específicos por banco de dados
#==============================================================================
test_sqli_database_specific() {
    sqli_print_subsection "SQL Injection Database-Specific (20 variações)"
    
    # MySQL specific
    test_curl "SQLi MySQL: @@version" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20@@version%20LIKE%20'5%25'"
    test_curl "SQLi MySQL: information_schema" "block" -A "$UA" -Lk "${URL}?id=1%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables"
    test_curl "SQLi MySQL: LOAD_FILE()" "block" -A "$UA" -Lk "${URL}?id=1%20UNION%20SELECT%20LOAD_FILE('/etc/passwd')"
    test_curl "SQLi MySQL: INTO OUTFILE" "block" -A "$UA" -Lk "${URL}?id=1%20UNION%20SELECT%20'<?php%20system(\$_GET[cmd]);?>'%20INTO%20OUTFILE%20'/tmp/shell.php'"
    test_curl "SQLi MySQL: connection_id()" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20connection_id()=connection_id()"
    
    # MSSQL specific
    test_curl "SQLi MSSQL: @@VERSION" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20@@VERSION%20LIKE%20'%25Microsoft%25'"
    test_curl "SQLi MSSQL: xp_cmdshell" "block" -A "$UA" -Lk "${URL}?id=1;EXEC%20xp_cmdshell('dir')"
    test_curl "SQLi MSSQL: BINARY_CHECKSUM" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)"
    test_curl "SQLi MSSQL: @@CONNECTIONS" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20@@CONNECTIONS>0"
    
    # PostgreSQL specific
    test_curl "SQLi PostgreSQL: version()" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20version()%20LIKE%20'PostgreSQL%25'"
    test_curl "SQLi PostgreSQL: current_database()" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20current_database()=current_database()"
    test_curl "SQLi PostgreSQL: pg_sleep()" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20pg_sleep(5)=0"
    test_curl "SQLi PostgreSQL: pg_client_encoding()" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20pg_client_encoding()=pg_client_encoding()"
    
    # Oracle specific
    test_curl "SQLi Oracle: ROWNUM" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20ROWNUM=ROWNUM"
    test_curl "SQLi Oracle: banner v\$version" "block" -A "$UA" -Lk "${URL}?id=1%20UNION%20SELECT%20banner%20FROM%20v\$version"
    test_curl "SQLi Oracle: UTL_INADDR" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20UTL_INADDR.get_host_address('localhost')='127.0.0.1'"
    
    # SQLite specific
    test_curl "SQLi SQLite: sqlite_version()" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20sqlite_version()=sqlite_version()"
    test_curl "SQLi SQLite: last_insert_rowid()" "block" -A "$UA" -Lk "${URL}?id=1%20AND%20last_insert_rowid()>0"
    
    # MongoDB (NoSQL but related)
    test_curl "SQLi MongoDB: {\$ne:1}" "block" -A "$UA" -Lk "${URL}?id={\\\$ne:1}"
    test_curl "SQLi MongoDB: {\$gt:''}" "block" -A "$UA" -Lk "${URL}?password={\\\$gt:''}"
}

#==============================================================================
# FUNÇÃO PRINCIPAL - Executa todos os testes SQLi
#==============================================================================
run_all_sqli_tests() {
    sqli_print_section "💉 TESTES COMPLETOS DE SQL INJECTION (PayloadsAllTheThings)" "-c sqli"
    
    echo -e "${CYAN}ℹ️  Usando payloads do PayloadsAllTheThings/SQL Injection${NC}"
    echo -e "${CYAN}ℹ️  Total estimado: 300+ testes de SQL Injection${NC}"
    echo ""
    
    test_sqli_classic
    test_sqli_union
    test_sqli_error_based
    test_sqli_blind
    test_sqli_auth_bypass
    test_sqli_stacked
    test_sqli_waf_bypass
    test_sqli_polyglot
    test_sqli_database_specific
    test_sqli_from_intruders
    
    echo ""
    echo -e "${GREEN}✓ Todos os testes SQL Injection foram concluídos!${NC}"
}

# Se o script for executado diretamente (não como source)
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    echo -e "${RED}❌ Este script deve ser chamado pelo head-test.sh${NC}"
    echo -e "${YELLOW}Use: ./head-test.sh -u URL -c sqli${NC}"
    exit 1
fi
