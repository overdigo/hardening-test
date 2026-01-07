# SQLi Tester - Módulo de Testes SQL Injection

## Descrição

O `sqli-tester.sh` é um módulo separado do `head-test.sh` dedicado exclusivamente a testes de **SQL Injection**. Este módulo utiliza os payloads do repositório **PayloadsAllTheThings/SQL Injection** para fornecer testes abrangentes e especializados.

## Motivação

A separação dos testes SQL Injection em um módulo dedicado oferece as mesmas vantagens do XSS Tester:

1. **Manutenção Facilit ada**: TOdas as alterações relacionadas a SQLi  ficam em um único arquivo
2. **Organização**: Código mais limpo e modular  
3. **Reutilização**: Fácil adaptação para outros projetos
4. **Escalabilidade**: Adicionar novos payloads é mais simples
5. **Payloads Profissionais**: Baseado no PayloadsAllTheThings

## Estrutura

O módulo está organizado nas seguintes categorias de testes:

### 1. SQLi Clássico (30 testes)
- OR-based injection: `OR 1=1`, `' OR '1'='1`
- AND-based injection: `AND 1=1`, `AND 1=2`
- Simple quote variations: `'`, `"`, `;`, `*`
- Tautology: `1'1`, `x' OR 1=1 OR 'x'='y`
- Integer variations

### 2. SQLi UNION-Based (25 testes)
- Column number discovery: 1-5 columns
- UNION ALL SELECT variations
- Data extraction: `version()`, `database()`, `user()`
- Information Schema queries
- ORDER BY detection
- GROUP_CONCAT e CONCAT payloads

### 3. SQLi Error-Based (20 testes)
- **MySQL**: `extractvalue()`, `updatexml()`, `floor()`, `exp()`
- **MySQL Geometry**: `geometrycollection()`, `polygon()`, `multipoint()`
- **MSSQL**: `convert()`, `cast()`
- **PostgreSQL**: `cast numeric`, `cast int`
- **Oracle**: `utl_inaddr`, `ctxsys`
- Generic triggers: division by zero, invalid cast

### 4. SQLi Blind (25 testes)
- **Boolean-Based**: substring, length, ascii, exists, LIKE, REGEXP
- **Time-Based MySQL**: `SLEEP()`, `IF SLEEP`, `BENCHMARK()`
- **Time-Based MSSQL**: `WAITFOR DELAY`
- **Time-Based PostgreSQL**: `pg_sleep()`
- **Time-Based Oracle**: `dbms_pipe.receive_message()`
- **Error-Based Blind** (SQLite): `json()` function

### 5. SQLi Authentication Bypass (30 testes)
- Payloads do arquivo `Auth_Bypass.txt`
- Técnicas clássicas de bypass de login
- Variações de escape de quotes
- LIMIT clause bypass
- Comment-based bypass

### 6. SQLi Stacked Queries (15 testes)
- **MySQL**: SELECT, INSERT, UPDATE, DELETE, DROP, CREATE
- **MSSQL**: `xp_cmdshell`, `sp_executesql`, enable features
- **PostgreSQL**: COPY, CREATE TABLE
- **Oracle**: EXECUTE IMMEDIATE, DBMS_OUTPUT
- Multiple statements chaining

### 7. SQLi WAF Bypass (40 testes)
- **No Space**: Tab, newline, carriage return, vertical tab, form feed
- **Comment-based**: `/**/`, `/*!50000*/`, inline comments
- **Parenthesis**: `(1)and(1)=(1)`
- **Case variation**: Mixed case, uppercase, random case
- **Encoding**: URL encode (single/double), Unicode
- **No comma**: LIMIT OFFSET, SUBSTR FROM FOR, JOIN SELECT
- **No equal**: LIKE, REGEXP, IN, BETWEEN
- **Logical operators**: `&&`, `||`
- **Scientific notation**: `1e0UNION`
- **Null bytes**: `%00`
- **HPP**: HTTP Parameter Pollution
- **Keyword splitting**: Comment-based, plus-based
- **Special techniques**: REVERSE(), CONCAT(), HEX, CHAR()

### 8. SQLi Polyglot (10 testes)
- Payloads do arquivo `SQLi_Polyglots.txt`
- Payloads universais que funcionam em múltiplos contextos

### 9. SQLi Database-Specific (20 testes)
- **MySQL**: `@@version`, `information_schema`, `LOAD_FILE()`, `INTO OUTFILE`
- **MSSQL**: `@@VERSION`, `xp_cmdshell`, `BINARY_CHECKSUM`
- **PostgreSQL**: `version()`, `current_database()`, `pg_sleep()`
- **Oracle**: `ROWNUM`, `v$version`, `UTL_INADDR`
- **SQLite**: `sqlite_version()`, `last_insert_rowid()`
- **MongoDB (NoSQL)**: `{$ne:1}`, `{$gt:''}`

### 10. SQLi Advanced (50 testes)
- Payloads do arquivo `Generic_ErrorBased.txt`
- Técnicas avançadas de error-based injection
-Payloads específicos por DBMS

## Uso

### Executar apenas testes SQLi
```bash
./head-test.sh -u https://example.com -c sqli
# ou
./head-test.sh -u https://example.com -c sql
# ou
./head-test.sh -u https://example.com -c sqlinjection
```

### Executar todos os testes (incluindo SQLi)
```bash
./head-test.sh -u https://example.com -c all
```

### Com velocidade TURBO
```bash
./head-test.sh -u https://example.com -c sqli --speed 5
```

## Arquitetura

```
head-test.sh
├── source sqli-tester.sh
│   ├── test_sqli_classic()
│   ├── test_sqli_union()
│   ├── test_sqli_error_based()
│   ├── test_sqli_blind()
│   ├── test_sqli_auth_bypass()
│   ├── test_sqli_stacked()
│   ├── test_sqli_waf_bypass()
│   ├── test_sqli_polyglot()
│   ├── test_sqli_database_specific()
│   ├── test_sqli_from_intruders()
│   └── run_all_sqli_tests() [função principal]
└── PayloadsAllTheThings/SQL Injection/
    ├── README.md
    ├── MySQL Injection.md
    ├── MSSQL Injection.md
    ├── PostgreSQL Injection.md
    ├── OracleSQL Injection.md
    ├── SQLite Injection.md
    ├── Intruder/
    │   ├── Auth_Bypass.txt
    │   ├── Auth_Bypass2.txt
    │   ├── SQLi_Polyglots.txt
    │   ├── Generic_ErrorBased.txt
    │   ├── Generic_TimeBased.txt
    │   ├── Generic_UnionSelect.txt
    │   └── ... outros arquivos de payload
    └── SQLmap.md
```

## Payloads Utilizados

O módulo utiliza payloads de várias fontes:

- **PayloadsAllTheThings**: Repositório community-driven
- **FUZZDB**: Database de fuzzing para SQL
- **Generic Payloads**: Error-based, Time-based, Union-based
- **Auth Bypass**: Técnicas específicas de bypass de autenticação

## Técnicas de Injeção Testadas

### 1. **Classic SQL Injection**
Testes de injeção básica em parâmetros GET/POST.

### 2. **UNION-Based Injection**
Extração de dados através do operador UNION, incluindo detecção automática do número de colunas.

### 3. **Error-Based Injection**
Exploração de mensagens de erro do banco de dados para extrair informações.

###4. **Blind SQL Injection**
- **Boolean-Based**: Inferência através de respostas verdadeiro/falso
- **Time-Based**: Inferência através de delays no tempo de resposta

### 5. **Authentication Bypass**
Bypass de telas de login através de SQL injection.

### 6. **Stacked Queries**
Execução de múltiplas queries separadas por semicolon (`;`).

### 7. **WAF Evasion**
Técnicas para bypass de Web Application Firewalls:
- Alternative whitespace characters
- Comment-based obfuscation
- Encoding (URL, Unicode, HEX)
- Case manipulation
- Operator substitution

### 8. **Polyglot Payloads**
Payloads que funcionam em múltiplos contextos sem modificação.

### 9. **Database-Specific**
Payloads otimizados para cada tipo de banco de dados (MySQL, MSSQL, PostgreSQL, Oracle, SQLite).

## Quantidade de Testes

**Total estimado: 300+ testes de SQL Injection**

Distribuídos em:
- 30 testes clássicos
- 25 testes UNION-based
- 20 testes error-based
- 25 testes blind (boolean + time)
- 30 testes auth bypass
- 15 testes stacked queries
- 40 testes WAF bypass
- 10 testes polyglot
- 20 testes database-specific
- 50 testes avançados (da lista Intruders)
- +25 testes SQLi na query string (já existentes no head-test.sh)

## DBMS Suportados

- ✅ **MySQL / MariaDB**
- ✅ **Microsoft SQL Server (MSSQL)**
- ✅ **PostgreSQL**
- ✅ **Oracle**
- ✅ **SQLite**
- ✅ **MongoDB** (NoSQL, mas técnicas similares)
- ✅ **DB2**
- ✅ **Cassandra**

## Comparação com SQLmap

Este módulo **NÃO substitui o SQLmap**, mas oferece:

| Característica | sqli-tester.sh | SQLmap |
|----------------|----------------|--------|
| **Propósito** | Teste de hardening | Exploração completa |
| **Velocidade** | Muito rápido (300+ testes em ~1min) | Lento (análise profunda) |
| **Cobertura** | Ampla | Completa |
| **Automação** | Total | Total |
| **Extração de dados** | ❌ Não | ✅ Sim |
| **Shell** | ❌ Não | ✅ Sim |
| **Detecção** | ✅ Sim | ✅ Sim |
| **Uso** | Pentesting inicial, CI/CD | Pentesting avançado |

##Próximos Passos

Possíveis melhorias futuras:

1. **Payloads específicos por CMS**: WordPress, Joomla, Drupal
2. **Second-order SQL Injection**: Testes de injeção de segunda ordem
3. **Routed SQL Injection**: Hex-encoded nested queries
4. **PDO Prepared Statements**: Testes específicos para PDO bypass
5. **NoSQL Injection**: Expandir testes para MongoDB, CouchDB, etc.
6. **ORM Bypass**: Testes específicos para ORMs (Sequelize, Hibernate, etc.)

## Contribuindo

Para adicionar novos payloads SQLi:

1. Edite o arquivo `sqli-tester.sh`
2. Adicione a função de teste na categoria apropriada
3. Ou adicione payloads nos arquivos em `PayloadsAllTheThings/SQL Injection/Intruder/`
4. Execute os testes para validar

## Referências

- [PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQLmap Documentation](https://github.com/sqlmapproject/sqlmap/wiki)
- [PentestMonkey SQL Injection Cheat Sheet](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)

## Exemplo de Uso em CI/CD

```bash
#!/bin/bash
# Teste de segurança automatizado

STAGING_URL="https://staging.example.com"

# Executar testes SQLi
./head-test.sh -u "$STAGING_URL" -c sqli --speed 5 --filter fail

# Se houver falhas, bloquear deploy
if [ $? -ne 0 ]; then
    echo "❌ Vulnerabilidades SQLi detectadas! Deploy bloqueado."
    exit 1
fi

echo "✅ Sem vulnerabilidades SQLi detectadas. Deploy autorizado."
```

## Logs e Reporting

Os resultados podem ser salvos para análise posterior:

```bash
# Salvar output em arquivo
./head-test.sh -u https://example.com -c sqli -o sqli_report.txt

# Filtrar apenas falhas
./head-test.sh -u https://example.com -c sqli --filter fail -o sqli_failures.txt

# Filtrar apenas sucessos
./head-test.sh -u https://example.com -c sqli --filter pass -o sqli_blocks.txt
```
