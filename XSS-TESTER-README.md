# XSS Tester - Módulo de Testes XSS

## Descrição

O `xss-tester.sh` é um módulo separado do `head-test.sh` dedicado exclusivamente a testes de Cross-Site Scripting (XSS). Este módulo utiliza os payloads do repositório **PayloadsAllTheThings/XSS Injection** para fornecer testes abrangentes e bem organizados.

## Motivação

A separação dos testes XSS em um módulo dedicado oferece várias vantagens:

1. **Manutenção Facilitada**: Todas as alterações e melhorias relacionadas a XSS ficam isoladas em um único arquivo
2. **Organização**: Código mais limpo e modular no script principal
3. **Reutilização**: O módulo pode ser facilmente adaptado para outros projetos
4. **Escalabilidade**: Adicionar novos payloads XSS é mais simples e organizado
5. **Utilização de Payloads Profissionais**: Baseado no repositório PayloadsAllTheThings, amplamente utilizado pela comunidade de segurança

## Estrutura

O módulo está organizado nas seguintes categorias de testes:

### 1. XSS Básico (20 testes)
- Payloads clássicos: `<script>alert(1)</script>`
- Variações com IMG tag: `<img src=x onerror=alert(1)>`
- Variações com SVG: `<svg onload=alert(1)>`
- Encoding variants

### 2. XSS HTML5 (25 testes)
- Tags HTML5 modernas: `<video>`, `<audio>`, `<details>`
- Event handlers: `onfocus`, `onload`, `ontoggle`
- Mobile-specific events: `ontouchstart`, `ontouchend`

### 3. XSS Wrappers (15 testes)
- Wrapper `javascript:`: `javascript:alert(1)`
- Wrapper `data:`: `data:text/html,<script>alert(1)</script>`
- Wrapper `vbscript:`: `vbscript:msgbox(1)` (IE)
- URL encoding variants

### 4. XSS Polyglots (10 testes)
- Payloads que funcionam em múltiplos contextos
- Técnicas de escape de contexto

### 5. XSS WAF Bypass (30 testes)
- Case manipulation
- Null bytes e encoding
- URL encoding (single and double)
- HTML entities
- Unicode bypass
- Tab/newline injection
- Comments bypass
- Attribute breaking
- SVG bypass tricks

### 6. XSS DOM Based (15 testes)
- Fragment-based XSS
- JavaScript context injection
- Hidden input XSS
- Mutated XSS
- Location-based injection

### 7. XSS em Files (15 testes)
- SVG file XSS
- XML XSS
- Markdown XSS
- CSS XSS
- PostMessage XSS

### 8. XSS Avançados (50 testes)
- Utiliza payloads do arquivo `JHADDIX_XSS.txt`
- Payloads avançados e específicos

### 9. Blind XSS (10 testes)
- Cookie stealers
- localStorage stealers
- Beacon techniques
- XSS Hunter style payloads

## Uso

### Executar apenas testes XSS
```bash
./head-test.sh -u https://example.com -c xss
```

### Executar todos os testes (incluindo XSS)
```bash
./head-test.sh -u https://example.com -c all
```

### Com velocidade TURBO
```bash
./head-test.sh -u https://example.com -c xss --speed 5
```

## Arquitetura

```
head-test.sh
├── source xss-tester.sh
│   ├── test_xss_basic()
│   ├── test_xss_html5()
│   ├── test_xss_wrappers()
│   ├── test_xss_polyglots()
│   ├── test_xss_waf_bypass()
│   ├── test_xss_dom_based()
│   ├── test_xss_in_files()
│   ├── test_xss_from_intruders()
│   ├── test_xss_blind()
│   └── run_all_xss_tests() [função principal]
└── PayloadsAllTheThings/XSS Injection/
    ├── README.md
    ├── Intruders/
    │   ├── JHADDIX_XSS.txt
    │   ├── BRUTELOGIC-XSS-STRINGS.txt
    │   ├── XSS_Polyglots.txt
    │   └── ... outros arquivos de payload
    └── Files/
```

## Payloads Utilizados

O módulo utiliza payloads de várias fontes reconhecidas na comunidade de segurança:

- **PayloadsAllTheThings**: Repositório mantido pela comunidade
- **JHADDIX**: Payloads do pesquisador Jason Haddix
- **BRUTELOGIC**: Payloads do especialista Rodolfo Assis
- **PortSwigger**: Cheat sheet oficial do Burp Suite

## Vantagens desta Abordagem

1. **Atualização Facilitada**: Para adicionar novos payloads, basta editar `xss-tester.sh`
2. **Testes Focados**: Executar apenas `-c xss` quando necessário
3. **Integração com Payloads Externos**: Fácil integração com listas de payloads atualizadas
4. **Modularidade**: Outros tipos de testes podem seguir o mesmo padrão
5. **Debugging Simplificado**: Isolar problemas em testes XSS fica mais fácil

## Quantidade de Testes

**Total estimado: 250+ testes de XSS**

Distribuídos em:
- 20 testes básicos
- 25 testes HTML5
- 15 testes de wrappers
- 10 testes de polyglots
- 30 testes de WAF bypass
- 15 testes DOM-based
- 15 testes em files
- 50 testes avançados (da lista Intruders)
- 10 testes Blind XSS
- +20 testes XSS na query string (já existentes no head-test.sh)

## Próximos Passos

Possíveis melhorias futuras:

1. **Módulos Adicionais**: Criar módulos separados para SQLi, LFI, RFI, etc.
2. **Configuração de Payloads**: Permitir ao usuário especificar quais arquivos de payload usar
3. **Reporting**: Gerar relatórios específicos de XSS
4. **Modo Interativo**: Permitir selecionar categorias específicas de XSS
5. **Detecção de Contexto**: Identificar automaticamente o contexto e testar payloads relevantes

## Contribuindo

Para adicionar novos payloads XSS:

1. Edite o arquivo `xss-tester.sh`
2. Adicione a função de teste na categoria apropriada
3. Ou adicione payloads nos arquivos em `PayloadsAllTheThings/XSS Injection/Intruders/`
4. Execute os testes para validar

## Referências

- [PayloadsAllTheThings - XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP XSS Filter Evasion](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
