# 🤖 Expansão de Testes de Bots - v6.1.0

## 📋 Resumo das Alterações

Este documento descreve as novas funções criadas para expandir os testes de bots no `head-test.sh`.

---

## ✨ Novas Funcionalidades

### 1. **test_good_bots() EXPANDIDO** (40+ bots legítimos)

Função expandida para testar **40+ bots legítimos** que devem ser permitidos.

**Categorias incluídas:**

#### 🔍 Search Engines (9 bots)
- Googlebot (Mobile + Desktop)
- Google-InspectionTool
- Bingbot
- DuckDuckBot
- YandexBot
- Baiduspider
- Yahoo Slurp
- Applebot

#### 📱 Social Media Crawlers (9 bots)
- Facebot (Facebook)
- Twitterbot
- LinkedInBot
- Slackbot
- WhatsApp
- Telegrambot
- Pinterest
- Discordbot
- Redditbot

#### 📊 SEO & Analytics Tools (5 bots)
- Ahrefs Bot
- SEMrush Bot
- Moz Dotbot
- Screaming Frog
- Majestic (MJ12bot)

#### 📡 Site Monitoring & Uptime (4 bots)
- UptimeRobot
- Pingdom
- StatusCake
- Site24x7

#### 🗄️ Web Archives & Crawlers (3 bots)
- Internet Archive
- Wayback Machine
- Common Crawl

#### 🛒 E-commerce & Shopping (2 bots)
- Google Shopping
- Amazon Bot

#### 🛠️ Developer Tools (3 bots)
- Chrome Lighthouse
- Google PageSpeed
- W3C Validator

#### 📰 Other Legitimate Bots (4 bots)
- Feedspot
- Feedly
- Apple News
- Qwant

**Total: 40+ bots legítimas**

---

### 2. **test_ai_bots() NOVA** (25+ AI bots)

Função totalmente nova para testar **bots de Inteligência Artificial**.

**Categorias incluídas:**

#### 🧠 ChatGPT & OpenAI (3 bots)
- ChatGPT-User (Web Browsing)
- GPTBot (Training)
- OAI-SearchBot

#### 🤖 Google AI - Bard/Gemini (2 bots)
- Google-Extended (Bard)
- GoogleOther (AI Training)

#### 💬 Anthropic - Claude (3 bots)
- Claude-Web
- anthropic-ai
- ClaudeBot

#### 🔍 Perplexity AI (1 bot)
- PerplexityBot

#### 📘 Meta AI (2 bots)
- Meta-ExternalAgent
- FacebookBot

#### 🌐 Cohere AI (1 bot)
- cohere-ai

#### 📚 Common Crawl (1 bot)
- CCBot (usado por LLMs)

#### 🍎 Apple Intelligence (1 bot)
- Applebot-Extended

#### 🗣️ Amazon Alexa (1 bot)
- ia_archiver

#### 🎵 Bytedance AI - TikTok (1 bot)
- Bytespider

#### 🔎 You.com AI Search (1 bot)
- YouBot

#### 📊 Diffbot (1 bot)
- Diffbot

#### 🚫 Scrapy & ML Crawlers - BLOQUEÁVEIS (3 bots)
- Scrapy (Python)
- Python-urllib
- Go-http-client

**Total: 25+ AI bots**

---

## 🔧 Como Integrar no head-test.sh

### Opção 1: Substituição Manual

1. **Substituir test_good_bots()**:
   - Localize a função `test_good_bots()` no `head-test.sh` (linhas 717-730)
   - Substitua por todo o conteúdo de `good-bots-expanded.sh`

2. **Adicionar test_ai_bots()**:
   - Após a função `test_fake_bots()` (linha ~757)
   - Cole todo o conteúdo de `ai-bots-function.sh`

3. **Adicionar categoria no switch/case**:
   - Localize a seção onde as categorias são processadas (linha ~5088)
   - Adicione:
   ```bash
   aibots|aibot|ai-bots|ai) test_ai_bots ;;
   ```

4. **Adicionar no "all"**:
   - Localize onde `test_good_bots` é chamado no teste completo (linha ~5238)
   - Adicione após `test_fake_bots`:
   ```bash
   test_ai_bots
   ```

### Opção 2: Merge Automático com Patch

```bash
cd /home/loja01/hardening-test

# Backup
cp head-test.sh head-test.sh.backup

# Preparar integração (executar manualmente as edições acima)
```

---

## 📖 Como Usar

### Testar Bots Legítimos (40+ bots)
```bash
./head-test.sh -u https://example.com -c useragent
```

### Testar AI Bots (25+ bots)
```bash
./head-test.sh -u https://example.com -c aibots
```

### Testar Todos os Bots
```bash
./head-test.sh -u https://example.com -c all
```

---

## 🛡️ Política para AI Bots

Por padrão, a função `test_ai_bots()` está configurada com `ai_policy=\"allow\"`, 
ou seja, **assume que você quer PERMITIR bots de IA**.

### Para BLOQUEAR AI Bots Globalmente

Edite `ai-bots-function.sh` (ou após integrar no head-test.sh):

```bash
local ai_policy=\"block\"  # Mude de "allow" para "block"
```

### Bloquear via robots.txt

Adicione ao seu `robots.txt`:

```
# Bloquear OpenAI (ChatGPT)
User-agent: GPTBot
Disallow: /

User-agent: ChatGPT-User
Disallow: /

# Bloquear Google AI (Bard/Gemini)
User-agent: Google-Extended
Disallow: /

# Bloquear Anthropic (Claude)
User-agent: ClaudeBot
Disallow: /

User-agent: Claude-Web
Disallow: /

# Bloquear Common Crawl
User-agent: CCBot
Disallow: /

# Bloquear Perplexity
User-agent: PerplexityBot
Disallow: /
```

---

## 📊 Estatísticas

| Métrica | Antes | Depois | Incremento |
|---------|-------|--------|------------|
| **Bots Legítimos** | 10 | 40+ | +300% |
| **AI Bots** | 0 | 25+ | NOVO |
| **Total Bots Testados** | ~110 | ~165 | +55 (+50%) |

---

## 🎯 Benefícios

✅ **Cobertura Completa**: Testa todos os principais crawlers legítimos  
✅ **AI-Ready**: Suporte para testar bots de IA modernos  
✅ **Organizado**: Bots agrupados por categoria  
✅ **Configurável**: Fácil definir política allow/block para AI  
✅ **Documentado**: Cada bot identificado com provider  

---

## 📝 Notas

- **Bots Legítimos** devem sempre retornar `PASS` (permitidos)
- **AI Bots** são configuráveis conforme sua política de dados
- **Fake Bots** devem sempre retornar `PASS` (bloqueados)

---

## 🔗 Referências

- [robots.txt para AI](https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers)
- [OpenAI GPTBot](https://platform.openai.com/docs/gptbot)
- [Anthropic ClaudeBot](https://www.anthropic.com/bot)
- [Google-Extended](https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers#google-extended)

---

**Criado em**: 2026-01-07  
**Versão**: 6.1.0  
**Autor**: head-test.sh expansion
