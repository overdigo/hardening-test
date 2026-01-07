#!/bin/bash
#==============================================================================
# Bots Tester - Módulo de Testes de Bots (Legítimos, Fake e AI)
# Versão: 1.0.0
# Descrição: Script modular para testes de user-agents de bots
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
BOTS_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

#==============================================================================
# FUNÇÕES AUXILIARES
#==============================================================================

bots_print_section() {
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

bots_print_subsection() {
    echo -e "\n  ${BOLD}${BLUE}▶ $1${NC}"
}

#==============================================================================
# BOTS LEGÍTIMOS EXPANDIDOS (40+ bots)
#==============================================================================
test_good_bots() {
    bots_print_section "✅ TESTES DE BOTS LEGÍTIMOS (devem passar - 40+ bots)" "-c useragent"
    
    bots_print_subsection "Search Engines (Motores de Busca)"
    test_curl "Googlebot Mobile" "allow" -Lk -A "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X) AppleWebKit/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" "$URL"
    test_curl "Googlebot Desktop" "allow" -Lk -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" "$URL"
    test_curl "Google-InspectionTool" "allow" -Lk -A "Mozilla/5.0 (compatible; Google-InspectionTool/1.0)" "$URL"
    test_curl "Bingbot" "allow" -Lk -A "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)" "$URL"
    test_curl "DuckDuckBot" "allow" -Lk -A "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)" "$URL"
    test_curl "YandexBot" "allow" -Lk -A "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)" "$URL"
    test_curl "Baiduspider" "allow" -Lk -A "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)" "$URL"
    test_curl "Yahoo Slurp" "allow" -Lk -A "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)" "$URL"
    test_curl "Applebot" "allow" -Lk -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)" "$URL"
    
    bots_print_subsection "Social Media Crawlers"
    test_curl "Facebot" "allow" -Lk -A "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)" "$URL"
    test_curl "Twitterbot" "allow" -Lk -A "Twitterbot/1.0" "$URL"
    test_curl "LinkedInBot" "allow" -Lk -A "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)" "$URL"
    test_curl "Slackbot" "allow" -Lk -A "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)" "$URL"
    test_curl "WhatsApp" "allow" -Lk -A "WhatsApp/2.23.20.0" "$URL"
    test_curl "Telegrambot" "allow" -Lk -A "TelegramBot (like TwitterBot)" "$URL"
    test_curl "Pinterest" "allow" -Lk -A "Mozilla/5.0 (compatible; Pinterestbot/1.0; +http://www.pinterest.com/bot.html)" "$URL"
    test_curl "Discordbot" "allow" -Lk -A "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)" "$URL"
    test_curl "Redditbot" "allow" -Lk -A "Mozilla/5.0 (compatible; Redditbot/1.0; +http://www.reddit.com/feedback)" "$URL"
    
    bots_print_subsection "SEO & Analytics Tools"
    test_curl "Ahrefs Bot" "allow" -Lk -A "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)" "$URL"
    test_curl "SEMrush Bot" "allow" -Lk -A "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)" "$URL"
    test_curl "Moz Dotbot" "allow" -Lk -A "Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)" "$URL"
    test_curl "Screaming Frog" "allow" -Lk -A "Screaming Frog SEO Spider/19.0" "$URL"
    test_curl "Majestic" "allow" -Lk -A "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)" "$URL"
    
    bots_print_subsection "Site Monitoring & Uptime"
    test_curl "UptimeRobot" "allow" -Lk -A "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)" "$URL"
    test_curl "Pingdom" "allow" -Lk -A "Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)" "$URL"
    test_curl "StatusCake" "allow" -Lk -A "Mozilla/5.0 (compatible; StatusCake.com)" "$URL"
    test_curl "Site24x7" "allow" -Lk -A "Mozilla/5.0 (compatible; Site24x7; https://www.site24x7.com/)" "$URL"
    
    bots_print_subsection "Web Archives & Crawlers"
    test_curl "Internet Archive" "allow" -Lk -A "Mozilla/5.0 (compatible; archive.org_bot +http://archive.org/details/archive.org_bot)" "$URL"
    test_curl "Wayback Machine" "allow" -Lk -A "Mozilla/5.0 (compatible; Wayback Save Page/1.0; +http://web.archive.org/)" "$URL"
    test_curl "Common Crawl" "allow" -Lk -A "CCBot/2.0 (https://commoncrawl.org/faq/)" "$URL"
    
    bots_print_subsection "E-commerce & Shopping"
    test_curl "Google Shopping" "allow" -Lk -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html) (via GoogleImageProxy)" "$URL"
    test_curl "Amazon Bot" "allow" -Lk -A "Mozilla/5.0 (compatible; Amazon; +https://amazon.com/)" "$URL"
    
    bots_print_subsection "Developer Tools"
    test_curl "Chrome Lighthouse" "allow" -Lk -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Chrome-Lighthouse" "$URL"
    test_curl "Google PageSpeed" "allow" -Lk -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Chrome-Lighthouse" "$URL"
    test_curl "W3C Validator" "allow" -Lk -A "W3C_Validator/1.3 http://validator.w3.org/services" "$URL"
    
    bots_print_subsection "Other Legitimate Bots"
    test_curl "Feedspot" "allow" -Lk -A "Feedspot/1.0 (+https://www.feedspot.com/fs/fetcher; like FeedFetcher-Google)" "$URL"
    test_curl "Feedly" "allow" -Lk -A "Mozilla/5.0 (compatible; Feedly/1.0; +http://www.feedly.com/fetcher.html; 1 subscribers)" "$URL"
    test_curl "Apple News" "allow" -Lk -A "AppleNewsBot/1.0" "$URL"
    test_curl "Qwant" "allow" -Lk -A "Mozilla/5.0 (compatible; Qwantify/2.4w; +https://www.qwant.com/)/2.4w" "$URL"
}

#==============================================================================
# FAKE BOTS - Bots que se passam por Google/Bing (devem ser BLOQUEADOS)
#==============================================================================
test_fake_bots() {
    bots_print_section "🎭 TESTES DE FAKE BOTS (Impostores - devem ser BLOQUEADOS)" "-c fakebots"
    
    echo -e "  ${YELLOW}ℹ️  Estes são bots FALSOS que tentam se passar por crawlers legítimos${NC}"
    echo -e "  ${YELLOW}   Servidores bem configurados devem verificar o IP de origem e bloquear${NC}"
    echo ""
    
    # Fake Googlebot - usando User-Agent real mas de IP não autorizado
    test_curl "FAKE Googlebot Mobile" "block" -Lk -A "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" "$URL"
    test_curl "FAKE Googlebot Desktop" "block" -Lk -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" "$URL"
    test_curl "FAKE Googlebot-Image" "block" -Lk -A "Googlebot-Image/1.0" "$URL"
    test_curl "FAKE Googlebot-News" "block" -Lk -A "Googlebot-News" "$URL"
    test_curl "FAKE Googlebot-Video" "block" -Lk -A "Googlebot-Video/1.0" "$URL"
    
    # Fake Bingbot
    test_curl "FAKE Bingbot" "block" -Lk -A "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)" "$URL"
    test_curl "FAKE Bingbot Mobile" "block" -Lk -A "Mozilla/5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11A465 Safari/9537.53 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)" "$URL"
    test_curl "FAKE MSNBot" "block" -Lk -A "msnbot/2.0b (+http://search.msn.com/msnbot.htm)" "$URL"
    
    # Fake outros bots famosos
    test_curl "FAKE YandexBot" "block" -Lk -A "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)" "$URL"
    test_curl "FAKE Baiduspider" "block" -Lk -A "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)" "$URL"
}

#==============================================================================
# AI BOTS - Bots de Inteligência Artificial (configurável: allow ou block)
#==============================================================================
test_ai_bots() {
    bots_print_section "🤖 TESTES DE AI BOTS (Inteligência Artificial - 25+ bots)" "-c aibots"
    
    echo -e "  ${CYAN}ℹ️  Estes são bots de IA que coletam dados para treinamento de modelos${NC}"
    echo -e "  ${CYAN}   Você pode escolher permitir ou bloquear conforme sua política de dados${NC}"
    echo ""
    
    # Por padrão, testando se estão sendo PERMITIDOS (allow)
    # Mude para "block" se você quer bloqueá-los
    local ai_policy="allow"  # Altere para "block" se necessário
    
    bots_print_subsection "ChatGPT & OpenAI"
    test_curl "ChatGPT-User (Web Browsing)" "$ai_policy" -Lk -A "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ChatGPT-User/1.0; +https://openai.com/bot)" "$URL"
    test_curl "GPTBot (Training)" "$ai_policy" -Lk -A "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.0; +https://openai.com/gptbot)" "$URL"
    test_curl "OAI-SearchBot" "$ai_policy" -Lk -A "OAI-SearchBot" "$URL"
    
    bots_print_subsection "Google AI (Bard/Gemini)"
    test_curl "Google-Extended (Bard)" "$ai_policy" -Lk -A "Mozilla/5.0 (compatible; Google-Extended/1.0; +https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers)" "$URL"
    test_curl "GoogleOther (AI Training)" "$ai_policy" -Lk -A "GoogleOther" "$URL"
    
    bots_print_subsection "Anthropic (Claude)"
    test_curl "Claude-Web" "$ai_policy" -Lk -A "Claude-Web/1.0" "$URL"
    test_curl "anthropic-ai" "$ai_policy" -Lk -A "anthropic-ai" "$URL"
    test_curl "ClaudeBot" "$ai_policy" -Lk -A "ClaudeBot/1.0; +https://www.anthropic.com/bot" "$URL"
    
    bots_print_subsection "Perplexity AI"
    test_curl "PerplexityBot" "$ai_policy" -Lk -A "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/bot)" "$URL"
    
    bots_print_subsection "Meta AI (Facebook AI)"
    test_curl "Meta-ExternalAgent" "$ai_policy" -Lk -A "Meta-ExternalAgent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)" "$URL"
    test_curl "FacebookBot" "$ai_policy" -Lk -A "facebookexternalua" "$URL"
    
    bots_print_subsection "Cohere AI"
    test_curl "cohere-ai" "$ai_policy" -Lk -A "cohere-ai" "$URL"
    
    bots_print_subsection "Common Crawl (usado por LLMs)"
    test_curl "CCBot (Common Crawl)" "$ai_policy" -Lk -A "CCBot/2.0 (https://commoncrawl.org/faq/)" "$URL"
    
    bots_print_subsection "Apple Intelligence"
    test_curl "Applebot-Extended" "$ai_policy" -Lk -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)" "$URL"
    
    bots_print_subsection "Amazon Alexa"
    test_curl "ia_archiver" "$ai_policy" -Lk -A "ia_archiver (+http://www.alexa.com/site/help/webmasters; crawler@alexa.com)" "$URL"
    
    bots_print_subsection "Bytedance AI (TikTok)"
    test_curl "Bytespider" "$ai_policy" -Lk -A "Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)" "$URL"
    
    bots_print_subsection "YouBot (You.com AI Search)"
    test_curl "YouBot" "$ai_policy" -Lk -A "Mozilla/5.0 (compatible; YouBot/1.0; +https://about.you.com/youbot)" "$URL"
    
    bots_print_subsection "Diffbot"
    test_curl "Diffbot" "$ai_policy" -Lk -A "Mozilla/5.0 (compatible; Diffbot/0.2; +http://www.diffbot.com)" "$URL"
    
    bots_print_subsection "Scrapy & ML Crawlers (potencialmente bloqueáveis)"
    test_curl "Scrapy (Python)" "block" -Lk -A "Scrapy/2.11.0 (+https://scrapy.org)" "$URL"
    test_curl "Python-urllib" "block" -Lk -A "Python-urllib/3.11" "$URL"
    test_curl "Go-http-client" "block" -Lk -A "Go-http-client/2.0" "$URL"
    
    echo ""
    echo -e "  ${YELLOW}💡 DICA: Para bloquear bots de IA, adicione ao robots.txt:${NC}"
    echo -e "  ${YELLOW}   User-agent: GPTBot${NC}"
    echo -e "  ${YELLOW}   Disallow: /${NC}"
    echo -e "  ${YELLOW}   User-agent: Google-Extended${NC}"
    echo -e "  ${YELLOW}   Disallow: /${NC}"
}

#==============================================================================
# FUNÇÃO PRINCIPAL - Executa todos os testes de bots
#==============================================================================
run_all_bots_tests() {
    bots_print_section "🤖 TESTES COMPLETOS DE BOTS (Legítimos + Fake + AI)" "-c bots"
    
    echo -e "${CYAN}ℹ️  Testando 75+ bots: Legítimos, Fake e AI${NC}"
    echo ""
    
    test_good_bots
    test_fake_bots
    test_ai_bots
    
    echo ""
    echo -e "${GREEN}✓ Todos os testes de bots foram concluídos!${NC}"
}

# Se o script for executado diretamente (não como source)
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    echo -e "${RED}❌ Este script deve ser chamado pelo head-test.sh${NC}"
    echo -e "${YELLOW}Use: ./head-test.sh -u URL -c useragent|fakebots|aibots${NC}"
    exit 1
fi
