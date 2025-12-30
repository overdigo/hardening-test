#!/bin/bash
#==============================================================================
# Script para build e execução do container de testes HTTP/3
# Uso:
#   ./docker-run.sh build          - Constrói a imagem Docker
#   ./docker-run.sh test <URL>     - Executa os testes na URL
#   ./docker-run.sh http3 <URL>    - Testa se a URL suporta HTTP/3
#   ./docker-run.sh shell          - Abre um shell interativo no container
#==============================================================================

set -eo pipefail

IMAGE_NAME="hardening-test-http3"
IMAGE_TAG="latest"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

show_help() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════════════════╗"
    echo "║         HTTP/3 Security Testing Suite - Docker Runner                     ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo -e "${YELLOW}Uso:${NC}"
    echo "  ./docker-run.sh build                    - Constrói a imagem Docker"
    echo "  ./docker-run.sh test <URL> [OPTIONS]     - Executa testes na URL"
    echo "  ./docker-run.sh http3 <URL>              - Verifica suporte HTTP/3"
    echo "  ./docker-run.sh curl <ARGS>              - Executa curl com HTTP/3"
    echo "  ./docker-run.sh shell                    - Shell interativo"
    echo ""
    echo -e "${YELLOW}Exemplos:${NC}"
    echo "  ./docker-run.sh build"
    echo "  ./docker-run.sh test https://example.com -c all"
    echo "  ./docker-run.sh test https://example.com -c header -v"
    echo "  ./docker-run.sh http3 https://cloudflare.com"
    echo "  ./docker-run.sh curl -IL --http3 https://cloudflare.com"
    echo ""
    echo -e "${YELLOW}Categorias de teste disponíveis:${NC}"
    echo "  all, method, cookie, query, useragent, referer, host, uri"
    echo "  header, contenttype, encoding, xff, range, smuggling, nginx"
    echo "  php, database, ssrf, fakebots, waf, ports, ssl"
}

build_image() {
    echo -e "${BLUE}🔨 Construindo imagem Docker: ${IMAGE_NAME}:${IMAGE_TAG}${NC}"
    echo ""
    
    cd "$SCRIPT_DIR"
    
    docker build \
        --tag "${IMAGE_NAME}:${IMAGE_TAG}" \
        --file Dockerfile \
        .
    
    echo ""
    echo -e "${GREEN}✓ Imagem construída com sucesso!${NC}"
    echo -e "  Use: ${CYAN}./docker-run.sh test <URL>${NC}"
}

run_tests() {
    local url="$1"
    shift
    
    if [ -z "$url" ]; then
        echo -e "${RED}Erro: URL é obrigatória${NC}"
        echo "Uso: ./docker-run.sh test <URL> [OPTIONS]"
        exit 1
    fi
    
    echo -e "${BLUE}🧪 Executando testes de segurança em: ${url}${NC}"
    echo -e "${CYAN}   Com suporte a HTTP/3 (QUIC)${NC}"
    echo ""
    
    docker run --rm -it \
        --network host \
        "${IMAGE_NAME}:${IMAGE_TAG}" \
        -u 1 "$url" "$@"
}

check_http3() {
    local url="$1"
    
    if [ -z "$url" ]; then
        echo -e "${RED}Erro: URL é obrigatória${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}🔍 Verificando suporte HTTP/3 para: ${url}${NC}"
    echo ""
    
    # Primeiro tenta HTTP/3
    echo -e "${YELLOW}Tentando HTTP/3...${NC}"
    local http3_result
    http3_result=$(docker run --rm --entrypoint /usr/local/bin/curl "${IMAGE_NAME}:${IMAGE_TAG}" \
        -sI --http3 -k --max-time 10 "$url" 2>/dev/null | head -1)
    
    if echo "$http3_result" | grep -q "HTTP/3"; then
        echo -e "${GREEN}✓ HTTP/3 SUPORTADO!${NC}"
        echo ""
        docker run --rm --entrypoint /usr/local/bin/curl "${IMAGE_NAME}:${IMAGE_TAG}" \
            -IL --http3 -k --max-time 10 "$url" 2>&1 | head -20
    else
        echo -e "${YELLOW}⚠ HTTP/3 não detectado ou indisponível${NC}"
        echo ""
        echo "Tentando HTTP/2..."
        docker run --rm --entrypoint /usr/local/bin/curl "${IMAGE_NAME}:${IMAGE_TAG}" \
            -IL --http2 -k --max-time 10 "$url" 2>&1 | head -20
    fi
}

run_curl() {
    echo -e "${BLUE}🌐 Executando curl com suporte HTTP/3${NC}"
    echo ""
    
    docker run --rm -it \
        --network host \
        --entrypoint /usr/local/bin/curl \
        "${IMAGE_NAME}:${IMAGE_TAG}" \
        "$@"
}

run_shell() {
    echo -e "${BLUE}🐚 Abrindo shell interativo no container${NC}"
    echo ""
    
    docker run --rm -it \
        --network host \
        --entrypoint /bin/bash \
        "${IMAGE_NAME}:${IMAGE_TAG}"
}

# Verificar se imagem existe para comandos que precisam dela
check_image() {
    if ! docker image inspect "${IMAGE_NAME}:${IMAGE_TAG}" &>/dev/null; then
        echo -e "${YELLOW}⚠ Imagem não encontrada. Construindo...${NC}"
        echo ""
        build_image
        echo ""
    fi
}

# Main
case "${1:-}" in
    build)
        build_image
        ;;
    test)
        check_image
        shift
        run_tests "$@"
        ;;
    http3|check)
        check_image
        run_curl -IL -k --http3 "${2:-https://cloudflare.com}"
        ;;
    curl)
        check_image
        shift
        run_curl "$@"
        ;;
    shell|sh)
        check_image
        run_shell
        ;;
    help|--help|-h|"")
        show_help
        ;;
    *)
        echo -e "${RED}Comando desconhecido: $1${NC}"
        show_help
        exit 1
        ;;
esac
