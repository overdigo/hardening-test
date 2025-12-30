# Dockerfile para rodar head-test.sh com suporte a HTTP/3 (QUIC)
# Base: ymuski/curl-http3 - curl compilado com nghttp3 e ngtcp2 (Debian bookworm)

FROM ymuski/curl-http3:latest

LABEL maintainer="hardening-test"
LABEL description="HTTP Header Security Testing Suite with HTTP/3 support"
LABEL version="5.1.0"

# Instalar dependências necessárias para o script bash (Debian)
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    coreutils \
    grep \
    gawk \
    sed \
    findutils \
    procps \
    ncurses-bin \
    netcat-openbsd \
    nmap \
    openssl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Criar diretório de trabalho
WORKDIR /app

# Copiar o script e arquivos necessários
COPY head-test.sh /app/
COPY lists/ /app/lists/

# Tornar o script executável
RUN chmod +x /app/head-test.sh

# Alias curl para garantir que o curl com HTTP/3 seja usado
ENV PATH="/usr/local/bin:${PATH}"

# Ponto de entrada padrão
ENTRYPOINT ["/bin/bash", "/app/head-test.sh"]

# Argumentos padrão (podem ser sobrescritos)
CMD ["--help"]
