FROM mcr.microsoft.com/devcontainers/base:jammy

ENV DEBIAN_FRONTEND=noninteractive
ENV DEBCONF_NONINTERACTIVE_SEEN=true
ENV PATH=$PATH:/usr/local/go/bin:

RUN touch dpkg-preseed \
    && echo "tzdata tzdata/Areas select America" >> dpkg-preseed \
    && echo "tzdata tzdata/Zones/America select New_York" >> dpkg-preseed \
    && debconf-set-selections dpkg-preseed

COPY --from=docker:dind /usr/local/bin/docker /usr/local/bin/

RUN apt update && apt install -y \
    build-essential \
    curl \
    gettext-base \
    git \
    jq \
    less \
    unzip \
    vim \
    wget \
    xxd

# install go
ARG GOLANG_VERSION=1.22.1
RUN SYSTEM_ARCH=$(dpkg --print-architecture) \
    && curl -sL "https://go.dev/dl/go${GOLANG_VERSION}.linux-${SYSTEM_ARCH}.tar.gz" | tar -C /usr/local -xzf - \
    && /usr/local/go/bin/go install -v golang.org/x/tools/gopls@latest

# install aws
RUN SYSTEM_ARCH=$(uname -m) \
    && curl "https://awscli.amazonaws.com/awscli-exe-linux-${SYSTEM_ARCH}-2.13.33.zip" -o "awscliv2.zip" \
    && unzip -qq awscliv2.zip \
    && aws/install \
    && rm -rf aws

# install opa
RUN SYSTEM_ARCH=$(dpkg --print-architecture) \
    && wget "https://github.com/open-policy-agent/opa/releases/latest/download/opa_linux_${SYSTEM_ARCH}_static" -O /usr/local/bin/opa \
    && chmod +x /usr/local/bin/opa

# arkade
RUN curl -sLS https://get.arkade.dev | sh

WORKDIR /
