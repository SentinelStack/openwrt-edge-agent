FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    xz-utils \
    file \
    ca-certificates \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

RUN curl -fsSLO https://downloads.openwrt.org/releases/23.05.3/targets/mvebu/cortexa9/openwrt-toolchain-23.05.3-mvebu-cortexa9_gcc-12.3.0_musl_eabi.Linux-x86_64.tar.xz \
    && tar -xJf openwrt-toolchain-23.05.3-mvebu-cortexa9_gcc-12.3.0_musl_eabi.Linux-x86_64.tar.xz \
    && rm -f openwrt-toolchain-23.05.3-mvebu-cortexa9_gcc-12.3.0_musl_eabi.Linux-x86_64.tar.xz

ENV PATH="/opt/openwrt-toolchain-23.05.3-mvebu-cortexa9_gcc-12.3.0_musl_eabi.Linux-x86_64/toolchain-arm_cortex-a9+vfpv3-d16_gcc-12.3.0_musl_eabi/bin:${PATH}"

# Cross-build mbedTLS (matches the router's 2.28.x) into static libs so the
# agent can do real in-process HTTPS. Linked by `make build`.
ARG MBEDTLS_VER=2.28.8
RUN curl -fsSL -o mbedtls.tar.gz https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v${MBEDTLS_VER}.tar.gz \
    && tar -xzf mbedtls.tar.gz && rm -f mbedtls.tar.gz \
    && make -C mbedtls-${MBEDTLS_VER} -j"$(nproc)" lib \
        CC=arm-openwrt-linux-muslgnueabi-gcc AR=arm-openwrt-linux-muslgnueabi-ar \
    && mkdir -p /opt/mbedtls/lib /opt/mbedtls/include \
    && cp mbedtls-${MBEDTLS_VER}/library/*.a /opt/mbedtls/lib/ \
    && cp -r mbedtls-${MBEDTLS_VER}/include/mbedtls mbedtls-${MBEDTLS_VER}/include/psa /opt/mbedtls/include/ \
    && rm -rf mbedtls-${MBEDTLS_VER}

ENV MBEDTLS_DIR=/opt/mbedtls

WORKDIR /work
