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

WORKDIR /work
