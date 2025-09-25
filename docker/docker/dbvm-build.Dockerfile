# Jammy + toolchain-r/test PPA so we can pin gcc-9 cleanly.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg software-properties-common && \
    add-apt-repository -y ppa:ubuntu-toolchain-r/test && \
    apt-get update -qq && apt-get install -y --no-install-recommends \
      gcc-9 g++-9 gcc-9-multilib g++-9-multilib \
      build-essential yasm nasm make libc6-dev-i386 \
      git ccache && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 90 && \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-9 90 && \
    # ccache fronting (optional but nice)
    ln -sf /usr/bin/ccache /usr/local/bin/gcc && \
    ln -sf /usr/bin/ccache /usr/local/bin/g++ && \
    echo 'export CCACHE_DIR=/github/home/.ccache' >> /etc/profile.d/ccache.sh && \
    echo 'max_size = 2G' > /etc/ccache.conf && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
