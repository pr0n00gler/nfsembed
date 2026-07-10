FROM rust:1.96.1-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends nfs-common python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
