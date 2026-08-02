FROM rust:1.96.1-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663

RUN apt-get update \
    && apt-get install -y --no-install-recommends nfs-common python3 \
    && rm -rf /var/lib/apt/lists/*

ENV NFSEMBED_CONTAINERIZED=1

WORKDIR /work
