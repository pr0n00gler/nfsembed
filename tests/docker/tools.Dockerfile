FROM rust:1.96.1-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663

ARG CARGO_FUZZ_VERSION=0.13.2
ARG NIGHTLY_TOOLCHAIN=nightly-2026-07-01

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && rustup component add clippy rustfmt \
    && rustup toolchain install "${NIGHTLY_TOOLCHAIN}" \
        --profile minimal \
        --component llvm-tools-preview \
        --component rustfmt \
        --component rust-src \
    && cargo install cargo-fuzz \
        --version "${CARGO_FUZZ_VERSION}" \
        --locked

ENV NIGHTLY_TOOLCHAIN=${NIGHTLY_TOOLCHAIN}

WORKDIR /workspace

CMD ["bash"]
