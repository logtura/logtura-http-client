# syntax=docker/dockerfile:1.7
#
# Two-stage build:
#   1) compile a statically-linked musl binary against pinned Rust
#   2) copy it into a scratch image so the final layer is just the
#      binary (~5MB), no shell, no OS surface, no CVE flow-through.
#
# Consumers (Logtura's deployment Dockerfile, anyone running a Vector
# `exec` source) reference this image via:
#   COPY --from=ghcr.io/logtura/logtura-http-client:vX.Y.Z \
#        /logtura-http-client /usr/local/bin/logtura-http-client

FROM rust:1.95-slim AS build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends \
      musl-tools \
    && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN cargo build --release --target x86_64-unknown-linux-musl --bin logtura-http-client

FROM scratch
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/logtura-http-client /logtura-http-client
ENTRYPOINT ["/logtura-http-client"]
