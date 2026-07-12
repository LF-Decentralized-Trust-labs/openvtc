FROM rust:1 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN \
    addgroup --system messagebus &&\
    apt update &&\
    apt install -y libdbus-1-dev pkg-config libpcsclite-dev

ADD . /build
WORKDIR /build

# Cache a build layer for downloads
RUN cargo fetch
RUN cargo build

# Create the actual image
FROM debian:trixie-slim
ARG DEBIAN_FRONTEND=noninteractive
RUN \
    apt-get update &&\
    apt-get install -y ca-certificates libpcsclite1 &&\
    apt-get clean &&\
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/debug/openvtc /openvtc
WORKDIR /data
ENTRYPOINT ["/openvtc"]
# CMD ["--config", "/data/config.toml"]
