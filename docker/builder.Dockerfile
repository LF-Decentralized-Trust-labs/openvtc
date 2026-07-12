FROM rust:1

ENV DEBIAN_FRONTEND=noninteractive

RUN \
    addgroup --system messagebus &&\
    apt update &&\
    apt install -y libdbus-1-dev pkg-config libpcsclite-dev
