# FROM rust:1.61 AS builder
# COPY . .
# RUN cargo build --release

FROM ubuntu:21.10
COPY bin/traffic-billing  /usr/local/bin/
ADD start.sh /usr/local/bin/

ENTRYPOINT ["bash","/usr/local/bin/start.sh"]