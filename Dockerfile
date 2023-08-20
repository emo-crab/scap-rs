# -*- mode: dockerfile -*-
#
# An example Dockerfile showing how to build a Rust executable using this
# image, and deploy it with a tiny Alpine Linux container.

# You can override this `--build-arg BASE_IMAGE=...` to use different
# version of Rust or OpenSSL.
ARG BASE_IMAGE=ekidd/rust-musl-builder:latest

# Our first FROM statement declares the build environment.
FROM ${BASE_IMAGE} AS builder

RUN sudo chown -R rust:rust /opt/rust/ /home/rust/src/ /home/rust/.cargo/

# Add our source code.
COPY ./ /home/rust/src/
COPY ./docker/config /home/rust/.cargo/config.bak
RUN cat /home/rust/.cargo/config.bak |head -n -2 >/home/rust/.cargo/config


RUN rustup target add x86_64-unknown-linux-musl
RUN sudo apt-get update
RUN sudo apt-get install -y gcc-multilib xz-utils liblz4-tool libc6-dev libssl-dev musl-tools pkg-config libmysqlclient-dev
RUN sudo apt-get install -y gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf
# Build our application.
RUN cargo build --bin=cpe_to_db --release --target x86_64-unknown-linux-musl --manifest-path tools/Cargo.toml

# Now, we need to build our _real_ Docker container, copying in `using-diesel`.
FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /home/rust/src/target/x86_64-unknown-linux-musl/release/cpe_to_db /usr/local/bin/
CMD /usr/local/bin/cpe_to_db