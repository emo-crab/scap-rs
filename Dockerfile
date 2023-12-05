FROM rust:slim-buster AS builder

WORKDIR /prod
#为了命中docker构建缓存，先拷贝这几个文件进去
COPY .cargo .cargo
RUN rustup target add wasm32-unknown-unknown
RUN cargo install --locked trunk
RUN cargo install --locked wasm-bindgen-cli
RUN apt-get update
RUN apt-get install -y --no-install-recommends gcc-multilib xz-utils liblz4-tool libc6-dev libssl-dev default-libmysqlclient-dev pkg-config musl-tools patchelf build-essential zlib1g-dev ca-certificates
COPY Cargo.toml Cargo.toml
COPY Trunk.toml Trunk.toml
COPY cpe cpe
COPY cve cve
COPY cvss cvss
COPY cwe cwe
COPY nvd-yew nvd-yew
COPY nvd-api nvd-api
COPY nvd-server nvd-server
COPY helper helper
COPY src src
RUN cargo build --release
RUN trunk build --release

# Use any runner as you want
# But beware that some images have old glibc which makes rust unhappy
FROM debian:latest AS runner
WORKDIR /prod
ENV TZ=Asia/Shanghai
RUN apt-get update
RUN apt-get install -y --no-install-recommends libssl-dev default-libmysqlclient-dev ca-certificates
COPY --from=builder /prod/target/release/nvd-server /prod
COPY --from=builder /prod/dist /prod/dist
EXPOSE 8888
CMD [ "/prod/nvd-server" ]