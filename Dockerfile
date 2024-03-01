FROM rust:latest AS server

WORKDIR /prod
#为了命中docker构建缓存，先拷贝这几个文件进去
RUN apt-get update &&\
    apt-get install -y --no-install-recommends gcc-multilib xz-utils liblz4-tool libc6-dev libssl-dev default-libmysqlclient-dev pkg-config musl-tools patchelf build-essential zlib1g-dev ca-certificates
COPY .cargo .cargo
COPY nvd-server/Cargo.toml Cargo.toml
COPY nvd-model/ /nvd-model
RUN cargo fetch
COPY nvd-server/src src
RUN cargo build --release --all-features

FROM rust:slim-buster AS yew

WORKDIR /prod
#为了命中docker构建缓存，先拷贝这几个文件进去
COPY .cargo .cargo
RUN rustup target add wasm32-unknown-unknown
RUN cargo install --locked trunk
RUN cargo install --locked wasm-bindgen-cli
# 其他模块需要工作区配置
COPY nvd-yew/Cargo.toml Cargo.toml
COPY nvd-model/ /nvd-model
RUN cargo fetch
COPY nvd-yew/index.html index.html
COPY nvd-yew/Trunk.toml Trunk.toml
COPY nvd-yew/static static
COPY nvd-yew/src src
COPY nvd-yew/i18n.json i18n.json
RUN trunk build --release --no-sri

# Use any runner as you want
# But beware that some images have old glibc which makes rust unhappy
FROM debian:latest AS runner
WORKDIR /prod
ENV TZ=Asia/Shanghai
RUN apt-get update &&\
    apt-get install -y --no-install-recommends libssl-dev default-libmysqlclient-dev ca-certificates cron curl
COPY --from=server /prod/target/release/nvd-server /prod
COPY --from=yew /prod/dist /prod/dist
EXPOSE 8888
CMD [ "/prod/nvd-server" ]