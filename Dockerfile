FROM rust:1.83.0-alpine3.20 AS builder

RUN set -ex \
        \
    && apk update \
    && apk upgrade \
    && apk add --update --no-cache musl-dev openssl-dev perl make lld \
    && rustup target add x86_64-unknown-linux-musl

WORKDIR /opt/app

COPY Cargo.toml /opt/app/Cargo.toml
COPY envs/ /opt/app/envs/
COPY envs-cli/ /opt/app/envs-cli/

RUN mkdir -p /opt/app/src && echo "fn main() {}" > /opt/app/src/main.rs

RUN --mount=type=cache,target=/usr/local/cargo/registry true \
    set -ex \
        \
    && cargo build --release --target=x86_64-unknown-linux-musl

RUN rm -f /opt/app/src/main.rs

RUN set -ex \
        \
    && export RUSTFLAGS="-C linker=lld" \
    && cargo build --release --target=x86_64-unknown-linux-musl


FROM scratch AS runtime

COPY --from=builder /opt/app/target/x86_64-unknown-linux-musl/release/envs /usr/local/bin/envs

ENTRYPOINT ["/usr/local/bin/envs"]
