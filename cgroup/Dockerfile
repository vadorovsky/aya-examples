FROM rustlang/rust:nightly-bullseye as builder

RUN apt-get update \
    && apt-get install -y \
    musl-dev
RUN rustup component add rust-src \
    && rustup target add x86_64-unknown-linux-musl \
    && cargo install bpf-linker
COPY . /src
WORKDIR /src
RUN --mount=type=cache,target=/.root/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo xtask build-ebpf --release \
    && cargo build --release --target=x86_64-unknown-linux-musl \
    && cp target/x86_64-unknown-linux-musl/release/cgroup /cgroup

FROM alpine:3.15

COPY --from=builder /cgroup /usr/sbin/cgroup
ENTRYPOINT [ "/usr/sbin/cgroup" ]
