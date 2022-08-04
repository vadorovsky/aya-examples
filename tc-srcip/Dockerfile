FROM rustlang/rust:nightly-bullseye-slim AS build

COPY . /src
WORKDIR /src
RUN rustup component add rust-src
RUN cargo install bpf-linker
RUN cargo xtask build-ebpf --release \
    && cargo build --release

FROM debian:bullseye-slim

COPY --from=build /src/target/release/tc-srcip /usr/bin/tc-srcip
ENTRYPOINT [ "/usr/bin/tc-srcip" ]
