# cofferak container image: the daemon and the CLI, nothing else.
#
# Build from the repository root:
#   docker build -f deployment/docker/Dockerfile -t cofferak:dev .
#
# The image is built with the `gcp-kms` feature, so the host key can be
# sealed with Google Cloud KMS (ADR 0020). It runs as an unprivileged user
# on a distroless base: no shell, no package manager.

FROM rust:1-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake clang \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# rust-toolchain.toml pins the compiler, --locked pins every dependency.
RUN cargo build --release --locked --features gcp-kms -p cofferak-cli -p cofferakd

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/cofferakd /src/target/release/cofferak /usr/local/bin/
ENV COFFERAK_DATA_DIR=/var/lib/cofferak/data \
    COFFERAK_SOCKET=/run/cofferak/cofferakd.sock
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/cofferakd"]
