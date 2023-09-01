FROM rust:slim-bullseye AS buildstage
WORKDIR /build
ENV PROTOC_NO_VENDOR 1
RUN rustup component add rustfmt && \
    apt-get update && \
    apt-get install -y --no-install-recommends librocksdb-dev libsnappy-dev liblz4-dev libzstd-dev clang wget protobuf-compiler && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
COPY . /build/
RUN cargo build --release

FROM debian:bullseye-slim
# get the latest CA certs
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && update-ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m chain
USER chain
COPY --from=buildstage /build/target/release/cloud_kms /usr/bin/
COPY --from=ghcr.io/grpc-ecosystem/grpc-health-probe:v0.4.19 /ko-app/grpc-health-probe /usr/bin/
CMD ["cloud_kms"]
