FROM rust:slim-bullseye AS buildstage
WORKDIR /build
ENV PROTOC_NO_VENDOR 1
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
COPY --from=buildstage /build/target/release/kms /usr/bin/
CMD ["kms"]
