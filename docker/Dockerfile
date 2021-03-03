FROM rust:1.50 as build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get -y install ca-certificates libssl-dev cmake && rm -rf /var/lib/apt/lists/*

COPY ./ ./

RUN cargo build --release

RUN mkdir -p /build-out

RUN cp target/release/rewind /build-out/

FROM ubuntu:focal

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get -y install ca-certificates libssl-dev && rm -rf /var/lib/apt/lists/*

COPY --from=build /build-out/rewind /

CMD /rewind