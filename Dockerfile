FROM ubuntu:22.04 AS builder

WORKDIR /root
RUN apt-get -y update \
    && apt-get install -y --no-install-recommends \
    autoconf automake build-essential ca-certificates cmake git \
    libpcap-dev libtool make pkg-config unzip wget \
    && apt-get clean \
    && git clone https://github.com/utoni/nDPId.git

WORKDIR /root/nDPId
RUN cmake -S . -B build -DBUILD_NDPI=ON \
    && cmake --build build --verbose

FROM ubuntu:22.04
USER root
WORKDIR /

COPY --from=builder /root/nDPId/build/nDPId /usr/sbin/nDPId
COPY --from=builder /root/nDPId/build/nDPIsrvd /usr/bin/nDPIsrvd

RUN apt-get -y update \
    && apt-get install -y --no-install-recommends libpcap-dev \
    && apt-get clean

USER nobody
RUN /usr/bin/nDPIsrvd -h || { RC=$?; test ${RC} -eq 1; }; \
    /usr/sbin/nDPId -h || { RC=$?; test ${RC} -eq 1; }
