FROM ubuntu:22.04 as builder

WORKDIR /root

RUN env DEBIAN_FRONTEND=noninteractive apt-get -y update && apt-get install -y --no-install-recommends autoconf automake build-essential ca-certificates wget unzip git make cmake pkg-config libpcap-dev autoconf libtool
RUN git clone https://github.com/utoni/nDPId.git
RUN cd nDPId && mkdir -p build && cd build && cmake .. -DBUILD_NDPI=ON && make

FROM ubuntu:22.04
USER root
WORKDIR /

COPY --from=builder /root/nDPId/build/nDPId /usr/sbin/nDPId
COPY --from=builder /root/nDPId/build/nDPIsrvd /usr/bin/nDPIsrvd

RUN env DEBIAN_FRONTEND=noninteractive apt-get -y update && apt-get install -y --no-install-recommends libpcap-dev

USER nobody
RUN /usr/bin/nDPIsrvd -h || { RC=$?; test ${RC} -eq 1; }
RUN /usr/sbin/nDPId -h || { RC=$?; test ${RC} -eq 1; }
