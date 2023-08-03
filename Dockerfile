FROM ubuntu:22.10 as builder

WORKDIR /root
RUN env DEBIAN_FRONTEND=noninteractive apt-get -y update && apt-get install -y wget unzip git make cmake pkg-config libpcap-dev autoconf libtool

RUN git clone https://github.com/utoni/nDPId.git
RUN cd nDPId && mkdir -p build && cd build && cmake .. -DBUILD_NDPI=ON && make

FROM ubuntu:22.10
WORKDIR /root
RUN apt-get -y update && apt-get -y install libpcap-dev

COPY --from=builder /root/nDPId/libnDPI/ /root/
COPY --from=builder /root/nDPId/build/nDPIsrvd /root/nDPId/build/nDPId /root/
