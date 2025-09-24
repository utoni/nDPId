FROM ubuntu:22.04 AS builder-ubuntu-2204

WORKDIR /root
RUN apt-get -y update \
    && apt-get install -y --no-install-recommends \
    autoconf automake build-essential ca-certificates cmake git \
    libpcap-dev libcurl4-openssl-dev libdbus-1-dev libtool make pkg-config unzip wget \
    && apt-get clean \
    && git clone https://github.com/utoni/nDPId.git

WORKDIR /root/nDPId
RUN cmake -S . -B build -DBUILD_NDPI=ON -DBUILD_EXAMPLES=ON \
    -DENABLE_DBUS=ON -DENABLE_CURL=ON \
    && cmake --build build --verbose

FROM ubuntu:22.04
USER root
WORKDIR /

COPY --from=builder-ubuntu-2204 /root/nDPId/build/nDPId /usr/sbin/nDPId
COPY --from=builder-ubuntu-2204 /root/nDPId/build/nDPIsrvd /usr/bin/nDPIsrvd
COPY --from=builder-ubuntu-2204 /root/nDPId/build/nDPId-test /usr/bin/nDPId-test
COPY --from=builder-ubuntu-2204 /root/nDPId/build/nDPIsrvd-collectd /usr/bin/nDPIsrvd-collectd
COPY --from=builder-ubuntu-2204 /root/nDPId/build/nDPIsrvd-captured /usr/bin/nDPIsrvd-captured
COPY --from=builder-ubuntu-2204 /root/nDPId/build/nDPIsrvd-analysed /usr/bin/nDPIsrvd-anaylsed
COPY --from=builder-ubuntu-2204 /root/nDPId/build/nDPIsrvd-analysed /usr/bin/nDPIsrvd-anaylsed
COPY --from=builder-ubuntu-2204 /root/nDPId/build/nDPIsrvd-notifyd /usr/bin/nDPIsrvd-notifyd
COPY --from=builder-ubuntu-2204 /root/nDPId/build/nDPIsrvd-influxd /usr/bin/nDPIsrvd-influxd
COPY --from=builder-ubuntu-2204 /root/nDPId/build/nDPIsrvd-simple /usr/bin/nDPIsrvd-simple

RUN apt-get -y update \
    && apt-get install -y --no-install-recommends libpcap-dev \
    && apt-get clean

USER nobody
RUN /usr/bin/nDPIsrvd -h || { RC=$?; test ${RC} -eq 1; }; \
    /usr/sbin/nDPId -h || { RC=$?; test ${RC} -eq 1; }

FROM archlinux:base-devel AS builder-archlinux

WORKDIR /root
RUN pacman --noconfirm -Sy cmake git unzip wget && mkdir /build && chown nobody /build && cd /build \
    && runuser -u nobody git clone https://github.com/utoni/nDPId.git

WORKDIR /build/nDPId/packages/archlinux
RUN runuser -u nobody makepkg
