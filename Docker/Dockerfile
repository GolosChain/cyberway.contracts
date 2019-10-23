ARG buildtype=stable
FROM cyberway/cyberway:$buildtype as cyberway
FROM cyberway/cyberway.cdt:$buildtype as cdt

FROM cyberway/builder:$buildtype as builder
COPY --from=cdt /opt/cyberway.cdt /opt/cyberway.cdt
COPY --from=cyberway /opt/cyberway /opt/cyberway

ARG branch=master
ADD https://api.github.com/repos/cyberway/cyberway.contracts/git/refs/heads/$branch /etc/version.json
RUN git clone -b $branch https://github.com/cyberway/cyberway.contracts.git --recursive

RUN cd cyberway.contracts \
    && echo "$branch:$(git rev-parse HEAD)" > version \
    && cmake -H. -B"build" \
        -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/opt/cyberway.contracts/ \
        -Dcyberway.cdt_DIR=/opt/cyberway.cdt/lib/cmake/cyberway.cdt \
        -DEOSIO_ROOT=/opt/cyberway \
    && cmake --build build --target install


FROM ubuntu:18.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y install openssl ca-certificates python3 python3-numpy python3-bson libusb-1.0-0-dev libcurl4-gnutls-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /cyberway.contracts/version /opt/cyberway.contracts/version
COPY --from=builder /opt/cyberway.contracts/ /opt/cyberway.contracts/
COPY --from=builder /cyberway.contracts/build/tests/unit_test /opt/cyberway.contracts/unit_test
COPY --from=builder /cyberway.contracts/tests/test_contracts /opt/cyberway.contracts/test_contracts

COPY --from=builder /cyberway.contracts/scripts/bios-boot-sequence /opt/cyberway.contracts/scripts/bios-boot-sequence

COPY --from=builder /usr/local/lib/libbson-1.0.so.0.0.0 /usr/local/lib/
COPY --from=cyberway /opt/cyberway/bin/cleos /opt/cyberway/bin/cleos
COPY --from=cyberway /opt/cyberway/bin/keosd /opt/cyberway/bin/keosd
COPY --from=cyberway /opt/cyberway/bin/create-genesis /opt/cyberway/bin/create-genesis

RUN ldconfig && ln -s ../cyberway.contracts /opt/cyberway.contracts

ENV CYBERWAY_TEST_CONTRACTS /opt/cyberway.contracts/test_contracts/
ENV CYBERWAY_CONTRACTS /opt/cyberway.contracts/
