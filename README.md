[![Build](https://github.com/utoni/nDPId/actions/workflows/build.yml/badge.svg)](https://github.com/utoni/nDPId/actions/workflows/build.yml)
[![Gitlab-CI](https://gitlab.com/utoni/nDPId/badges/master/pipeline.svg)](https://gitlab.com/utoni/nDPId/-/pipelines)

# Abstract

nDPId is a set of daemons and tools to capture, process and classify network traffic.
It's minimal dependencies (besides a half-way modern c library and POSIX threads) are libnDPI (>= 4.4.0 or current github dev branch) and libpcap.

The daemon `nDPId` is capable of multithreading for packet processing, but w/o mutexes for performance reasons.
Instead synchronization is achieved by a packet distribution mechanism.
To balance all workload to all threads (more or less) equally a unique identifier represented as hash value is calculated using a 3-tuple consisting of IPv4/IPv6 src/dst address, IP header value of the layer4 protocol and (for TCP/UDP) src/dst port. Other protocols e.g. ICMP/ICMPv6 are lacking relevance for DPI, thus nDPId does not distinguish between different ICMP/ICMPv6 flows coming from the same host. Saves memory and performance, but might change in the future.

`nDPId` uses libnDPI's JSON serialization interface to generate a JSON strings for each event it receive from the library and which it then sends out to a UNIX-socket (default: /tmp/ndpid-collector.sock ). From such a socket, `nDPIsrvd` (or other custom applications) can retrieve incoming JSON-messages and further proceed working/distributing messages to higher-level applications.

Unfortunately `nDPIsrvd` does currently not support any encryption/authentication for TCP connections (TODO!).

# Architecture

This project uses some kind of microservice architecture.

```text
                connect to UNIX socket [1]        connect to UNIX/TCP socket [2]                
_______________________   |                                 |   __________________________
|     "producer"      |___|                                 |___|       "consumer"       |
|---------------------|      _____________________________      |------------------------|
|                     |      |        nDPIsrvd           |      |                        |
| nDPId --- Thread 1 >| ---> |>           |             <| ---> |< example/c-json-stdout |
| (eth0) `- Thread 2 >| ---> |> collector | distributor <| ---> |________________________|
|        `- Thread N >| ---> |>    >>> forward >>>      <| ---> |                        |
|_____________________|  ^   |____________|______________|   ^  |< example/py-flow-info  |
|                     |  |                                   |  |________________________|
| nDPId --- Thread 1 >|  `- send serialized data [1]         |  |                        |
| (eth1) `- Thread 2 >|                                      |  |< example/...           |
|        `- Thread N >|         receive serialized data [2] -'  |________________________|
|_____________________|                                                                   

```
where:
* `nDPId` capture traffic, extract traffic data (with libnDPI) and send a JSON-serialized output stream to an already existing UNIX-socket;
* `nDPIsrvd`:
    * create and manage an "incoming" UNIX-socket (ref [1] above), to fetch data from a local `nDPId`;
    * apply a filtering logic to received data to select "flow_event_id" related JSONs;
    * create and manage an "outgoing" UNIX or TCP socket (ref [2] above) to relay matched events
    to connected clients
* `consumers` are common/custom applications being able to receive selected flows/events, via both UNIX-socket or TCP-socket.


# JSON stream format

JSON messages streamed by both `nDPId` and `nDPIsrvd` are presented with:

* a 5-digit-number describing (as decimal number) of the **entire** JSON string including the newline `\n` at the end;
* the JSON messages

```text
[5-digit-number][JSON string]
```

as with the following example:

```text
01223{"flow_event_id":7,"flow_event_name":"detection-update","thread_id":12,"packet_id":307,"source":"wlan0",[...]}
00458{"packet_event_id":2,"packet_event_name":"packet-flow","thread_id":11,"packet_id":324,"source":"wlan0",[...]]}
00572{"flow_event_id":1,"flow_event_name":"new","thread_id":11,"packet_id":324,"source":"wlan0",[...]}
```

The full stream of `nDPId` generated JSON-events can be retrieved directly from `nDPId`, without relying on `nDPIsrvd`, by providing a properly managed UNIX-socket.

Technical details about JSON-messages format can be obtained from related `.schema` file included in the `schema` directory


# Build (CMake)

`nDPId` build system is based on [CMake](https://cmake.org/)

```shell
git clone https://github.com/utoni/nDPId.git
[...]
cd ndpid
mkdir build
cd build
cmake ..
[...]
make
```

see below for a full/test live-session

![](examples/ndpid_install_and_run.gif)

Based on your building environment and/or desiderata, you could need:

```shell
mkdir build
cd build
ccmake ..
```

or to build with a staticially linked libnDPI:

```shell
mkdir build
cd build
cmake .. -DSTATIC_LIBNDPI_INSTALLDIR=[path/to/your/libnDPI/installdir]
```

If you're using the latter one, make sure that you've configured libnDPI with `./configure --prefix=[path/to/your/libnDPI/installdir]`
and do not forget to set the all necessary CMake variables to link against shared libraries used by your nDPI build.

e.g.:

```shell
mkdir build
cd build
cmake .. -DSTATIC_LIBNDPI_INSTALLDIR=[path/to/your/libnDPI/installdir] -DNDPI_WITH_GCRYPT=ON -DNDPI_WITH_PCRE=OFF -DNDPI_WITH_MAXMINDDB=OFF
```

Or let a shell script do the work for you:

```shell
mkdir build
cd build
cmake .. -DBUILD_NDPI=ON
```

The CMake cache variable `-DBUILD_NDPI=ON` builds a version of `libnDPI` residing as git submodule in this repository.

# run

As mentioned above, in order to run `nDPId` a UNIX-socket need to be provided in order to stream our related JSON-data.

Such a UNIX-socket can be provided by both the included `nDPIsrvd` daemon, or, if you simply need a quick check, with the [ncat](https://nmap.org/book/ncat-man.html) utility, with a simple `ncat -U /tmp/listen.sock -l -k`

Once the socket is ready, you can run `nDPId` capturing and analyzing your own traffic, with something similar to:

Of course, both `ncat` and `nDPId` need to point to the same UNIX-socket (`nDPId` provides the `-c` option, exactly for this. As a default, `nDPId` refer to `/tmp/ndpid-collector.sock`, and the same default-path is also used by `nDPIsrvd` as for the incoming socket)

You also need to provide `nDPId` some real-traffic. You can capture your own traffic, with something similar to:

    ./nDPId -c /tmp/listen.sock -i wlan0 -l

or you can generate a nDPId-compatible JSON dump with:

```shell
./nDPId-test [path-to-a-PCAP-file]
```

You can also automatically fire both `nDPId` and `nDPIsrvd` automatically, with:

Daemons:
```shell
make -C [path-to-a-build-dir] daemon
```

Or you can proceed with a manual approach with:

```shell
./nDPIsrvd -d
sudo ./nDPId -d
```

or for a usage printout:
```shell
./nDPIsrvd -h
./nDPId -h
```

And why not a flow-info example?
```shell
./examples/py-flow-info/flow-info.py
```

or
```shell
./nDPIsrvd-json-dump
```

or anything below `./examples`.

# test

The recommended way to run integration / diff tests:

```shell
mkdir build
cd build
cmake .. -DBUILD_NDPI=ON
make nDPId-test test
```

Alternatively you can run some integration tests manually:

`./test/run_tests.sh [/path/to/libnDPI/root/directory] [/path/to/nDPId-test]`

e.g.:

`./test/run_tests.sh [${HOME}/git/nDPI] [${HOME}/git/nDPId/build/nDPId-test]`

Remember that all test results are tied to a specific libnDPI commit hash
as part of the `git submodule`. Using `test/run_tests.sh` for other commit hashes
will most likely result in PCAP diff's.

Why not use `examples/py-flow-dashboard/flow-dash.py` to visualize nDPId's output.
