[![Build](https://github.com/utoni/nDPId/actions/workflows/build.yml/badge.svg)](https://github.com/utoni/nDPId/actions/workflows/build.yml)
[![Gitlab-CI](https://gitlab.com/utoni/nDPId/badges/main/pipeline.svg)](https://gitlab.com/utoni/nDPId/-/pipelines)
[![Circle-CI](https://circleci.com/gh/utoni/nDPId.svg?style=shield "Circle-CI")](https://app.circleci.com/pipelines/github/utoni/nDPId)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=lnslbrty_nDPId&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=lnslbrty_nDPId)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=lnslbrty_nDPId&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=lnslbrty_nDPId)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=lnslbrty_nDPId&metric=bugs)](https://sonarcloud.io/summary/new_code?id=lnslbrty_nDPId)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=lnslbrty_nDPId&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=lnslbrty_nDPId)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=lnslbrty_nDPId&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=lnslbrty_nDPId)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=lnslbrty_nDPId&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=lnslbrty_nDPId)
![Docker Automated build](https://img.shields.io/docker/automated/utoni/ndpid)

# References

[ntop Webinar 2022](https://www.ntop.org/webinar/ntop-webinar-on-dec-14th-community-meeting-and-future-plans/)

# Disclaimer

Please respect&protect the privacy of others.

The purpose of this software is not to spy on others, but to detect network anomalies and malicious traffic.

# Abstract

nDPId is a set of daemons and tools to capture, process and classify network traffic.
It's minimal dependencies (besides a half-way modern c library and POSIX threads) are libnDPI (**>**4.6.0 or current github dev branch) and libpcap.

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
    * apply a buffering logic to received data;
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


# Events

`nDPId` generates JSON strings whereas each string is assigned to a certain event.
Those events specify the contents (key-value-pairs) of the JSON string.
They are divided into four categories, each with a number of subevents.

## Error Events
They are 17 distinct events, indicating that layer2 or layer3 packet processing failed or not enough flow memory available:

1. Unknown datalink layer packet
2. Unknown L3 protocol
3. Unsupported datalink layer
4. Packet too short
5. Unknown packet type
6. Packet header invalid
7. IP4 packet too short
8. Packet smaller than IP4 header:
9. nDPI IPv4/L4 payload detection failed
10. IP6 packet too short
11. Packet smaller than IP6 header
12. nDPI IPv6/L4 payload detection failed
13. TCP packet smaller than expected
14. UDP packet smaller than expected
15. Captured packet size is smaller than expected packet size
16. Max flows to track reached
17. Flow memory allocation failed

Detailed JSON-schema is available [here](schema/error_event_schema.json)

## Daemon Events
There are 4 distinct events indicating startup/shutdown or status events as well as a reconnect event if there was a previous connection failure (collector):

1. init: `nDPId` startup
2. reconnect: (UNIX) socket connection lost previously and was established again
3. shutdown: `nDPId` terminates gracefully
4. status: statistics about the daemon itself e.g. memory consumption, zLib compressions (if enabled)

Detailed JSON-schema is available [here](schema/daemon_event_schema.json)


## Packet Events
There are 2 events containing base64 encoded packet payload either belonging to a flow or not:

1. packet: does not belong to any flow
2. packet-flow: does belong to a flow e.g. TCP/UDP or ICMP

Detailed JSON-schema is available [here](schema/packet_event_schema.json)

## Flow Events
There are 9 distinct events related to a flow:

1. new: a new TCP/UDP/ICMP flow seen which will be tracked
2. end: a TCP connections terminates
3. idle: a flow timed out, because there was no packet on the wire for a certain amount of time
4. update: inform nDPIsrvd or other apps about a long-lasting flow, whose detection was finished a long time ago but is still active
5. analyse: provide some information about extracted features of a flow (Experimental; disabled per default, enable with `-A`)
6. guessed: `libnDPI` was not able to reliable detect a layer7 protocol and falls back to IP/Port based detection
7. detected: `libnDPI` sucessfully detected a layer7 protocol
8. detection-update: `libnDPI` dissected more layer7 protocol data (after detection already done)
9. not-detected: neither detected nor guessed

Detailed JSON-schema is available [here](schema/flow_event_schema.json). Also, a graphical representation of *Flow Events* timeline is available [here](schema/flow_events_diagram.png). 

# Flow States

A flow can have three different states while it is been tracked by `nDPId`.

1. skipped: the flow will be tracked, but no detection will happen to safe memory, see command line argument `-I` and `-E`
2. finished: detection finished and the memory used for the detection is free'd
3. info: detection is in progress and all flow memory required for `libnDPI` is allocated (this state consumes most memory)

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

Such a UNIX-socket can be provided by both the included `nDPIsrvd` daemon, or, if you simply need a quick check, with the [ncat](https://nmap.org/book/ncat-man.html) utility, with a simple `ncat -U /tmp/listen.sock -l -k`. Remember that OpenBSD `netcat` is not able to handle multiple connections reliably.

Once the socket is ready, you can run `nDPId` capturing and analyzing your own traffic, with something similar to:

Of course, both `ncat` and `nDPId` need to point to the same UNIX-socket (`nDPId` provides the `-c` option, exactly for this. As a default, `nDPId` refer to `/tmp/ndpid-collector.sock`, and the same default-path is also used by `nDPIsrvd` as for the incoming socket).

You also need to provide `nDPId` some real-traffic. You can capture your own traffic, with something similar to:

```shell
socat -u UNIX-Listen:/tmp/listen.sock,fork - # does the same as `ncat`
sudo chown nobody:nobody /tmp/listen.sock # default `nDPId` user/group, see `-u` and `-g`
sudo ./nDPId -c /tmp/listen.sock -l
```

`nDPId` supports also UDP collector endpoints:

```shell
nc -d -u 127.0.0.1 7000 -l -k
sudo ./nDPId -c 127.0.0.1:7000 -l
```

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

# nDPId tuning

It is possible to change `nDPId` internals w/o recompiling by using `-o subopt=value`.
But be careful: changing the default values may render `nDPId` useless and is not well tested.

Suboptions for `-o`:

Format: `subopt` (unit, comment): description

 * `max-flows-per-thread` (N, caution advised): affects max. memory usage
 * `max-idle-flows-per-thread` (N, safe): max. allowed idle flows which memory get's free'd after `flow-scan-interval`
 * `max-reader-threads` (N, safe): amount of packet processing threads, every thread can have a max. of `max-flows-per-thread` flows
 * `daemon-status-interval` (ms, safe): specifies how often daemon event `status` will be generated
 * `compression-scan-interval` (ms, untested): specifies how often `nDPId` should scan for inactive flows ready for compression
 * `compression-flow-inactivity` (ms, untested): the earliest period of time that must elapse before `nDPId` may consider compressing a flow that did neither send nor receive any data
 * `flow-scan-interval` (ms, safe): min. amount of time after which `nDPId` will scan for idle or long-lasting flows
 * `generic-max-idle-time` (ms, untested): time after which a non TCP/UDP/ICMP flow will time out
 * `icmp-max-idle-time` (ms, untested): time after which an ICMP flow will time out
 * `udp-max-idle-time` (ms, caution advised): time after which an UDP flow will time out
 * `tcp-max-idle-time` (ms, caution advised): time after which a TCP flow will time out
 * `tcp-max-post-end-flow-time` (ms, caution advised): a TCP flow that received a FIN or RST will wait that amount of time before flow tracking will be stopped and the flow memory free'd
 * `max-packets-per-flow-to-send` (N, safe): max. `packet-flow` events that will be generated for the first N packets of each flow
 * `max-packets-per-flow-to-process` (N, caution advised): max. packets that will be processed by `libnDPI`
 * `max-packets-per-flow-to-analyze` (N, safe): max. packets to analyze before sending an `analyse` event, requires `-A`

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

# Contributors

Special thanks to Damiano Verzulli ([@verzulli](https://github.com/verzulli)) from [GARRLab](https://www.garrlab.it) for providing server and test infrastructure.
