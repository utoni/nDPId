# abstract

nDPId is a set of daemons and tools to capture, process and classify network flows.
It's only dependencies (besides a half-way modern c library and POSIX threads) are libnDPI (>= 3.6.0 or current github dev branch) and libpcap.

The core daemon nDPId uses pthread but does use mutexes for performance reasons.
Instead synchronization is achieved by a packet distribution mechanism.
To balance all workload to all threads (more or less) equally a hash value is calculated using the 5-tuple.
This value serves as unique identifier for the processing thread. Multithreaded packet processing has to be flow-stable.

nDPId uses libnDPI's JSON serialization to produce meaningful JSON output which it then sends to the nDPIsrvd for distribution.
High level applications can connect to nDPIsrvd to get the latest flow/packet events from nDPId.

Unfortunately nDPIsrvd does currently not support any encryption/authentication for TCP connections.

# architecture

This project uses some kind of microservice architecture.

```text
_______________________                                         __________________________
|     "producer"      |                                         |       "consumer"       |
|---------------------|      _____________________________      |------------------------|
|                     |      |        nDPIsrvd           |      |                        |
| nDPId --- Thread 1 >| ---> |>           |             <| <--- |< example/c-json-stdout |
| (eth0) `- Thread 2 >| ---> |> collector | distributor <| <--- |________________________|
|        `- Thread N >| ---> |>    >>> forward >>>      <| <--- |                        |
|_____________________|  ^   |____________|______________|   ^  |< example/py-flow-info  |
|                     |  |                                   |  |________________________|
| nDPId --- Thread 1 >|  `- connect to UNIX socket           |  |                        |
| (eth1) `- Thread 2 >|  `- sends serialized data            |  |< example/...           |
|        `- Thread N >|                                      |  |________________________|
|_____________________|                                      |                            
                                                             `- connect to UNIX/TCP socket
                                                             `- receives serialized data  
```

It doesn't use a producer/consumer design pattern, so the wording is not precise.

# JSON TCP protocol

All JSON strings sent need to be in the following format:
```text
[5-digit-number][JSON string]
```

## Example:

```text
00015{"key":"value"}
```
where `00015` describes the length of a **complete** JSON string.

TODO: Describe data format via JSON schema.

# build (CMake)

```shell
mkdir build
cd build
cmake ..
```

or

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

Or if this is all too much for you, let CMake do it for you:

```shell
git submodule update --init
mkdir build
cd build
cmake .. -DBUILD_NDPI=ON
```

# run

Generate a nDPId compatible JSON dump:
```shell
./nDPId-test [path-to-a-PCAP-file]
```

Daemons:
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

You may want to run some integration tests using pcap files from nDPI:

`./test/run_tests.sh /path/to/libnDPI/root/directory`

e.g.:

`./test/run_tests.sh ${HOME}/git/nDPI`


For out-of-source builds, you'll need to specify a path to nDPId-test as well with:

`/test/run_tests.sh /path/to/libnDPI/root/directory /path/to/nDPId-test-executable`

For in-source builds and if CMake was configured with BUILD_NDPI=ON you can just type:

`/test/run_tests.sh`
