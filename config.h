#ifndef CONFIG_H
#define CONFIG_H 1

/* macros shared across multiple executables */
#define COLLECTOR_UNIX_SOCKET "/tmp/ndpid-collector.sock"
#define DISTRIBUTOR_HOST "127.0.0.1"
#define DISTRIBUTOR_PORT 7000

#define NETWORK_BUFFER_MAX_SIZE 8448 /* 8192 + 256 */

/* nDPId default config options */
#define nDPId_PIDFILE "/tmp/ndpid.pid"
#define nDPId_MAX_FLOWS_PER_THREAD 4096
#define nDPId_MAX_IDLE_FLOWS_PER_THREAD 512
#define nDPId_TICK_RESOLUTION 1000
#define nDPId_MAX_READER_THREADS 8
#define nDPId_IDLE_SCAN_PERIOD 10000 /* 10 sec */
#define nDPId_IDLE_TIME 600000 /* 600 sec */
#define nDPId_POST_END_FLOW_TIME 60000 /* 60 sec */
#define nDPId_INITIAL_THREAD_HASH 0x03dd018b
#define nDPId_PACKETS_PER_FLOW_TO_SEND 15

/* nDPIsrvd default config options */
#define nDPIsrvd_PIDFILE "/tmp/ndpisrvd.pid"
#define nDPIsrvd_JSON_BYTES 4

#endif
