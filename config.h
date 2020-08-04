#ifndef CONFIG_H
#define CONFIG_H 1

/* macros shared across multiple executables */
#define COLLECTOR_UNIX_SOCKET "/tmp/ndpid-collector.sock"
#define DISTRIBUTOR_HOST "127.0.0.1"
#define DISTRIBUTOR_PORT 7000

#define NETWORK_BUFFER_MAX_SIZE 8192

/* nDPId default config options */
#define nDPId_MAX_FLOW_ROOTS_PER_THREAD 2048
#define nDPId_MAX_IDLE_FLOWS_PER_THREAD 64
#define nDPId_TICK_RESOLUTION 1000
#define nDPId_MAX_READER_THREADS 4
#define nDPId_IDLE_SCAN_PERIOD 10000 /* msec */
#define nDPId_MAX_IDLE_TIME 300000   /* msec */
#define nDPId_INITIAL_THREAD_HASH 0x03dd018b
#define nDPId_MAX_PACKETS_PER_FLOW_TO_SEND 15

#endif
