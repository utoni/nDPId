#ifndef CONFIG_H
#define CONFIG_H 1

/* macros shared across multiple executables */
#define COLLECTOR_UNIX_SOCKET "/tmp/ndpid-collector.sock"
#define DISTRIBUTOR_UNIX_SOCKET "/tmp/ndpid-distributor.sock"
#define DISTRIBUTOR_HOST "127.0.0.1"
#define DISTRIBUTOR_PORT 7000u

/*
 * NOTE: Buffer size needs to keep in sync with other implementations
 *       e.g. dependencies/nDPIsrvd.py
 */
#define NETWORK_BUFFER_MAX_SIZE 16384u /* 8192 + 8192 */
#define NETWORK_BUFFER_LENGTH_DIGITS 5u
#define NETWORK_BUFFER_LENGTH_DIGITS_STR "5"

/* nDPId default config options */
#define nDPId_PIDFILE "/tmp/ndpid.pid"
#define nDPId_MAX_FLOWS_PER_THREAD 4096u
#define nDPId_MAX_IDLE_FLOWS_PER_THREAD (nDPId_MAX_FLOWS_PER_THREAD / 32u)
#define nDPId_TICK_RESOLUTION 1000u
#define nDPId_MAX_READER_THREADS 32u
#define nDPId_DAEMON_STATUS_INTERVAL 600000u /* 600 sec */
#define nDPId_MEMORY_PROFILING_LOG_INTERVAL 5000u /* 5 sec */
#define nDPId_COMPRESSION_SCAN_INTERVAL 20000u /* 20 sec */
#define nDPId_COMPRESSION_FLOW_INACTIVITY 30000u /* 30 sec */
#define nDPId_FLOW_SCAN_INTERVAL 10000u /* 10 sec */
#define nDPId_GENERIC_IDLE_TIME 600000u /* 600 sec */
#define nDPId_ICMP_IDLE_TIME 120000u /* 120 sec */
#define nDPId_TCP_IDLE_TIME 7440000u /* 7440 sec */
#define nDPId_UDP_IDLE_TIME 180000u /* 180 sec */
#define nDPId_TCP_POST_END_FLOW_TIME 120000u /* 120 sec */
#define nDPId_THREAD_DISTRIBUTION_SEED 0x03dd018b
#define nDPId_PACKETS_PER_FLOW_TO_SEND 15u
#define nDPId_PACKETS_PER_FLOW_TO_PROCESS NDPI_DEFAULT_MAX_NUM_PKTS_PER_FLOW_TO_DISSECT
#define nDPId_FLOW_STRUCT_SEED 0x5defc104

/* nDPIsrvd default config options */
#define nDPIsrvd_PIDFILE "/tmp/ndpisrvd.pid"
#define nDPIsrvd_MAX_REMOTE_DESCRIPTORS 32
#define nDPIsrvd_CACHE_ARRAY_LENGTH 256

#endif
