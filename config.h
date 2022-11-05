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
#define NETWORK_BUFFER_MAX_SIZE 33792u /* 8192 + 8192 + 8192 + 8192 + 1024 */
#define NETWORK_BUFFER_LENGTH_DIGITS 5u
#define NETWORK_BUFFER_LENGTH_DIGITS_STR "5"

#define TIME_S_TO_US(s) (s * 1000u * 1000u)

/* nDPId default config options */
#define nDPId_PIDFILE "/tmp/ndpid.pid"
#define nDPId_MAX_FLOWS_PER_THREAD 4096u
#define nDPId_MAX_IDLE_FLOWS_PER_THREAD (nDPId_MAX_FLOWS_PER_THREAD / 32u)
#define nDPId_MAX_READER_THREADS 32u
#define nDPId_ERROR_EVENT_THRESHOLD_N 16u
#define nDPId_ERROR_EVENT_THRESHOLD_TIME TIME_S_TO_US(10u) /* 10 sec */
#define nDPId_DAEMON_STATUS_INTERVAL TIME_S_TO_US(600u) /* 600 sec */
#define nDPId_MEMORY_PROFILING_LOG_INTERVAL TIME_S_TO_US(5u) /* 5 sec */
#define nDPId_COMPRESSION_SCAN_INTERVAL TIME_S_TO_US(20u) /* 20 sec */
#define nDPId_COMPRESSION_FLOW_INACTIVITY TIME_S_TO_US(30u) /* 30 sec */
#define nDPId_FLOW_SCAN_INTERVAL TIME_S_TO_US(10u) /* 10 sec */
#define nDPId_GENERIC_IDLE_TIME TIME_S_TO_US(600u) /* 600 sec */
#define nDPId_ICMP_IDLE_TIME TIME_S_TO_US(120u) /* 120 sec */
#define nDPId_TCP_IDLE_TIME TIME_S_TO_US(7440u) /* 7440 sec */
#define nDPId_UDP_IDLE_TIME TIME_S_TO_US(180u) /* 180 sec */
#define nDPId_TCP_POST_END_FLOW_TIME TIME_S_TO_US(120u) /* 120 sec */
#define nDPId_THREAD_DISTRIBUTION_SEED 0x03dd018b
#define nDPId_PACKETS_PER_FLOW_TO_SEND 15u
#define nDPId_PACKETS_PER_FLOW_TO_PROCESS NDPI_DEFAULT_MAX_NUM_PKTS_PER_FLOW_TO_DISSECT
#define nDPId_PACKETS_PER_FLOW_TO_ANALYZE 32u
#define nDPId_ANALYZE_PLEN_MAX 1504u
#define nDPId_ANALYZE_PLEN_BIN_LEN 32u
#define nDPId_ANALYZE_PLEN_NUM_BINS 48u
#define nDPId_FLOW_STRUCT_SEED 0x5defc104

/* nDPIsrvd default config options */
#define nDPIsrvd_PIDFILE "/tmp/ndpisrvd.pid"
#define nDPIsrvd_MAX_REMOTE_DESCRIPTORS 128
#define nDPIsrvd_MAX_WRITE_BUFFERS 1024

#endif
