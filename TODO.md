# TODOs

1.6:

 * event I/O abstraction layer (testing)
 * Apple/BSD port (testing)

1.7:

 * let nDPIsrvd (collector) connect to other nDPIsrvd instances (as distributor)
 * nDPIsrvd GnuTLS support for TCP/IP distributor connections

no release plan:

 * improve UDP/TCP timeout handling by reading netfilter conntrack timeouts from /proc (or just read conntrack table entries)
 * detect interface / timeout changes and apply them to nDPId
