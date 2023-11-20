# TODOs

1.7:

 * let nDPIsrvd (collector) connect to other nDPIsrvd instances (as distributor)
 * nDPIsrvd GnuTLS support for TCP/IP distributor connections
 * PF\_RING integration

2.0.0:

 * switch to semantic versioning for the greater good ;)

no release plan:

 * merge flow end/idle event into idle event (end is not really useful..)
 * provide a shared library for C / C++ for distributor application developers
 * improve UDP/TCP timeout handling by reading netfilter conntrack timeouts from /proc (or just read conntrack table entries)
 * detect interface / timeout changes and apply them to nDPId
 * switch to MIT or BSD License
