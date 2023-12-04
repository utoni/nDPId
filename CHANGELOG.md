# CHANGELOG

#### nDPId 1.6 (Nov 2023)

 - Added Event I/O abstraction layer (supporting only poll/epoll by now)
 - Support for OSX and *BSD systems
 - Added proper DLT_RAW dissection for IPv4 and IPv6
 - Improved TCP timeout handling if FIN/RST seen which caused Midstream TCP flows when there shouldn't be any
 - Fixed a crash if `nDPId -o value=''` was used
 - Added OpenWrt packaging
 - Added new flow event "analyse" used to give some statistical information about active flows
 - Added new analyse event daemon which generates CSV files from such events
 - Fixed a crash in nDPIsrvd if a collector closes a connection
 - Support `nDPId` to send it's data to a UDP endpoint instead of a nDPIsrvd collector
 - Added events and flow states documentation
 - Added basic systemd support
 - Fixed a bug in base64 encoding which could lead to invalid base64 strings
 - Added some machine learning examples
 - Fixed various smaller bugs
 - Fixed nDPIsrvd bug which causes invalid JSON messages sent to Distributors

#### nDPId 1.5 (Apr 2022)

 - Improved nDPId cross compilation
 - zLib flow memory compression (Experimental!)
 - Memory profiling for nDPId-test
 - JSMN with parent link support for subtoken iteration
 - Refactored nDPIsrvd buffer and buffer bloat handling
 - Upgraded JSMN/uthash
 - Improved nDPIsrvd.(h|py) debugging capability for client apps
 - Advanced flow usage logging usable for memory profiling
 - Support for dissection additional layer2/layer3 protocols
 - Serialize more JSON information
 - Add TCP/IP support for nDPIsrvd
 - Improved nDPIsrvd connection lost behaviour
 - Reworked Python/C distributor API
 - Support read()/recv() timeouts and nonblocking I/O


#### nDPId 1.4 (Jun 2021)

 - Use layer4 specific flow timeouts for nDPId
 - Reworked layer4 flow length names and calculations (use only layer4 payload w/o any previous headers) for nDPId
 - Build system cleanup and cosmetics


#### nDPId 1.3 (May 2021)

 - Added missing datalink layer types


#### nDPId 1.2 (May 2021)

 - OpenWrt compatible build system


#### nDPId 1.1 (May 2021)

 - Added License information


#### nDPId 1.0 (May 2021)

 - First public release
