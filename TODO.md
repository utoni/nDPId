# TODOs

1. improve UDP/TCP timeout handling by reading netfilter conntrack timeouts from /proc (or just read conntrack table entries)
2. detect interface / timeout changes and apply them to nDPId
3. implement AEAD crypto via libsodium (at least for TCP communication)
