# TODOs

1. improve nDPIsrvd buffer bloat handling (Do not fall back to blocking mode!)
2. improve UDP/TCP timeout handling by reading netfilter conntrack timeouts from /proc (or just read conntrack table entries)
3. detect interface / timeout changes and apply them to nDPId
4. implement AEAD crypto via libsodium (at least for TCP communication)
