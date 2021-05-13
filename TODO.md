# TODOs

1. unify `struct io_buffer` from nDPIsrvd.c and `struct nDPIsrvd_buffer` from nDPIsrvd.h
2. improve nDPIsrvd buffer bloat handling (Do not fall back to blocking mode!)
3. improve UDP/TCP timeout handling by reading netfilter conntrack timeouts from /proc (or just read the conntrack table directly)
4. detect interface / timeout changes and apply them to nDPId
5. implement AEAD crypto via libsodium (at least for TCP communication)
