HowTo use this
==============

Simply add `src-link ndpid_testing [path-to-this-dir]` to your OpenWrt repository feeds (`feeds.conf`).

Run `./scripts/feeds update -a && ./scripts/feeds install -a` from the OpenWrt repository directory.

There should be a new package named `nDPId-testing` available.
