Notice
======

You should only use this as a feed if you are aware that you will get an unstable `nDPId` version.
To get a more stable `nDPId` experience, use the https://github.com/utoni/my-openwrt-packages feed.

HowTo use this
==============

Simply add `src-link ndpid_testing [path-to-this-dir]` to your OpenWrt repository feeds (`feeds.conf`).

Run `./scripts/feeds update -a && ./scripts/feeds install -a` from the OpenWrt repository directory.

There should be a new package named `nDPId-testing` available.
