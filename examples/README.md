# examples

Some ready-2-use/ready-2-extend examples/utils.
All examples are prefixed with their used LANG.

## c-captured

A capture daemon suitable for low-resource devices.
It saves flows that were guessed/undetected/risky/midstream to a PCAP file for manual analysis.
Basicially a combination of `py-flow-undetected-to-pcap` and `py-risky-flow-to-pcap`.

## c-collectd

A collecd-exec compatible middleware that gathers statistic values from nDPId.

## c-json-stdout

Tiny nDPId json dumper. Does not provide any useful funcationality besides dumping parsed JSON objects.

## c-simple

Very tiny integration example.

## go-dashboard (DISCONTINUED!)

A discontinued tty UI nDPId dashboard.

## py-flow-info

Prints prettyfied information about flow events.

## py-flow-dash

A realtime web based graph using Plotly/Dash.

## py-flow-multiprocess

Simple Python Multiprocess example spawning two worker processes, one connecting to nDPIsrvd and one printing flow id's to STDOUT.

## py-flow-undetected-to-pcap

Captures and saves undetected flows to a PCAP file.

## py-json-stdout

Dump received and parsed JSON strings.

## py-risky-flow-to-pcap

Captures and saves risky flows to a PCAP file.

## py-schema-validation

Validate nDPId JSON strings against pre-defined JSON schema's.
See `schema/`.
Required by `tests/run_tests.sh`

## py-semantic-validation

Validate nDPId JSON strings against internal event semantics.
Required by `tests/run_tests.sh`

## py-ja3-checker

Captures JA3 hashes from nDPIsrvd and checks them against known hashes from [ja3er.com](https://ja3er.com).
