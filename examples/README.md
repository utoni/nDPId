# examples

Some ready-2-use/ready-2-extend examples/utils.
All examples are prefixed with their used LANG.

## c-analysed

A feature extractor useful for ML/DL use cases.
It generates CSV files from flow "analyse" events.

## c-captured

A capture daemon suitable for low-resource devices.
It saves flows that were guessed/undetected/risky/midstream to a PCAP file for manual analysis.

## c-collectd

A collecd-exec compatible middleware that gathers statistic values from nDPId.

## c-json-stdout

Tiny nDPId json dumper. Does not provide any useful funcationality besides dumping parsed JSON objects.

## c-simple

Very tiny integration example.

## ~~go-dashboard~~ (DISCONTINUED!)

A discontinued tty UI nDPId dashboard.
Removed with commit 29c72fb30bb7d5614c0a8ebb73bee2ac7eca6608.

## js-rt-analyzer

[nDPId-rt-analyzer](https://gitlab.com/verzulli/ndpid-rt-analyzer.git)

## py-flow-info

Prints prettyfied information about flow events.

## py-machine-learning

Use sklearn together with CSVs created with **c-analysed** to train and predict DPI detections.

Try it with: `./examples/py-machine-learning/sklearn-ml.py --csv ./ndpi-analysed.csv --proto-class tls.youtube --proto-class tls.github --proto-class tls.spotify --proto-class tls.facebook --proto-class tls.instagram --proto-class tls.doh_dot --proto-class quic --proto-class icmp`

This way you should get 9 different classification classes.
You may notice that some classes e.g. TLS protocol classifications may have a higher false-negative rate.

Unfortunately, I can not provide any datasets due to some privacy concerns.

## py-flow-dashboard

A realtime web based graph using Plotly/Dash.
Probably the most informative example.

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
