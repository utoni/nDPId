#!/usr/bin/env python3

import base64
import os
import sys

sys.path.append(os.path.dirname(sys.argv[0]) + '/../../contrib')
import nDPIsrvd
from nDPIsrvd import TermColor, nDPIsrvdSocket, PcapPacket

FLOWS = dict()

def parse_json_str(json_str):

    j = nDPIsrvd.JsonParseBytes(json_str[0])

    global FLOWS

    if 'flow_event_name' in j:

        event = j['flow_event_name'].lower()
        flow_id = j['flow_id']

        if 'midstream' in j and j['midstream'] == 1:
            return

        if event == 'new':
            FLOWS[flow_id] = PcapPacket(flow_id)
        elif flow_id not in FLOWS:
            return
        elif event == 'end' or event == 'idle':
            del FLOWS[flow_id]
        elif event == 'detected' or event == 'guessed' or event == 'not-detected':
            if 'ndpi' in j and 'flow_risk' in j['ndpi']:
                print('Risky flow with id {}, PCAP dump returned: {}'.format(flow_id, FLOWS[flow_id].fin('risky')))

            FLOWS[flow_id].detected()
        else:
            raise RuntimeError('unknown flow event name: {}'.format(event))

    elif 'packet_event_name' in j:

        buffer_decoded = base64.b64decode(j['pkt'], validate=True)

        if j['packet_event_name'] == 'packet-flow':

            flow_id = j['flow_id']

            if flow_id not in FLOWS:
                return

            FLOWS[flow_id].addPacket(buffer_decoded, j['pkt_type'], j['pkt_ipoffset'])

        if j['packet_event_name'] == 'packet':

            flow = PcapPacket()
            flow.addPacket(buffer_decoded, j['pkt_type'], j['pkt_ipoffset'])


if __name__ == '__main__':
    host = nDPIsrvd.DEFAULT_HOST
    port = nDPIsrvd.DEFAULT_PORT

    if len(sys.argv) == 1:
        sys.stderr.write('usage: {} [host] [port]\n'.format(sys.argv[0]))
    if len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port = int(sys.argv[2])

    sys.stderr.write('Recv buffer size: {}\n'.format(nDPIsrvd.NETWORK_BUFFER_MAX_SIZE))
    sys.stderr.write('Connecting to {}:{} ..\n'.format(host, port))

    nsock = nDPIsrvdSocket()
    nsock.connect(host, port)

    while True:
        received = nsock.receive()
        for received_json_pkt in received:
            parse_json_str(received_json_pkt)

