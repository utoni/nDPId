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
        elif event == 'detected' or event == 'detection-update':
            FLOWS[flow_id].detected()
        elif event == 'guessed' or event == 'not-detected':
            if event == 'guessed':
                print('Guessed flow with id {}, PCAP dump returned: {}'.format(flow_id, FLOWS[flow_id].fin('guessed')))
            else:
                print('Not-detected flow with id {}: PCAP dump returned {}'.format(flow_id, FLOWS[flow_id].fin('undetected')))
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
    argparser = nDPIsrvd.defaultArgumentParser()
    args = argparser.parse_args()
    address = nDPIsrvd.validateAddress(args)

    sys.stderr.write('Recv buffer size: {}\n'.format(nDPIsrvd.NETWORK_BUFFER_MAX_SIZE))
    sys.stderr.write('Connecting to {} ..\n'.format(address[0]+':'+str(address[1]) if type(address) is tuple else address))

    nsock = nDPIsrvdSocket()
    nsock.connect(address)

    while True:
        received = nsock.receive()
        for received_json_pkt in received:
            parse_json_str(received_json_pkt)

