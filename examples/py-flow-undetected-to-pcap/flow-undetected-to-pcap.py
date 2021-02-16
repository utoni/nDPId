#!/usr/bin/env python3

import os
import sys

sys.path.append(os.path.dirname(sys.argv[0]) + '/../../dependencies')
import nDPIsrvd
from nDPIsrvd import TermColor, nDPIsrvdSocket, PcapPacket

def onJsonLineRecvd(json_dict, current_flow, global_user_data):
    if current_flow is None:

        if 'packet_event_name' in json_dict and json_dict['packet_event_name'] == 'packet':
            fake_flow = Flow()
            fake_flow.pkt = PcapPacket()
            PcapPacket.handleJSON(json_dict, fake_flow)
            fake_flow.pkt.doDump()
            fake_flow.pkt.setSuffix('packet_undetected')
            fake_flow.pkt.fin()

        return True

    PcapPacket.handleJSON(json_dict, current_flow)

    if 'flow_event_name' in json_dict and PcapPacket.isInitialized(current_flow) and \
        (json_dict['flow_event_name'] == 'guessed' or json_dict['flow_event_name'] == 'not-detected'):

        current_flow.pcap_packet.doDump()
        if json_dict['flow_event_name'] == 'guessed':
            current_flow.pcap_packet.setSuffix('guessed')

            try:
                if current_flow.pcap_packet.fin() is True:
                    print('Guessed flow with id {}, dumped'.format(current_flow.flow_id))
            except RuntimeError as err:
                print('Guessed flow with id {} excepted: {}'.format(current_flow.flow_id, str(err)))

        else:
            current_flow.pcap_packet.setSuffix('undetected')

            try:
                if current_flow.pcap_packet.fin() is True:
                    print('Not-detected flow with id {}, dumped'.format(current_flow.flow_id))
            except RuntimeError as err:
                print('Not-detected flow with id {} excepted: {}'.format(current_flow.flow_id, str(err)))

    return True

if __name__ == '__main__':
    argparser = nDPIsrvd.defaultArgumentParser()
    args = argparser.parse_args()
    address = nDPIsrvd.validateAddress(args)

    sys.stderr.write('Recv buffer size: {}\n'.format(nDPIsrvd.NETWORK_BUFFER_MAX_SIZE))
    sys.stderr.write('Connecting to {} ..\n'.format(address[0]+':'+str(address[1]) if type(address) is tuple else address))

    nsock = nDPIsrvdSocket()
    nsock.connect(address)
    nsock.loop(onJsonLineRecvd, None)
