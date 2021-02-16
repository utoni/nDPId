#!/usr/bin/env python3

import base64
import os
import sys

sys.path.append(os.path.dirname(sys.argv[0]) + '/../../dependencies')
import nDPIsrvd
from nDPIsrvd import TermColor, nDPIsrvdSocket, PcapPacket

def onJsonLineRecvd(json_dict, current_flow, global_user_data):
    if current_flow is None:
        return True

    PcapPacket.handleJSON(json_dict, current_flow)

    if 'flow_event_name' in json_dict and PcapPacket.isInitialized(current_flow) and \
        'ndpi' in json_dict and 'flow_risk' in json_dict['ndpi'] and not hasattr(current_flow, 'is_risky_flow'):

        current_flow.pcap_packet.doDump()
        current_flow.pcap_packet.setSuffix('risky')
        current_flow.is_risky_flow = True
        print('Risky flow with id {} marked for dumping.'.format(current_flow.flow_id))

    if hasattr(current_flow, 'is_risky_flow') and \
        (current_flow.pcap_packet.current_packet < current_flow.pcap_packet.max_packets or \
         ('flow_event_name' in json_dict and \
          (json_dict['flow_event_name'] == 'end' or json_dict['flow_event_name'] == 'idle'))):

        try:
            if current_flow.pcap_packet.fin() is True:
                print('Risky flow with id {} dumped.'.format(current_flow.flow_id))
        except RuntimeError as err:
            pass

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
