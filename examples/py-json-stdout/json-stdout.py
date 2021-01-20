#!/usr/bin/env python3

import os
import sys

sys.path.append(os.path.dirname(sys.argv[0]) + '/../../dependencies')
import nDPIsrvd
from nDPIsrvd import nDPIsrvdSocket, TermColor


def parse_json_str(json_str):

    j = nDPIsrvd.JsonParseBytes(json_str[0])
    nDPIdEvent = nDPIsrvd.nDPIdEvent.validateJsonEventTypes(j)
    if nDPIdEvent.isValid is False:
        raise RuntimeError('Missing event id or event name invalid in the JSON string: {}'.format(j))
    print(j)

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

