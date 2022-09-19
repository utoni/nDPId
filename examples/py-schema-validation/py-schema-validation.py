#!/usr/bin/env python3

import os
import sys

sys.path.append(os.path.dirname(sys.argv[0]) + '/../../dependencies')
sys.path.append(os.path.dirname(sys.argv[0]) + '/../share/nDPId')
sys.path.append(os.path.dirname(sys.argv[0]))
sys.path.append(sys.base_prefix + '/share/nDPId')
import nDPIsrvd
from nDPIsrvd import nDPIsrvdSocket, TermColor

class Stats:

    def __init__(self):
        self.lines_processed = 0
        self.print_dot_every = 10
        self.print_nmb_every = self.print_dot_every * 5

def onJsonLineRecvd(json_dict, instance, current_flow, global_user_data):
    validation_done = nDPIsrvd.validateAgainstSchema(json_dict)

    global_user_data.lines_processed += 1
    if global_user_data.lines_processed % global_user_data.print_dot_every == 0:
        sys.stdout.write('.')
        sys.stdout.flush()
    print_nmb_every = global_user_data.print_nmb_every + (len(str(global_user_data.lines_processed)) * global_user_data.print_dot_every)
    if global_user_data.lines_processed % print_nmb_every == 0:
        sys.stdout.write(str(global_user_data.lines_processed))
        sys.stdout.flush()

    return validation_done

if __name__ == '__main__':
    argparser = nDPIsrvd.defaultArgumentParser()
    args = argparser.parse_args()
    address = nDPIsrvd.validateAddress(args)

    sys.stderr.write('Recv buffer size: {}\n'.format(nDPIsrvd.NETWORK_BUFFER_MAX_SIZE))
    sys.stderr.write('Connecting to {} ..\n'.format(address[0]+':'+str(address[1]) if type(address) is tuple else address))

    nDPIsrvd.initSchemaValidator()

    nsock = nDPIsrvdSocket()
    nsock.connect(address)
    try:
        nsock.loop(onJsonLineRecvd, None, Stats())
    except nDPIsrvd.SocketConnectionBroken as err:
        sys.stderr.write('\n{}\n'.format(err))
    except KeyboardInterrupt:
        print()
