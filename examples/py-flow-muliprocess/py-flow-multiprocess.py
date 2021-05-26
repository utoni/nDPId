#!/usr/bin/env python3

import multiprocessing
import os
import sys

sys.path.append(os.path.dirname(sys.argv[0]) + '/../share/nDPId')
sys.path.append(os.path.dirname(sys.argv[0]) + '/../usr/share/nDPId')
try:
    import nDPIsrvd
    from nDPIsrvd import nDPIsrvdSocket
except ImportError:
    sys.path.append(os.path.dirname(sys.argv[0]) + '/../../dependencies')
    import nDPIsrvd
    from nDPIsrvd import nDPIsrvdSocket


def mp_worker(unused, shared_flow_dict):
    import time
    while True:
        s = str()
        for key in shared_flow_dict.keys():
            s += '{}, '.format(str(key))
        if len(s) == 0:
            s = '-'
        else:
            s = s[:-2]
        print('Flows: {}'.format(s))
        time.sleep(1)


def nDPIsrvd_worker_onJsonLineRecvd(json_dict, current_flow, global_user_data):
    shared_flow_dict = global_user_data

    if 'flow_event_name' not in json_dict:
        return True

    if json_dict['flow_event_name'] == 'new':
        shared_flow_dict[json_dict['flow_id']] = current_flow
    elif json_dict['flow_event_name'] == 'idle' or \
            json_dict['flow_event_name'] == 'end':
        if json_dict['flow_id'] in shared_flow_dict:
            del shared_flow_dict[json_dict['flow_id']]

    return True


def nDPIsrvd_worker(address, shared_flow_dict):
    sys.stderr.write('Recv buffer size: {}\n'.format(
        nDPIsrvd.NETWORK_BUFFER_MAX_SIZE))
    sys.stderr.write('Connecting to {} ..\n'.format(
        address[0] + ':' +
        str(address[1]) if type(address) is tuple else address))

    nsock = nDPIsrvdSocket()
    nsock.connect(address)
    nsock.loop(nDPIsrvd_worker_onJsonLineRecvd, shared_flow_dict)


if __name__ == '__main__':
    argparser = nDPIsrvd.defaultArgumentParser()
    args = argparser.parse_args()
    address = nDPIsrvd.validateAddress(args)

    mgr = multiprocessing.Manager()
    shared_flow_dict = mgr.dict()

    nDPIsrvd_job = multiprocessing.Process(
            target=nDPIsrvd_worker,
            args=(address, shared_flow_dict))
    nDPIsrvd_job.start()

    mp_job = multiprocessing.Process(
            target=mp_worker,
            args=(None, shared_flow_dict))
    mp_job.start()

    nDPIsrvd_job.join()
    mp_job.terminate()
    mp_job.join()
