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
        n = int()

        for key in shared_flow_dict.keys():
            try:
                flow = shared_flow_dict[key]
            except KeyError:
                continue

            s += '{}, '.format(str(flow.flow_id))
            n += 1

        if len(s) == 0:
            s = '-'
        else:
            s = s[:-2]

        print('Flows({}): {}'.format(n, s))
        time.sleep(1)


def nDPIsrvd_worker_onFlowCleanup(instance, current_flow, global_user_data):
    shared_flow_dict = global_user_data

    del shared_flow_dict[current_flow.flow_id]

    return True


def nDPIsrvd_worker_onJsonLineRecvd(json_dict, instance, current_flow, global_user_data):
    shared_flow_dict = global_user_data

    if 'flow_id' not in json_dict:
        return True

    shared_flow_dict[current_flow.flow_id] = current_flow

    return True


def nDPIsrvd_worker(address, shared_flow_dict):
    sys.stderr.write('Recv buffer size: {}\n'.format(
        nDPIsrvd.NETWORK_BUFFER_MAX_SIZE))
    sys.stderr.write('Connecting to {} ..\n'.format(
        address[0] + ':' +
        str(address[1]) if type(address) is tuple else address))

    nsock = nDPIsrvdSocket()
    nsock.connect(address)
    nsock.loop(nDPIsrvd_worker_onJsonLineRecvd,
               nDPIsrvd_worker_onFlowCleanup,
               shared_flow_dict)


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
