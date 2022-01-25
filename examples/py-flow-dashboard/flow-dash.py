#!/usr/bin/env python3

import multiprocessing
import os
import sys

import plotly_dash

sys.path.append(os.path.dirname(sys.argv[0]) + '/../share/nDPId')
sys.path.append(os.path.dirname(sys.argv[0]) + '/../usr/share/nDPId')
try:
    import nDPIsrvd
    from nDPIsrvd import nDPIsrvdSocket
except ImportError:
    sys.path.append(os.path.dirname(sys.argv[0]) + '/../../dependencies')
    import nDPIsrvd
    from nDPIsrvd import nDPIsrvdSocket


def nDPIsrvd_worker_onFlowCleanup(instance, current_flow, global_user_data):
    _, shared_flow_dict = global_user_data

    flow_id = current_flow.flow_id

    shared_flow_dict['current-flows'] -= 1

    if shared_flow_dict[flow_id]['is_detected'] is True:
        shared_flow_dict['current-detected-flows'] -= 1

    if shared_flow_dict[flow_id]['is_guessed'] is True:
        shared_flow_dict['current-guessed-flows'] -= 1

    if shared_flow_dict[flow_id]['is_not_detected'] is True:
        shared_flow_dict['current-detected-flows'] -= 1

    if shared_flow_dict[flow_id]['is_midstream'] is True:
        shared_flow_dict['current-midstream-flows'] -= 1

    if shared_flow_dict[flow_id]['is_risky'] is True:
        shared_flow_dict['current-risky-flows'] -= 1

    del shared_flow_dict[current_flow.flow_id]

    return True

def nDPIsrvd_worker_onJsonLineRecvd(json_dict, instance, current_flow, global_user_data):
    nsock, shared_flow_dict = global_user_data

    shared_flow_dict['total-events'] += 1
    shared_flow_dict['total-bytes']   = nsock.received_bytes

    if 'flow_id' not in json_dict:
        return True
    else:
        if current_flow.flow_id != json_dict['flow_id']:
            return False
        flow_id = current_flow.flow_id

    # print(json_dict)

    if flow_id not in shared_flow_dict:
        shared_flow_dict[flow_id] = mgr.dict()
        shared_flow_dict[flow_id]['is_detected']     = False
        shared_flow_dict[flow_id]['is_guessed']      = False
        shared_flow_dict[flow_id]['is_not_detected'] = False
        shared_flow_dict[flow_id]['is_midstream']    = False
        shared_flow_dict[flow_id]['is_risky']        = False

        shared_flow_dict['total-flows']   += 1
        shared_flow_dict['current-flows'] += 1

    if 'midstream' in json_dict and json_dict['midstream'] != 0:
        if shared_flow_dict[flow_id]['is_midstream'] is False:
            shared_flow_dict['total-midstream-flows']   += 1
            shared_flow_dict['current-midstream-flows'] += 1
        shared_flow_dict[flow_id]['is_midstream'] = True

    if 'ndpi' in json_dict and 'flow_risk' in json_dict['ndpi']:
        if shared_flow_dict[flow_id]['is_risky'] is False:
            shared_flow_dict['total-risky-flows']   += 1
            shared_flow_dict['current-risky-flows'] += 1
        shared_flow_dict[flow_id]['is_risky'] = True

    if 'flow_event_name' not in json_dict:
        return True

    if json_dict['flow_event_name'] == 'new':

        pass

    elif json_dict['flow_event_name'] == 'guessed':

        if shared_flow_dict[flow_id]['is_guessed'] is False:
            shared_flow_dict['total-guessed-flows']   += 1
            shared_flow_dict['current-guessed-flows'] += 1
        shared_flow_dict[flow_id]['is_guessed'] = True

    elif json_dict['flow_event_name'] == 'not-detected':

        if shared_flow_dict[flow_id]['is_not_detected'] is False:
            shared_flow_dict['total-not-detected-flows']   += 1
            shared_flow_dict['current-not-detected-flows'] += 1
        shared_flow_dict[flow_id]['is_not_detected'] = True

    elif json_dict['flow_event_name'] == 'detected' or \
         json_dict['flow_event_name'] == 'detection-update':

        if shared_flow_dict[flow_id]['is_detected'] is False:
            shared_flow_dict['total-detected-flows']   += 1
            shared_flow_dict['current-detected-flows'] += 1
        shared_flow_dict[flow_id]['is_detected'] = True

        if shared_flow_dict[flow_id]['is_guessed'] is True:
            shared_flow_dict['total-guessed-flows']   -= 1
            shared_flow_dict['current-guessed-flows'] -= 1
        shared_flow_dict[flow_id]['is_guessed'] = False

    return True


def nDPIsrvd_worker(address, shared_flow_dict):
    sys.stderr.write('Recv buffer size: {}\n'
                     .format(nDPIsrvd.NETWORK_BUFFER_MAX_SIZE))
    sys.stderr.write('Connecting to {} ..\n'
                     .format(address[0]+':'+str(address[1])
                             if type(address) is tuple else address))

    nsock = nDPIsrvdSocket()
    nsock.connect(address)
    nsock.loop(nDPIsrvd_worker_onJsonLineRecvd,
               nDPIsrvd_worker_onFlowCleanup,
               (nsock, shared_flow_dict))


if __name__ == '__main__':
    argparser = nDPIsrvd.defaultArgumentParser()
    args = argparser.parse_args()
    address = nDPIsrvd.validateAddress(args)

    mgr = multiprocessing.Manager()
    shared_flow_dict = mgr.dict()

    shared_flow_dict['total-events']             = 0
    shared_flow_dict['total-bytes']              = 0
    shared_flow_dict['total-flows']              = 0
    shared_flow_dict['total-detected-flows']     = 0
    shared_flow_dict['total-risky-flows']        = 0
    shared_flow_dict['total-midstream-flows']    = 0
    shared_flow_dict['total-guessed-flows']      = 0
    shared_flow_dict['total-not-detected-flows'] = 0

    shared_flow_dict['current-flows']              = 0
    shared_flow_dict['current-detected-flows']     = 0
    shared_flow_dict['current-risky-flows']        = 0
    shared_flow_dict['current-midstream-flows']    = 0
    shared_flow_dict['current-guessed-flows']      = 0
    shared_flow_dict['current-not-detected-flows'] = 0

    nDPIsrvd_job = multiprocessing.Process(target=nDPIsrvd_worker,
                                           args=(address, shared_flow_dict))
    nDPIsrvd_job.start()

    web_job = multiprocessing.Process(target=plotly_dash.web_worker,
                                      args=(shared_flow_dict,))
    web_job.start()

    nDPIsrvd_job.join()
    web_job.terminate()
    web_job.join()
