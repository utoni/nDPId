#!/usr/bin/env python3

import multiprocessing
import os
import sys

sys.path.append(os.path.dirname(sys.argv[0]) + '/../../dependencies')
sys.path.append(os.path.dirname(sys.argv[0]) + '/../share/nDPId')
sys.path.append(sys.base_prefix + '/share/nDPId')
import nDPIsrvd
from nDPIsrvd import nDPIsrvdSocket
import plotly_dash

FLOW_RISK_SEVERE = 4
FLOW_RISK_HIGH   = 3
FLOW_RISK_MEDIUM = 2
FLOW_RISK_LOW    = 1

def nDPIsrvd_worker_onFlowCleanup(instance, current_flow, global_user_data):
    _, shared_flow_dict = global_user_data

    flow_key = current_flow.flow_key

    shared_flow_dict['current-flows'] -= 1

    if flow_key not in shared_flow_dict:
        return True

    shared_flow_dict['total-l4-bytes'] += shared_flow_dict[flow_key]['total-l4-bytes']

    if shared_flow_dict[flow_key]['is_detected'] is True:
        shared_flow_dict['current-detected-flows'] -= 1

    if shared_flow_dict[flow_key]['is_guessed'] is True:
        shared_flow_dict['current-guessed-flows'] -= 1

    if shared_flow_dict[flow_key]['is_not_detected'] is True:
        shared_flow_dict['current-not-detected-flows'] -= 1

    if shared_flow_dict[flow_key]['is_midstream'] is True:
        shared_flow_dict['current-midstream-flows'] -= 1

    if shared_flow_dict[flow_key]['is_risky'] > 0:
        shared_flow_dict['current-risky-flows'] -= 1

    if shared_flow_dict[flow_key]['is_risky'] == FLOW_RISK_LOW:
        shared_flow_dict['current-risky-flows-low'] -= 1
    elif shared_flow_dict[flow_key]['is_risky'] == FLOW_RISK_MEDIUM:
        shared_flow_dict['current-risky-flows-medium'] -= 1
    elif shared_flow_dict[flow_key]['is_risky'] == FLOW_RISK_HIGH:
        shared_flow_dict['current-risky-flows-high'] -= 1
    elif shared_flow_dict[flow_key]['is_risky'] == FLOW_RISK_SEVERE:
        shared_flow_dict['current-risky-flows-severe'] -= 1

    del shared_flow_dict[current_flow.flow_key]

    return True

def nDPIsrvd_worker_onJsonLineRecvd(json_dict, instance, current_flow, global_user_data):
    nsock, shared_flow_dict = global_user_data

    shared_flow_dict['total-events'] += 1
    shared_flow_dict['total-json-bytes'] = nsock.received_bytes

    if 'error_event_name' in json_dict:
        shared_flow_dict['total-base-events'] += 1

    if 'daemon_event_name' in json_dict:
        shared_flow_dict['total-daemon-events'] += 1

    if 'packet_event_name' in json_dict and \
       (json_dict['packet_event_name'] == 'packet' or \
        json_dict['packet_event_name'] == 'packet-flow'):
        shared_flow_dict['total-packet-events'] += 1

    if 'flow_id' not in json_dict:
        return True
    else:
        flow_key = json_dict['alias'] + '-' + json_dict['source'] + '-' + str(json_dict['flow_id'])

    if flow_key not in shared_flow_dict:
        current_flow.flow_key = flow_key
        shared_flow_dict[flow_key] = mgr.dict()
        shared_flow_dict[flow_key]['is_detected']     = False
        shared_flow_dict[flow_key]['is_guessed']      = False
        shared_flow_dict[flow_key]['is_not_detected'] = False
        shared_flow_dict[flow_key]['is_midstream']    = False
        shared_flow_dict[flow_key]['is_risky']        = 0
        shared_flow_dict[flow_key]['total-l4-bytes']  = 0

        shared_flow_dict[flow_key]['json'] = mgr.dict()

        shared_flow_dict['total-flows']   += 1
        shared_flow_dict['current-flows'] += 1

    if current_flow.flow_key != flow_key:
        return False

    if 'flow_src_tot_l4_payload_len' in json_dict and 'flow_dst_tot_l4_payload_len' in json_dict:
        shared_flow_dict[flow_key]['total-l4-bytes'] = json_dict['flow_src_tot_l4_payload_len'] + \
                                                       json_dict['flow_dst_tot_l4_payload_len']

    if 'midstream' in json_dict and json_dict['midstream'] != 0:
        if shared_flow_dict[flow_key]['is_midstream'] is False:
            shared_flow_dict['total-midstream-flows']   += 1
            shared_flow_dict['current-midstream-flows'] += 1
        shared_flow_dict[flow_key]['is_midstream'] = True

    if 'ndpi' in json_dict:
        shared_flow_dict[flow_key]['json']['ndpi'] = json_dict['ndpi']

        if 'flow_risk' in json_dict['ndpi']:
            if shared_flow_dict[flow_key]['is_risky'] == 0:
                shared_flow_dict['total-risky-flows']   += 1
                shared_flow_dict['current-risky-flows'] += 1

            severity = shared_flow_dict[flow_key]['is_risky']
            if severity == FLOW_RISK_LOW:
                shared_flow_dict['current-risky-flows-low'] -= 1
            elif severity == FLOW_RISK_MEDIUM:
                shared_flow_dict['current-risky-flows-medium'] -= 1
            elif severity == FLOW_RISK_HIGH:
                shared_flow_dict['current-risky-flows-high'] -= 1
            elif severity == FLOW_RISK_SEVERE:
                shared_flow_dict['current-risky-flows-severe'] -= 1

            for key in json_dict['ndpi']['flow_risk']:
                if json_dict['ndpi']['flow_risk'][key]['severity'] == 'Low':
                    severity = max(severity, FLOW_RISK_LOW)
                elif json_dict['ndpi']['flow_risk'][key]['severity'] == 'Medium':
                    severity = max(severity, FLOW_RISK_MEDIUM)
                elif json_dict['ndpi']['flow_risk'][key]['severity'] == 'High':
                    severity = max(severity, FLOW_RISK_HIGH)
                elif json_dict['ndpi']['flow_risk'][key]['severity'] == 'Severe':
                    severity = max(severity, FLOW_RISK_SEVERE)
                else:
                    raise RuntimeError('Invalid flow risk severity: {}'.format(
                                       json_dict['ndpi']['flow_risk'][key]['severity']))

            shared_flow_dict[flow_key]['is_risky'] = severity
            if severity == FLOW_RISK_LOW:
                shared_flow_dict['current-risky-flows-low'] += 1
            elif severity == FLOW_RISK_MEDIUM:
                shared_flow_dict['current-risky-flows-medium'] += 1
            elif severity == FLOW_RISK_HIGH:
                shared_flow_dict['current-risky-flows-high'] += 1
            elif severity == FLOW_RISK_SEVERE:
                shared_flow_dict['current-risky-flows-severe'] += 1

    if 'flow_event_name' not in json_dict:
        return True

    if json_dict['flow_state'] == 'finished' and \
       json_dict['ndpi']['proto'] != 'Unknown' and \
       shared_flow_dict[flow_key]['is_detected'] is False:
        shared_flow_dict['total-detected-flows']   += 1
        shared_flow_dict['current-detected-flows'] += 1
        shared_flow_dict[flow_key]['is_detected'] = True

    if json_dict['flow_event_name'] == 'new':

        shared_flow_dict['total-flow-new-events'] += 1

    elif json_dict['flow_event_name'] == 'update':

        shared_flow_dict['total-flow-update-events'] += 1

    elif json_dict['flow_event_name'] == 'end':

        shared_flow_dict['total-flow-end-events'] += 1

    elif json_dict['flow_event_name'] == 'idle':

        shared_flow_dict['total-flow-idle-events'] += 1

    elif json_dict['flow_event_name'] == 'guessed':

        shared_flow_dict['total-flow-guessed-events'] += 1

        if shared_flow_dict[flow_key]['is_guessed'] is False:
            shared_flow_dict['total-guessed-flows']   += 1
            shared_flow_dict['current-guessed-flows'] += 1
        shared_flow_dict[flow_key]['is_guessed'] = True

    elif json_dict['flow_event_name'] == 'not-detected':

        shared_flow_dict['total-flow-not-detected-events'] += 1

        if shared_flow_dict[flow_key]['is_not_detected'] is False:
            shared_flow_dict['total-not-detected-flows']   += 1
            shared_flow_dict['current-not-detected-flows'] += 1
        shared_flow_dict[flow_key]['is_not_detected'] = True

    elif json_dict['flow_event_name'] == 'detected' or \
         json_dict['flow_event_name'] == 'detection-update':

        if json_dict['flow_event_name'] == 'detection-update':
            shared_flow_dict['total-flow-detection-update-events'] += 1
        else:
            shared_flow_dict['total-flow-detected-events'] += 1

        if shared_flow_dict[flow_key]['is_detected'] is False:
            shared_flow_dict['total-detected-flows']   += 1
            shared_flow_dict['current-detected-flows'] += 1
        shared_flow_dict[flow_key]['is_detected'] = True

        if shared_flow_dict[flow_key]['is_guessed'] is True:
            shared_flow_dict['total-guessed-flows']   -= 1
            shared_flow_dict['current-guessed-flows'] -= 1
        shared_flow_dict[flow_key]['is_guessed'] = False

    return True


def nDPIsrvd_worker(address, shared_flow_dict):
    sys.stderr.write('Recv buffer size: {}\n'
                     .format(nDPIsrvd.NETWORK_BUFFER_MAX_SIZE))
    sys.stderr.write('Connecting to {} ..\n'
                     .format(address[0]+':'+str(address[1])
                             if type(address) is tuple else address))

    try:
        while True:
            try:
                nsock = nDPIsrvdSocket()
                nsock.connect(address)
                nsock.loop(nDPIsrvd_worker_onJsonLineRecvd,
                           nDPIsrvd_worker_onFlowCleanup,
                           (nsock, shared_flow_dict))
            except nDPIsrvd.SocketConnectionBroken:
                sys.stderr.write('Lost connection to {} .. reconnecting\n'
                                 .format(address[0]+':'+str(address[1])
                                         if type(address) is tuple else address))
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    argparser = nDPIsrvd.defaultArgumentParser()
    argparser.add_argument('--listen-address', type=str, default='127.0.0.1', help='Plotly listen address')
    argparser.add_argument('--listen-port', type=str, default=8050, help='Plotly listen port')
    args = argparser.parse_args()
    address = nDPIsrvd.validateAddress(args)

    mgr = multiprocessing.Manager()
    shared_flow_dict = mgr.dict()

    shared_flow_dict['total-events']             = 0
    shared_flow_dict['total-flow-new-events']    = 0
    shared_flow_dict['total-flow-update-events'] = 0
    shared_flow_dict['total-flow-end-events']    = 0
    shared_flow_dict['total-flow-idle-events']   = 0
    shared_flow_dict['total-flow-detected-events'] = 0
    shared_flow_dict['total-flow-detection-update-events'] = 0
    shared_flow_dict['total-flow-guessed-events'] = 0
    shared_flow_dict['total-flow-not-detected-events'] = 0
    shared_flow_dict['total-packet-events']      = 0
    shared_flow_dict['total-base-events']        = 0
    shared_flow_dict['total-daemon-events']      = 0

    shared_flow_dict['total-json-bytes']         = 0
    shared_flow_dict['total-l4-bytes']           = 0
    shared_flow_dict['total-flows']              = 0
    shared_flow_dict['total-detected-flows']     = 0
    shared_flow_dict['total-risky-flows']        = 0
    shared_flow_dict['total-midstream-flows']    = 0
    shared_flow_dict['total-guessed-flows']      = 0
    shared_flow_dict['total-not-detected-flows'] = 0

    shared_flow_dict['current-flows']              = 0
    shared_flow_dict['current-detected-flows']     = 0
    shared_flow_dict['current-midstream-flows']    = 0
    shared_flow_dict['current-guessed-flows']      = 0
    shared_flow_dict['current-not-detected-flows'] = 0

    shared_flow_dict['current-risky-flows']        = 0
    shared_flow_dict['current-risky-flows-severe'] = 0
    shared_flow_dict['current-risky-flows-high']   = 0
    shared_flow_dict['current-risky-flows-medium'] = 0
    shared_flow_dict['current-risky-flows-low']    = 0

    nDPIsrvd_job = multiprocessing.Process(target=nDPIsrvd_worker,
                                           args=(address, shared_flow_dict))
    nDPIsrvd_job.start()

    web_job = multiprocessing.Process(target=plotly_dash.web_worker,
                                      args=(shared_flow_dict, args.listen_address, args.listen_port))
    web_job.start()

    nDPIsrvd_job.join()
    web_job.terminate()
    web_job.join()
