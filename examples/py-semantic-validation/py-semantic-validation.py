#!/usr/bin/env python3

import os
import sys

sys.path.append(os.path.dirname(sys.argv[0]) + '/../../dependencies')
sys.path.append(os.path.dirname(sys.argv[0]) + '/../share/nDPId')
sys.path.append(os.path.dirname(sys.argv[0]) + '/../usr/share/nDPId')
import nDPIsrvd
from nDPIsrvd import nDPIsrvdSocket, TermColor

class Stats:

    def __init__(self, nDPIsrvd_sock):
        self.nsock = nDPIsrvd_sock
        self.event_counter   = dict()
        self.resetEventCounter()
        self.lines_processed = 0
        self.print_dot_every = 10
        self.print_nmb_every = self.print_dot_every * 5

    def resetEventCounter(self):
        keys = ['init','reconnect','shutdown','status', \
                'new','end','idle','update',
                'guessed','detected','detection-update','not-detected', \
                'packet', 'packet-flow']
        for k in keys:
            self.event_counter[k] = 0

    def incrementEventCounter(self, json_dict):
        try:
            if 'daemon_event_name' in json_dict:
                self.event_counter[json_dict['daemon_event_name']] += 1
            if 'flow_event_name' in json_dict:
                self.event_counter[json_dict['flow_event_name']] += 1
            if 'packet_event_name' in json_dict:
                self.event_counter[json_dict['packet_event_name']] += 1
        except KeyError as e:
            raise RuntimeError('Semantic validation failed for event counter '
                               'which received an invalid key: {}'.format(str(e)))

    def verifyEventCounter(self):
        if self.event_counter['shutdown'] != self.event_counter['init'] or self.event_counter['init'] == 0:
            return False
        if self.event_counter['new'] != self.event_counter['end'] + self.event_counter['idle']:
            return False
        if self.event_counter['new'] < self.event_counter['detected'] + self.event_counter['not-detected']:
            return False
        if self.event_counter['new'] < self.event_counter['guessed'] + self.event_counter['not-detected']:
            return False

        return True

    def getEventCounterStr(self):
        keys = [ [ 'init','reconnect','shutdown','status' ], \
                 [ 'new','end','idle','update' ], \
                 [ 'guessed','detected','detection-update','not-detected' ], \
                 [ 'packet', 'packet-flow' ] ]
        retval = str()
        retval += '-' * 98 + '--\n'
        for klist in keys:
            for k in klist:
                retval += '| {:<16}: {:<4} '.format(k, self.event_counter[k])
            retval += '\n--' + '-' * 98 + '\n'
        return retval

class SemanticValidationException(Exception):
    def __init__(self, current_flow, text):
        self.text = text
        self.current_flow = current_flow
    def __str__(self):
        if self.current_flow is None:
            return '{}'.format(self.text)
        else:
            return 'Flow ID {}: {}'.format(self.current_flow.flow_id, self.text)

def onFlowCleanup(instance, current_flow, global_user_data):
    if type(instance) is not nDPIsrvd.Instance:
        raise SemanticValidationException(current_flow,
                                          'instance is not of type nDPIsrvd.Instance: ' \
                                          '{}'.format(type(instance)))
    if type(current_flow) is not nDPIsrvd.Flow:
        raise SemanticValidationException(current_flow,
                                          'current_flow is not of type nDPIsrvd.Flow: ' \
                                          '{}'.format(type(current_flow)))
    if type(global_user_data) is not tuple:
        raise SemanticValidationException(current_flow,
                                          'global_user_data is not of type tuple: ' \
                                          '{}'.format(type(global_user_data)))

    if current_flow.cleanup_reason == nDPIsrvd.FlowManager.CLEANUP_REASON_INVALID:
        raise SemanticValidationException(current_flow,
                                          'Invalid flow cleanup reason')

    if current_flow.cleanup_reason == nDPIsrvd.FlowManager.CLEANUP_REASON_FLOW_TIMEOUT:
        raise SemanticValidationException(current_flow,
                                          'Unexpected flow cleanup reason: CLEANUP_REASON_FLOW_TIMEOUT')

    try:
        l4_proto = current_flow.l4_proto
    except AttributeError:
        l4_proto = 'n/a'

    invalid_flows = stats.nsock.verify()
    if len(invalid_flows) > 0:
        invalid_flows_str = ''
        for flow_id in invalid_flows:
            flow = instance.flows[flow_id]
            try:
                l4_proto = flow.l4_proto
            except AttributeError:
                l4_proto = 'n/a'
            invalid_flows_str += '{} proto[{},{}] ts[{} + {} < {}] diff[{}], '.format(flow_id, l4_proto, flow.flow_idle_time,
                                                         flow.flow_last_seen, flow.flow_idle_time,
                                                         instance.most_recent_flow_time,
                                                         instance.most_recent_flow_time -
                                                         (flow.flow_last_seen + flow.flow_idle_time))

        raise SemanticValidationException(None, 'Flow Manager verification failed for: {}'.format(invalid_flows_str[:-2]))

    return True

def onJsonLineRecvd(json_dict, instance, current_flow, global_user_data):
    _, stats = global_user_data
    stats.incrementEventCounter(json_dict)

    if type(instance) is not nDPIsrvd.Instance:
        raise SemanticValidationException(current_flow,
                                          'instance is not of type nDPIsrvd.Instance: ' \
                                          '{}'.format(type(instance)))
    if type(current_flow) is not nDPIsrvd.Flow and current_flow is not None:
        raise SemanticValidationException(current_flow,
                                          'current_flow is not of type nDPIsrvd.Flow: ' \
                                          '{}'.format(type(current_flow)))
    if type(global_user_data) is not tuple:
        raise SemanticValidationException(current_flow,
                                          'global_user_data is not of type tuple: ' \
                                          '{}'.format(type(global_user_data)))
    if type(stats) is not Stats:
        raise SemanticValidationException(current_flow,
                                          'stats is not of type Stats: ' \
                                          '{}'.format(type(stats)))

    td = instance.getThreadDataFromJSON(json_dict)

    for event_name in ['basic_event_name', 'daemon_event_name',
                       'packet_event_name', 'flow_event_name']:
        if event_name in json_dict and json_dict[event_name].lower() == 'invalid':
            raise SemanticValidationException(current_flow,
                                              'Received an invalid event for {}'.format(event_name))

    if td is not None:
        lowest_possible_flow_id = getattr(td, 'lowest_possible_flow_id', 0)
        lowest_possible_packet_id = getattr(td, 'lowest_possible_packet_id', 0)
    else:
        lowest_possible_flow_id = 0
        lowest_possible_packet_id = 0

    if current_flow is not None:

        if instance.flows[current_flow.flow_id] != current_flow:
            raise SemanticValidationException(current_flow,
                                              'FlowManager flow reference != current flow reference: ' \
                                              '{} != {}'.format(instance.flows[current_flow.flow_id], current_flow))

        if 'l4_proto' in json_dict:
            try:
                l4_proto = current_flow.l4_proto
            except AttributeError:
                l4_proto = current_flow.l4_proto = json_dict['l4_proto']

            if l4_proto != json_dict['l4_proto']:
                raise SemanticValidationException(current_flow, 'Layer4 protocol mismatch: {} != {}'.format(l4_proto, json_dict['l4_proto']))
        elif json_dict['packet_event_name'] != 'packet-flow':
            raise SemanticValidationException(current_flow, 'Layer4 protocol not found in JSON')

        if 'flow_last_seen' in json_dict:
            if json_dict['flow_last_seen'] != current_flow.flow_last_seen:
                raise SemanticValidationException(current_flow, 'Flow last seen: {} != {}'.format(json_dict['flow_last_seen'],
                                                                                                  current_flow.flow_last_seen))

        if 'flow_idle_time' in json_dict:
            if json_dict['flow_idle_time'] != current_flow.flow_idle_time:
                raise SemanticValidationException(current_flow, 'Flow idle time mismatch: {} != {}'.format(json_dict['flow_idle_time'],
                                                                                                           current_flow.flow_idle_time))

        if ('flow_last_seen' in json_dict and 'flow_idle_time' not in json_dict) or \
           ('flow_last_seen' not in json_dict and 'flow_idle_time' in json_dict):
            raise SemanticValidationException(current_flow,
                                              'Got a JSON string with only one of both keys, ' \
                                              'both required for timeout handling:' \
                                              'flow_last_seen, flow_idle_time')

        if 'thread_ts_msec' in json_dict:
            current_flow.thread_ts_msec = int(json_dict['thread_ts_msec'])

        if 'flow_packet_id' in json_dict:
            try:
                if json_dict['flow_packet_id'] != current_flow.flow_packet_id + 1:
                    raise SemanticValidationException(current_flow,
                                                      'Invalid flow_packet_id seen, expected {}, got ' \
                                                      '{}'.format(current_flow.flow_packet_id + 1, json_dict['flow_packet_id']))
                else:
                    current_flow.flow_packet_id += 1
            except AttributeError:
                pass

    try:
        if current_flow.flow_ended == True:
            raise SemanticValidationException(current_flow,
                                              'Received JSON string for a flow that already ended/idled.')
    except AttributeError:
        pass

    if 'packet_event_name' in json_dict:
        if json_dict['packet_event_name'] == 'packet-flow':
            if lowest_possible_packet_id > json_dict['packet_id']:
                raise SemanticValidationException(current_flow,
                                                  'Invalid packet id for thread {} received: ' \
                                                  'expected packet id lesser or equal {}, ' \
                                                  'got {}'.format(json_dict['thread_id'],
                                                                  lowest_possible_packet_id,
                                                                  json_dict['packet_id']))
            if td is not None:
                td.lowest_possible_packet_id = lowest_possible_packet_id

    if 'flow_id' in json_dict:
        if current_flow.flow_id != json_dict['flow_id']:
            raise SemanticValidationException(current_flow,
                                              'Current flow id != JSON dictionary flow id: ' \
                                              '{} != {}'.format(current_flow.flow_id, json_dict['flow_id']))

    if 'flow_event_name' in json_dict:
        try:
            if current_flow.flow_detection_finished == True and \
               (json_dict['flow_event_name'] == 'detected' or \
                json_dict['flow_event_name'] == 'guessed'):
                raise SemanticValidationException(current_flow,
                                                  'Received another detected/guessed event after '
                                                  'a flow was already detected')

            if current_flow.flow_detected == True and \
               json_dict['flow_state'] == 'finished' and \
               json_dict['ndpi']['proto'] == 'Unknown' and \
               json_dict['ndpi']['category'] == 'Unknown':
                raise SemanticValidationException(current_flow,
                                                  'Flow detection successfully finished, but '
                                                  'flow update indiciates an unknown flow.')
        except AttributeError:
            pass

        try:
            if json_dict['flow_state'] == 'finished':
                current_flow.flow_finished = True

            if current_flow.flow_finished == True and \
               json_dict['flow_event_name'] != 'update' and \
               json_dict['flow_event_name'] != 'idle' and \
               json_dict['flow_event_name'] != 'end':
                raise SemanticValidationException(current_flow,
                                                  'Flow detection finished, but received another '
                                                  '{} event'.format(json_dict['flow_event_name']))
        except AttributeError:
            pass

        try:
            if json_dict['flow_first_seen'] > current_flow.thread_ts_msec or \
               json_dict['flow_last_seen'] > current_flow.thread_ts_msec or \
               json_dict['flow_first_seen'] > json_dict['flow_last_seen']:
                raise SemanticValidationException(current_flow,
                                                  'Last packet timestamp is invalid: ' \
                                                  'first_seen({}) <= {} >= last_seen({})'.format(json_dict['flow_first_seen'],
                                                                                                 current_flow.thread_ts_msec,
                                                                                                 json_dict['flow_last_seen']))
        except AttributeError:
            if json_dict['flow_event_name'] == 'new':
                pass

        if json_dict['flow_event_name'] == 'end' or \
           json_dict['flow_event_name'] == 'idle':
            current_flow.flow_ended = True
        elif json_dict['flow_event_name'] == 'new':
            if lowest_possible_flow_id > current_flow.flow_id:
                raise SemanticValidationException(current_flow,
                                                  'JSON dictionary lowest flow id for new flow > current flow id: ' \
                                                  '{} != {}'.format(lowest_possible_flow_id, current_flow.flow_id))
            try:
                if current_flow.flow_new_seen == True:
                    raise SemanticValidationException(current_flow,
                                                      'Received flow new event twice.')
            except AttributeError:
                pass
            current_flow.flow_new_seen = True
            current_flow.flow_packet_id = 0
            if lowest_possible_flow_id == 0 and td is not None:
                td.lowest_possible_flow_id = current_flow.flow_id
        elif json_dict['flow_event_name'] == 'detected' or \
             json_dict['flow_event_name'] == 'not-detected':
            try:
                if current_flow.flow_detection_finished is True:
                    raise SemanticValidationException(current_flow,
                                                      'Flow detection already finished, but detected/not-detected event received.')
            except AttributeError:
                pass
            current_flow.flow_detection_finished = True
            current_flow.flow_detected = True if json_dict['flow_event_name'] == 'detected' else False

    try:
        if current_flow.flow_new_seen is True and lowest_possible_flow_id > current_flow.flow_id:
            raise SemanticValidationException(current_flow, 'Lowest flow id for flow > current flow id: ' \
                                              '{} > {}'.format(lowest_possible_flow_id, current_flow.flow_id))
    except AttributeError:
        pass

    stats.lines_processed += 1
    if stats.lines_processed % stats.print_dot_every == 0:
        sys.stdout.write('.')
        sys.stdout.flush()
    print_nmb_every = stats.print_nmb_every + (len(str(stats.lines_processed)) * stats.print_dot_every)
    if stats.lines_processed % print_nmb_every == 0:
        sys.stdout.write(str(stats.lines_processed))
        sys.stdout.flush()

    return True

if __name__ == '__main__':
    argparser = nDPIsrvd.defaultArgumentParser()
    argparser.add_argument('--strict', action='store_true', default=False, help='Require and validate a full nDPId application lifecycle.')
    args = argparser.parse_args()
    address = nDPIsrvd.validateAddress(args)

    sys.stderr.write('Recv buffer size: {}\n'.format(nDPIsrvd.NETWORK_BUFFER_MAX_SIZE))
    sys.stderr.write('Connecting to {} ..\n'.format(address[0]+':'+str(address[1]) if type(address) is tuple else address))

    nsock = nDPIsrvdSocket()
    nsock.connect(address)
    stats = Stats(nsock)
    try:
        nsock.loop(onJsonLineRecvd, onFlowCleanup, (args.strict, stats))
    except nDPIsrvd.SocketConnectionBroken as err:
        sys.stderr.write('\n{}\n'.format(err))
    except KeyboardInterrupt:
        print()

    sys.stderr.write('\nEvent counter:\n' + stats.getEventCounterStr() + '\n')
    if args.strict is True:
        if stats.verifyEventCounter() is False:
            sys.stderr.write('Event counter verification failed. (`--strict\')\n')
            sys.exit(1)
