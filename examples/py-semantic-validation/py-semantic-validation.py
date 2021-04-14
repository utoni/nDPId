#!/usr/bin/env python3

import os
import sys

sys.path.append(os.path.dirname(sys.argv[0]) + '/../share/nDPId')
sys.path.append(os.path.dirname(sys.argv[0]) + '/../usr/share/nDPId')
try:
    import nDPIsrvd
    from nDPIsrvd import nDPIsrvdSocket, TermColor
except ImportError:
    sys.path.append(os.path.dirname(sys.argv[0]) + '/../../dependencies')
    import nDPIsrvd
    from nDPIsrvd import nDPIsrvdSocket, TermColor

global lowest_flow_id_for_new_flow
lowest_flow_id_for_new_flow = 0

class Stats:
    event_counter   = dict()

    lines_processed = 0
    print_dot_every = 10
    print_nmb_every = print_dot_every * 5

    def resetEventCounter(self):
        keys = ['init','reconnect','shutdown', \
                'new','end','idle','guessed','detected','detection-update','not-detected', \
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
        keys = [ [ 'init','reconnect','shutdown' ], \
                 [ 'new','end','idle' ], \
                 [ 'guessed','detected','detection-update','not-detected' ], \
                 [ 'packet', 'packet-flow' ] ]
        retval = str()
        retval += '-' * 98 + '--\n'
        for klist in keys:
            for k in klist:
                retval += '| {:<16}: {:<4} '.format(k, self.event_counter[k])
            retval += '\n--' + '-' * 98 + '\n'
        return retval

    def __init__(self):
        self.resetEventCounter()

class SemanticValidationException(Exception):
    def __init__(self, current_flow, text):
        self.text = text
        self.current_flow = current_flow
    def __str__(self):
        if self.current_flow is None:
            return '{}'.format(self.text)
        else:
            return 'Flow ID {}: {}'.format(self.current_flow.flow_id, self.text)

def onJsonLineRecvd(json_dict, current_flow, global_user_data):
    global lowest_flow_id_for_new_flow
    stats = global_user_data
    stats.incrementEventCounter(json_dict)

    try:
        semdict = current_flow.semdict
    except AttributeError:
        try:
            semdict = current_flow.semdict = dict()
        except AttributeError:
            semdict = dict()

    if 'current_flow' in semdict:
        if semdict['current_flow'] != current_flow:
            raise SemanticValidationException(current_flow,
                                              'Semantic dictionary flow reference != current flow reference: ' \
                                              '{} != {}'.format(semdict['current_flow'], current_flow))
    else:
        semdict['current_flow'] = current_flow

    if current_flow is not None:
        if 'flow_id' in semdict:
            if semdict['flow_id'] != current_flow.flow_id or \
               semdict['flow_id'] != json_dict['flow_id']:
                raise SemanticValidationException(current_flow,
                                                  'Semantic dictionary flow id != current flow id != JSON dictionary flow id: ' \
                                                  '{} != {} != {}'.format(semdict['flow_id'], \
                                                  current_flow.flow_id, json_dict['flow_id']))
        else:
            if json_dict['flow_id'] != current_flow.flow_id:
                raise SemanticValidationException(current_flow,
                                                  'JSON dictionary flow id != current flow id: ' \
                                                  '{} != {}'.format(json_dict['flow_id'], current_flow.flow_id))
            semdict['flow_id'] = json_dict['flow_id']

    if 'flow_event_name' in json_dict:
        if json_dict['flow_event_name'] == 'end' or \
           json_dict['flow_event_name'] == 'idle':
            pass
        elif json_dict['flow_event_name'] == 'new':
            if lowest_flow_id_for_new_flow > current_flow.flow_id:
                raise SemanticValidationException(current_flow,
                                                  'JSON dictionary lowest flow id for new flow > current flow id: ' \
                                                  '{} != {}'.format(lowest_flow_id_for_new_flow, current_flow.flow_id))
            current_flow.flow_new_seen = True
            if lowest_flow_id_for_new_flow == 0:
                lowest_flow_id_for_new_flow = current_flow.flow_id
        elif json_dict['flow_event_name'] == 'detected' or \
             json_dict['flow_event_name'] == 'not-detected':
            try:
                if current_flow.flow_detection_finished is True:
                    raise SemanticValidationException(current_flow,
                                                      'Flow detection already finished, but detected/not-detected event received.')
            except AttributeError:
                pass
            current_flow.flow_detection_finished = True

    try:
        if current_flow.flow_new_seen is True and lowest_flow_id_for_new_flow > current_flow.flow_id:
            raise SemanticValidationException(current_flow, 'Lowest flow id for flow > current flow id: ' \
                                              '{} > {}'.format(lowest_flow_id_for_new_flow, current_flow.flow_id))
    except AttributeError:
        pass

    global_user_data.lines_processed += 1
    if global_user_data.lines_processed % global_user_data.print_dot_every == 0:
        sys.stdout.write('.')
        sys.stdout.flush()
    print_nmb_every = global_user_data.print_nmb_every + (len(str(global_user_data.lines_processed)) * global_user_data.print_dot_every)
    if global_user_data.lines_processed % print_nmb_every == 0:
        sys.stdout.write(str(global_user_data.lines_processed))
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
    stats = Stats()
    try:
        nsock.loop(onJsonLineRecvd, stats)
    except nDPIsrvd.SocketConnectionBroken as err:
        sys.stderr.write('\n{}\n'.format(err))
    except KeyboardInterrupt:
        print()

    sys.stderr.write('\nEvent counter:\n' + stats.getEventCounterStr() + '\n')
    if args.strict is True:
        if stats.verifyEventCounter() is False:
            sys.stderr.write('Event counter verification failed. (`--strict\')\n')
            sys.exit(1)
