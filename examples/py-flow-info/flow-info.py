#!/usr/bin/env python3

import os
import math
import sys
import time

sys.path.append(os.path.dirname(sys.argv[0]) + '/../share/nDPId')
sys.path.append(os.path.dirname(sys.argv[0]) + '/../usr/share/nDPId')
try:
    import nDPIsrvd
    from nDPIsrvd import nDPIsrvdSocket, TermColor
except ImportError:
    sys.path.append(os.path.dirname(sys.argv[0]) + '/../../dependencies')
    import nDPIsrvd
    from nDPIsrvd import nDPIsrvdSocket, TermColor

global args
global whois_db

def set_attr_from_dict(some_object, some_dict, key_and_attr_name, default_value):
    try:
        setattr(some_object, key_and_attr_name, some_dict[key_and_attr_name])
    except KeyError:
        if default_value is not None and getattr(some_object, key_and_attr_name, None) is None:
            setattr(some_object, key_and_attr_name, default_value)

def set_attr_if_not_set(some_object, attr_name, value):
    try:
        getattr(some_object, attr_name)
    except AttributeError:
        setattr(some_object, attr_name, value)

class Stats:
    last_status_length = 0
    avg_xfer_json_bytes = 0.0
    expired_tot_l4_payload_len = 0
    expired_avg_l4_payload_len = 0
    total_flows        = 0
    risky_flows        = 0
    midstream_flows    = 0
    guessed_flows      = 0
    not_detected_flows = 0
    start_time    = 0.0
    current_time  = 0.0
    json_lines    = 0
    spinner_state = 0

    def __init__(self, nDPIsrvd_sock):
        self.start_time = time.time()
        self.nsock = nDPIsrvd_sock

    def updateSpinner(self):
        if self.current_time + 0.25 <= time.time():
            self.spinner_state += 1

    def getSpinner(self):
        spinner_states = ['-', '\\', '|', '/']
        return spinner_states[self.spinner_state % len(spinner_states)]

    def getDataFromJson(self, json_dict, current_flow):
        if current_flow is None:
            return

        set_attr_from_dict(current_flow, json_dict, 'flow_tot_l4_payload_len', 0)
        set_attr_from_dict(current_flow, json_dict, 'flow_avg_l4_payload_len', 0)
        if 'ndpi' in json_dict:
            set_attr_from_dict(current_flow, json_dict['ndpi'], 'flow_risk', {})
        else:
            set_attr_from_dict(current_flow, {}, 'flow_risk', {})
        set_attr_from_dict(current_flow, json_dict, 'midstream', 0)
        set_attr_from_dict(current_flow, json_dict, 'flow_event_name', '')
        set_attr_if_not_set(current_flow, 'guessed', False)
        set_attr_if_not_set(current_flow, 'not_detected', False)

        if current_flow.flow_event_name == 'detected' or \
           current_flow.flow_event_name == 'detection-update':
            current_flow.guessed = False
        elif current_flow.flow_event_name == 'guessed':
            current_flow.guessed = True
        elif current_flow.flow_event_name == 'not-detected':
            current_flow.not_detected = True

    def update(self, json_dict, current_flow):
        self.updateSpinner()
        self.json_lines += 1
        self.current_time = time.time()
        self.avg_xfer_json_bytes = self.nsock.received_bytes / (self.current_time - self.start_time)
        self.getDataFromJson(json_dict, current_flow)

    def updateOnCleanup(self, current_flow):
        self.total_flows += 1
        self.expired_tot_l4_payload_len += current_flow.flow_tot_l4_payload_len
        self.expired_avg_l4_payload_len += current_flow.flow_avg_l4_payload_len
        self.risky_flows += 1 if len(current_flow.flow_risk) > 0 else 0
        self.midstream_flows += 1 if current_flow.midstream != 0 else 0
        self.guessed_flows += 1 if current_flow.guessed is True else 0
        self.not_detected_flows += 1 if current_flow.not_detected is True else 0

    def getStatsFromFlowMgr(self):
        alias_count = 0
        source_count = 0
        flow_count = 0
        flow_tot_l4_payload_len = 0.0
        flow_avg_l4_payload_len = 0.0
        risky = 0
        midstream = 0
        guessed = 0
        not_detected = 0

        instances = self.nsock.flow_mgr.instances
        for alias in instances:
            alias_count += 1
            for source in instances[alias]:
                source_count += 1
                for flow_id in instances[alias][source].flows:
                    flow_count += 1
                    current_flow = instances[alias][source].flows[flow_id]

                    flow_tot_l4_payload_len += current_flow.flow_tot_l4_payload_len
                    flow_avg_l4_payload_len += current_flow.flow_avg_l4_payload_len
                    risky += 1 if len(current_flow.flow_risk) > 0 else 0
                    midstream += 1 if current_flow.midstream != 0 else 0
                    guessed += 1 if current_flow.guessed is True else 0
                    not_detected = 1 if current_flow.not_detected is True else 0

        return alias_count, source_count, flow_count, \
               flow_tot_l4_payload_len, flow_avg_l4_payload_len, \
               risky, midstream, guessed, not_detected

    @staticmethod
    def prettifyBytes(bytes_received):
        size_names = ['B', 'KB', 'MB', 'GB', 'TB']
        if bytes_received == 0:
            i = 0
        else:
            i = min(int(math.floor(math.log(bytes_received, 1024))), len(size_names) - 1)
        p = math.pow(1024, i)
        s = round(bytes_received / p, 2)
        return '{:.2f} {}'.format(s, size_names[i])

    def resetStatus(self):
        sys.stdout.write('\r' + str(' ' * self.last_status_length) + '\r')
        sys.stdout.flush()

    def printStatus(self):
        alias_count, source_count, flow_count, \
        tot_l4_payload_len, avg_l4_payload_len, \
        risky, midstream, guessed, not_detected = self.getStatsFromFlowMgr()

        out_str = '\r[n|tot|avg JSONs: {}|{}|{}/s] [tot|avg l4: {}|{}] ' \
            '[lss|srcs: {}|{}] ' \
            '[flws|rsky|mdstrm|!dtctd|gssd: {}|{}|{}|{}|{} / {}|{}|{}|{}|{}] [{}]' \
            ''.format(self.json_lines,
                      Stats.prettifyBytes(self.nsock.received_bytes),
                      Stats.prettifyBytes(self.avg_xfer_json_bytes),
                      Stats.prettifyBytes(tot_l4_payload_len + self.expired_tot_l4_payload_len),
                      Stats.prettifyBytes(avg_l4_payload_len + self.expired_avg_l4_payload_len),
                      alias_count, source_count,
                      flow_count, risky, midstream, not_detected, guessed,
                      flow_count + self.total_flows,
                      risky + self.risky_flows,
                      midstream + self.midstream_flows,
                      not_detected + self.not_detected_flows,
                      guessed + self.guessed_flows,
                      self.getSpinner())
        self.last_status_length = len(out_str) - 1 # '\r'

        sys.stdout.write(out_str)
        sys.stdout.flush()

def prettifyEvent(color_list, whitespaces, text):
    term_attrs = str()
    for color in color_list:
        term_attrs += str(color)
    fmt = '{}{:>' + str(whitespaces) + '}{}'
    return fmt.format(term_attrs, text, TermColor.END)

def checkEventFilter(json_dict):
    if json_dict['flow_event_name'] == 'new':
        if args.new is True:
            return True
    if json_dict['flow_event_name'] == 'detected' or \
       json_dict['flow_event_name'] == 'detection-update':
        if args.detection is True:
            return True
    if json_dict['flow_event_name'] == 'guessed':
        if args.guessed is True:
            return True
    if json_dict['flow_event_name'] == 'not-detected':
        if args.undetected is True:
            return True
    if 'ndpi' in json_dict and 'flow_risk' in json_dict['ndpi']:
        if args.risky is True:
            return True
    if json_dict['midstream'] != 0:
        if args.midstream is True:
            return True

    if args.new is False and args.detection is False and \
        args.guessed is False and args.undetected is False and \
        args.risky is False and args.midstream is False:
        return True

    return False

def whois(ip_str):
    if ip_str not in whois_db:
        try:
            whois_json = ipwhois.ipwhois.IPWhois(ip_str).lookup_whois()
            whois_db[ip_str] = whois_json['asn_description']
        except (ipwhois.exceptions.IPDefinedError, dns.resolver.NoResolverConfiguration):
            return None
    return whois_db[ip_str]

def onFlowCleanup(instance, current_flow, global_user_data):
    stats = global_user_data
    stats.updateOnCleanup(current_flow)

    return True

def onJsonLineRecvd(json_dict, instance, current_flow, global_user_data):
    stats = global_user_data
    stats.update(json_dict, current_flow)
    stats.resetStatus()

    instance_and_source = ''
    instance_and_source += '[{}]'.format(TermColor.setColorByString(instance.alias))
    instance_and_source += '[{}]'.format(TermColor.setColorByString(instance.source))

    if 'daemon_event_id' in json_dict:
        print('{} {}: {}'.format(instance_and_source, prettifyEvent([TermColor.WARNING, TermColor.BLINK], 16, 'DAEMON-EVENT'), json_dict['daemon_event_name']))
        stats.printStatus()
        return True
    if 'basic_event_id' in json_dict:
        print('{} {}: {}'.format(instance_and_source, prettifyEvent([TermColor.FAIL, TermColor.BLINK], 16, 'BASIC-EVENT'), json_dict['basic_event_name']))
        stats.printStatus()
        return True
    elif 'flow_event_id' not in json_dict:
        stats.printStatus()
        return True

    if checkEventFilter(json_dict) is False:
        stats.printStatus()
        return True

    ndpi_proto_categ_breed = ''
    ndpi_frisk = ''

    if 'ndpi' in json_dict:
        if 'proto' in json_dict['ndpi']:
            ndpi_proto_categ_breed += '[' + str(json_dict['ndpi']['proto']) + ']'

        if 'category' in json_dict['ndpi']:
            ndpi_proto_categ_breed += '[' + str(json_dict['ndpi']['category']) + ']'

        if 'breed' in json_dict['ndpi']:
            ndpi_proto_categ_breed += '[' + str(json_dict['ndpi']['breed']) + ']'

        if 'flow_risk' in json_dict['ndpi']:
            cnt = 0
            for key in json_dict['ndpi']['flow_risk']:
                ndpi_frisk += str(json_dict['ndpi']['flow_risk'][key]) + ', '
                cnt += 1
            ndpi_frisk = '{}: {}'.format(
                TermColor.WARNING + TermColor.BOLD + 'RISK' + TermColor.END if cnt < 2
                else TermColor.FAIL + TermColor.BOLD + TermColor.BLINK + 'RISK' + TermColor.END,
                ndpi_frisk[:-2])

    line_suffix = ''
    flow_event_name = ''
    if json_dict['flow_event_name'] == 'guessed':
        flow_event_name += '{}{:>16}{}'.format(TermColor.HINT, json_dict['flow_event_name'], TermColor.END)
    elif json_dict['flow_event_name'] == 'not-detected':
        flow_event_name += '{}{:>16}{}'.format(TermColor.WARNING + TermColor.BOLD + TermColor.BLINK,
                                               json_dict['flow_event_name'], TermColor.END)
    else:
        if json_dict['flow_event_name'] == 'new':
            line_suffix = ''
            if json_dict['midstream'] != 0:
                line_suffix += '[{}] '.format(TermColor.WARNING + TermColor.BLINK + 'MIDSTREAM' + TermColor.END)
            if args.ipwhois is True:
                src_whois = whois(json_dict['src_ip'].lower())
                dst_whois = whois(json_dict['dst_ip'].lower())
                line_suffix += '['
                if src_whois is not None:
                    line_suffix += '{}'.format(src_whois)
                if dst_whois is not None:
                    if src_whois is not None:
                        line_suffix += ' -> '
                    line_suffix += '{}'.format(dst_whois)
                if src_whois is None and dst_whois is None:
                    line_suffix += TermColor.WARNING + 'WHOIS empty' + TermColor.END
                line_suffix += ']'
        flow_event_name += '{:>16}'.format(json_dict['flow_event_name'])

    if json_dict['l3_proto'] == 'ip4':
        print('{} {}: [{:.>6}] [{}][{:.>5}] [{:.>15}]{} -> [{:.>15}]{} {}{}' \
              ''.format(instance_and_source, flow_event_name, 
              json_dict['flow_id'], json_dict['l3_proto'], json_dict['l4_proto'],
              json_dict['src_ip'].lower(),
              '[{:.>5}]'.format(json_dict['src_port']) if 'src_port' in json_dict else '',
              json_dict['dst_ip'].lower(),
              '[{:.>5}]'.format(json_dict['dst_port']) if 'dst_port' in json_dict else '',
              ndpi_proto_categ_breed, line_suffix))
    elif json_dict['l3_proto'] == 'ip6':
        print('{} {}: [{:.>6}] [{}][{:.>5}] [{:.>39}]{} -> [{:.>39}]{} {}{}' \
                ''.format(instance_and_source, flow_event_name,
              json_dict['flow_id'], json_dict['l3_proto'], json_dict['l4_proto'],
              json_dict['src_ip'].lower(),
              '[{:.>5}]'.format(json_dict['src_port']) if 'src_port' in json_dict else '',
              json_dict['dst_ip'].lower(),
              '[{:.>5}]'.format(json_dict['dst_port']) if 'dst_port' in json_dict else '',
              ndpi_proto_categ_breed, line_suffix))
    else:
        raise RuntimeError('unsupported l3 protocol: {}'.format(json_dict['l3_proto']))

    if len(ndpi_frisk) > 0:
        print('{} {:>18}{}'.format(instance_and_source, '', ndpi_frisk))

    stats.printStatus()

    return True

if __name__ == '__main__':
    argparser = nDPIsrvd.defaultArgumentParser()
    argparser.add_argument('--guessed',    action='store_true', default=False, help='Print only guessed flow events.')
    argparser.add_argument('--undetected', action='store_true', default=False, help='Print only undetected flow events.')
    argparser.add_argument('--risky',      action='store_true', default=False, help='Print only risky flow events.')
    argparser.add_argument('--midstream',  action='store_true', default=False, help='Print only midstream flow events.')
    argparser.add_argument('--new',        action='store_true', default=False, help='Print only new flow events.')
    argparser.add_argument('--detection',  action='store_true', default=False, help='Print only detected/detection-update flow events.')
    argparser.add_argument('--ipwhois',    action='store_true', default=False, help='Use Python-IPWhois to print additional location information.')
    args = argparser.parse_args()

    if args.ipwhois is True:
        import dns, ipwhois
        whois_db = dict()

    address = nDPIsrvd.validateAddress(args)

    sys.stderr.write('Recv buffer size: {}\n'.format(nDPIsrvd.NETWORK_BUFFER_MAX_SIZE))
    sys.stderr.write('Connecting to {} ..\n'.format(address[0]+':'+str(address[1]) if type(address) is tuple else address))

    nsock = nDPIsrvdSocket()
    nsock.connect(address)
    stats = Stats(nsock)
    try:
        nsock.loop(onJsonLineRecvd, onFlowCleanup, stats)
    except KeyboardInterrupt:
        print('\n\nKeyboard Interrupt: cleaned up {} flows.'.format(len(nsock.shutdown())))
