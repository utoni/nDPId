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

global args
global whois_db

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

def onJsonLineRecvd(json_dict, current_flow, global_user_data):
    instance_and_source = ''
    instance_and_source += '[{}]'.format(TermColor.setColorByString(json_dict['alias']))
    instance_and_source += '[{}]'.format(TermColor.setColorByString(json_dict['source']))

    if 'basic_event_id' in json_dict:
        print('{} {}: {}'.format(instance_and_source, prettifyEvent([TermColor.WARNING, TermColor.BLINK], 16, 'BASIC-EVENT'), json_dict['basic_event_name']))
        return True
    elif 'flow_event_id' not in json_dict:
        return True

    if checkEventFilter(json_dict) is False:
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
    if json_dict['flow_event_name'] == 'guessed' or json_dict['flow_event_name'] == 'not-detected':
        flow_event_name += '{}{:>16}{}'.format(TermColor.HINT, json_dict['flow_event_name'], TermColor.END)
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
    nsock.loop(onJsonLineRecvd, None)
