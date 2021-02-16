#!/usr/bin/env python3

import os
import sys

sys.path.append(os.path.dirname(sys.argv[0]) + '/../../dependencies')
import nDPIsrvd
from nDPIsrvd import nDPIsrvdSocket, TermColor

def prettifyEvent(color_list, whitespaces, text):
    term_attrs = str()
    for color in color_list:
        term_attrs += str(color)
    return '{}{:>' + str(whitespaces) + '}{}'.format(term_attrs, text, TermColor.END)

def onJsonLineRecvd(json_dict, current_flow, global_user_data):
    if 'basic_event_id' in json_dict:
        print('{}: {}'.format(prettifyEvent([TermColor.WARNING, TermColor.BLINK], 16, 'BASIC-EVENT'), json_dict['basic_event_name']))
        return True
    elif 'flow_event_id' not in json_dict:
        return True

    ndpi_proto_categ = ''
    ndpi_frisk = ''

    if 'ndpi' in json_dict:
        if 'proto' in json_dict['ndpi']:
            ndpi_proto_categ += '[' + str(json_dict['ndpi']['proto']) + ']'

        if 'category' in json_dict['ndpi']:
            ndpi_proto_categ += '[' + str(json_dict['ndpi']['category']) + ']'

        if 'flow_risk' in json_dict['ndpi']:
            cnt = 0
            for key in json_dict['ndpi']['flow_risk']:
                ndpi_frisk += str(json_dict['ndpi']['flow_risk'][key]) + ', '
                cnt += 1
            ndpi_frisk = '{}: {}'.format(
                TermColor.WARNING + TermColor.BOLD + 'RISK' + TermColor.END if cnt < 2
                else TermColor.FAIL + TermColor.BOLD + TermColor.BLINK + 'RISK' + TermColor.END,
                ndpi_frisk[:-2])

    instance_and_source = ''
    instance_and_source += '[{}]'.format(TermColor.setColorByString(json_dict['alias']))
    instance_and_source += '[{}]'.format(TermColor.setColorByString(json_dict['source']))

    line_suffix = ''
    flow_event_name = ''
    if json_dict['flow_event_name'] == 'guessed' or json_dict['flow_event_name'] == 'not-detected':
        flow_event_name += '{}{:>16}{}'.format(TermColor.HINT, json_dict['flow_event_name'], TermColor.END)
    else:
        if json_dict['flow_event_name'] == 'new' and json_dict['midstream'] != 0:
            line_suffix = '[{}]'.format(TermColor.WARNING + TermColor.BLINK + 'MIDSTREAM' + TermColor.END)
        flow_event_name += '{:>16}'.format(json_dict['flow_event_name'])

    if json_dict['l3_proto'] == 'ip4':
        print('{} {}: [{:.>6}] [{}][{:.>5}] [{:.>15}]{} -> [{:.>15}]{} {}{}' \
              ''.format(instance_and_source, flow_event_name, 
              json_dict['flow_id'], json_dict['l3_proto'], json_dict['l4_proto'],
              json_dict['src_ip'].lower(),
              '[{:.>5}]'.format(json_dict['src_port']) if 'src_port' in json_dict else '',
              json_dict['dst_ip'].lower(),
              '[{:.>5}]'.format(json_dict['dst_port']) if 'dst_port' in json_dict else '',
              ndpi_proto_categ, line_suffix))
    elif json_dict['l3_proto'] == 'ip6':
        print('{} {}: [{:.>6}] [{}][{:.>5}] [{:.>39}]{} -> [{:.>39}]{} {}{}' \
                ''.format(instance_and_source, flow_event_name,
              json_dict['flow_id'], json_dict['l3_proto'], json_dict['l4_proto'],
              json_dict['src_ip'].lower(),
              '[{:.>5}]'.format(json_dict['src_port']) if 'src_port' in json_dict else '',
              json_dict['dst_ip'].lower(),
              '[{:.>5}]'.format(json_dict['dst_port']) if 'dst_port' in json_dict else '',
              ndpi_proto_categ, line_suffix))
    else:
        raise RuntimeError('unsupported l3 protocol: {}'.format(json_dict['l3_proto']))

    if len(ndpi_frisk) > 0:
        print('{} {:>18}{}'.format(instance_and_source, '', ndpi_frisk))

    return True

if __name__ == '__main__':
    argparser = nDPIsrvd.defaultArgumentParser()
    args = argparser.parse_args()
    address = nDPIsrvd.validateAddress(args)

    sys.stderr.write('Recv buffer size: {}\n'.format(nDPIsrvd.NETWORK_BUFFER_MAX_SIZE))
    sys.stderr.write('Connecting to {} ..\n'.format(address[0]+':'+str(address[1]) if type(address) is tuple else address))

    nsock = nDPIsrvdSocket()
    nsock.connect(address)
    nsock.loop(onJsonLineRecvd, None)
