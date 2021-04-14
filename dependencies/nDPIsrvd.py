#!/usr/bin/env python3

import argparse
import array
import base64
import json
import re
import os
import stat
import socket
import sys

try:
    from colorama import Back, Fore, Style
    USE_COLORAMA=True
except ImportError:
    sys.stderr.write('Python module colorama not found, using fallback.\n')
    USE_COLORAMA=False

try:
    import scapy.all
except ImportError:
    sys.stderr.write('Python module scapy not found, PCAP generation will fail!\n')

DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 7000
DEFAULT_UNIX = '/tmp/ndpid-distributor.sock'

NETWORK_BUFFER_MIN_SIZE = 6 # NETWORK_BUFFER_LENGTH_DIGITS + 1
NETWORK_BUFFER_MAX_SIZE = 12288 # Please keep this value in sync with the one in config.h

PKT_TYPE_ETH_IP4 = 0x0800
PKT_TYPE_ETH_IP6 = 0x86DD


class TermColor:
    HINT = '\033[33m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'
    BLINK = '\x1b[5m'

    if USE_COLORAMA is True:
        COLOR_TUPLES = [ (Fore.BLUE, [Back.RED, Back.MAGENTA, Back.WHITE]),
                         (Fore.CYAN, [Back.MAGENTA, Back.RED, Back.WHITE]),
                         (Fore.GREEN, [Back.YELLOW, Back.RED, Back.MAGENTA, Back.WHITE]),
                         (Fore.MAGENTA, [Back.CYAN, Back.BLUE, Back.WHITE]),
                         (Fore.RED, [Back.GREEN, Back.BLUE, Back.WHITE]),
                         (Fore.WHITE, [Back.BLACK, Back.MAGENTA, Back.RED, Back.BLUE]),
                         (Fore.YELLOW, [Back.RED, Back.CYAN, Back.BLUE, Back.WHITE]),
                         (Fore.LIGHTBLUE_EX, [Back.LIGHTRED_EX, Back.RED]),
                         (Fore.LIGHTCYAN_EX, [Back.LIGHTMAGENTA_EX, Back.MAGENTA]),
                         (Fore.LIGHTGREEN_EX, [Back.LIGHTYELLOW_EX, Back.YELLOW]),
                         (Fore.LIGHTMAGENTA_EX, [Back.LIGHTCYAN_EX, Back.CYAN]),
                         (Fore.LIGHTRED_EX, [Back.LIGHTGREEN_EX, Back.GREEN]),
                         (Fore.LIGHTWHITE_EX, [Back.LIGHTBLACK_EX, Back.BLACK]),
                         (Fore.LIGHTYELLOW_EX, [Back.LIGHTRED_EX, Back.RED]) ]

    @staticmethod
    def calcColorHash(string):
        h = 0
        for char in string:
            h += ord(char)
        return h

    @staticmethod
    def getColorsByHash(string):
        h = TermColor.calcColorHash(string)
        tuple_index = h % len(TermColor.COLOR_TUPLES)
        bg_tuple_index = h % len(TermColor.COLOR_TUPLES[tuple_index][1])
        return (TermColor.COLOR_TUPLES[tuple_index][0],
                TermColor.COLOR_TUPLES[tuple_index][1][bg_tuple_index])

    @staticmethod
    def setColorByString(string):
        if USE_COLORAMA is True:
            fg_color, bg_color = TermColor.getColorsByHash(string)
            color_hash = TermColor.calcColorHash(string)
            return '{}{}{}{}{}'.format(Style.BRIGHT, fg_color, bg_color, string, Style.RESET_ALL)
        else:
            return '{}{}{}'.format(TermColor.BOLD, string, TermColor.END)

class Flow:
    flow_id = -1

class FlowManager:
    def __init__(self):
        self.__flows = dict()

    def __buildFlowKey(self, json_dict):
        if 'flow_id' not in json_dict or \
           'alias' not in json_dict or \
           'source' not in json_dict:
            return None

        return str(json_dict['alias']) + str(json_dict['source']) + str(json_dict['flow_id'])

    def getFlow(self, json_dict):
        event = json_dict['flow_event_name'].lower() if 'flow_event_name' in json_dict else ''
        flow_key = self.__buildFlowKey(json_dict)
        flow = None

        if flow_key is None:
            return None
        if flow_key not in self.__flows:
            self.__flows[flow_key] = Flow()
            self.__flows[flow_key].flow_id = int(json_dict['flow_id'])
        flow = self.__flows[flow_key]
        if event == 'end' or event == 'idle':
            flow = self.__flows[flow_key]
            del self.__flows[flow_key]

        return flow

class nDPIsrvdException(Exception):
    UNSUPPORTED_ADDRESS_TYPE = 1
    BUFFER_CAPACITY_REACHED  = 2
    SOCKET_CONNECTION_BROKEN = 3
    INVALID_LINE_RECEIVED    = 4
    CALLBACK_RETURNED_FALSE  = 5

    def __init__(self, etype):
        self.etype = etype
    def __str__(self):
        return 'nDPIsrvdException type {}'.format(self.etype)

class UnsupportedAddressType(nDPIsrvdException):
    def __init__(self, addr):
        super().__init__(nDPIsrvdException.UNSUPPORTED_ADDRESS_TYPE)
        self.addr = addr
    def __str__(self):
        return '{}'.format(str(self.addr))

class BufferCapacityReached(nDPIsrvdException):
    def __init__(self, current_length, max_length):
        super().__init__(nDPIsrvdException.BUFFER_CAPACITY_REACHED)
        self.current_length = current_length
        self.max_length = max_length
    def __str__(self):
        return '{} of {} bytes'.format(self.current_length, self.max_length)

class SocketConnectionBroken(nDPIsrvdException):
    def __init__(self):
        super().__init__(nDPIsrvdException.SOCKET_CONNECTION_BROKEN)
    def __str__(self):
        return 'Disconnected.'

class InvalidLineReceived(nDPIsrvdException):
    def __init__(self, packet_buffer):
        super().__init__(nDPIsrvdException.INVALID_LINE_RECEIVED)
        self.packet_buffer = packet_buffer
    def __str__(self):
        return 'Received JSON line is invalid.'

class CallbackReturnedFalse(nDPIsrvdException):
    def __init__(self):
        super().__init__(nDPIsrvdException.CALLBACK_RETURNED_FALSE)
    def __str__(self):
        return 'Callback returned False, abort.'

class nDPIsrvdSocket:
    def __init__(self):
        self.sock_family = None
        self.flow_mgr = FlowManager()

    def connect(self, addr):
        if type(addr) is tuple:
            self.sock_family = socket.AF_INET
        elif type(addr) is str:
            self.sock_family = socket.AF_UNIX
        else:
            raise UnsupportedAddressType(addr)

        self.sock = socket.socket(self.sock_family, socket.SOCK_STREAM)
        self.sock.connect(addr)
        self.buffer = bytes()
        self.msglen = 0
        self.digitlen = 0
        self.lines = []

    def receive(self):
        if len(self.buffer) == NETWORK_BUFFER_MAX_SIZE:
            raise BufferCapacityReached(len(self.buffer), NETWORK_BUFFER_MAX_SIZE)

        connection_finished = False
        try:
            recvd = self.sock.recv(NETWORK_BUFFER_MAX_SIZE - len(self.buffer))
        except ConnectionResetError:
            connection_finished = True
            recvd = bytes()
        if len(recvd) == 0:
            connection_finished = True

        self.buffer += recvd

        new_data_avail = False
        while self.msglen + self.digitlen <= len(self.buffer):

            if self.msglen == 0:
                starts_with_digits = re.match(r'(^\d+){', self.buffer[:NETWORK_BUFFER_MIN_SIZE].decode(errors='strict'))
                if starts_with_digits is None:
                    if len(self.buffer) < NETWORK_BUFFER_MIN_SIZE:
                        break
                    raise InvalidLineReceived(self.buffer)
                self.msglen = int(starts_with_digits.group(1))
                self.digitlen = len(starts_with_digits.group(1))

            if len(self.buffer) >= self.msglen + self.digitlen:
                recvd = self.buffer[self.digitlen:self.msglen + self.digitlen]
                self.buffer = self.buffer[self.msglen + self.digitlen:]
                self.lines += [(recvd,self.msglen,self.digitlen)]
                new_data_avail = True

                self.msglen = 0
                self.digitlen = 0

        if connection_finished is True:
            raise SocketConnectionBroken()

        return new_data_avail

    def parse(self, callback, global_user_data):
        retval = True
        index = 0
        for received_json_line in self.lines:
            json_dict = json.loads(received_json_line[0].decode('ascii', errors='replace'), strict=True)
            if callback(json_dict, self.flow_mgr.getFlow(json_dict), global_user_data) is not True:
                retval = False
                break
            index += 1

        self.lines = self.lines[index:]

        return retval

    def loop(self, callback, global_user_data):
        throw_ex = None

        while True:
            bytes_recv = 0
            try:
                bytes_recv = self.receive()
            except Exception as err:
                throw_ex = err

            if self.parse(callback, global_user_data) is False:
                raise CallbackReturnedFalse()

            if throw_ex is not None:
                raise throw_ex

class PcapPacket:
    def __init__(self):
        self.pktdump = None
        self.flow_id = 0
        self.packets = []
        self.__suffix = ''
        self.__dump = False
        self.__dumped = False

    @staticmethod
    def isInitialized(current_flow):
        return current_flow is not None and hasattr(current_flow, 'pcap_packet')

    @staticmethod
    def handleJSON(json_dict, current_flow):
        if 'flow_event_name' in json_dict:

            if json_dict['flow_event_name'] == 'new':

                current_flow.pcap_packet = PcapPacket()
                current_flow.pcap_packet.current_packet = 0
                current_flow.pcap_packet.max_packets = json_dict['flow_max_packets']
                current_flow.pcap_packet.flow_id = json_dict['flow_id']

            elif PcapPacket.isInitialized(current_flow) is not True:

                pass

            elif json_dict['flow_event_name'] == 'end' or json_dict['flow_event_name'] == 'idle':

                try:
                    current_flow.pcap_packet.fin()
                except RuntimeError:
                    pass

        elif PcapPacket.isInitialized(current_flow) is True and \
             ('packet_event_name' in json_dict and json_dict['packet_event_name'] == 'packet-flow' and current_flow.pcap_packet.flow_id > 0) or \
             ('packet_event_name' in json_dict and json_dict['packet_event_name'] == 'packet' and 'pkt' in json_dict):

            buffer_decoded = base64.b64decode(json_dict['pkt'], validate=True)
            current_flow.pcap_packet.packets += [ ( buffer_decoded, json_dict['pkt_type'], json_dict['pkt_l3_offset'] ) ]
            current_flow.pcap_packet.current_packet += 1

            if current_flow.pcap_packet.current_packet != int(json_dict['flow_packet_id']):
                raise RuntimeError('Packet IDs not in sync (local: {}, remote: {}).'.format(current_flow.pcap_packet.current_packet, int(json_dict['flow_packet_id'])))

    @staticmethod
    def getIp(packet):
        if packet[1] == PKT_TYPE_ETH_IP4:
            return scapy.all.IP(packet[0][packet[2]:])
        elif packet[1] == PKT_TYPE_ETH_IP6:
            return scapy.all.IPv6(packet[0][packet[2]:])
        else:
            raise RuntimeError('packet type unknown: {}'.format(packet[1]))

    @staticmethod
    def getTCPorUDP(packet):
        p = PcapPacket.getIp(packet)
        if p.haslayer(scapy.all.TCP):
            return p.getlayer(scapy.all.TCP)
        elif p.haslayer(scapy.all.UDP):
            return p.getlayer(scapy.all.UDP)
        else:
            return None

    def setSuffix(self, filename_suffix):
        self.__suffix = filename_suffix

    def doDump(self):
        self.__dump = True

    def fin(self):
        if self.__dumped is True:
            raise RuntimeError('Flow {} already dumped.'.format(self.flow_id))
        if self.__dump is False:
            raise RuntimeError('Flow {} should not be dumped.'.format(self.flow_id))

        emptyTCPorUDPcount = 0;
        for packet in self.packets:
            p = PcapPacket.getTCPorUDP(packet)
            if p is not None:
                if p.haslayer(scapy.all.Padding) and len(p.payload) - len(p[scapy.all.Padding]) == 0:
                    emptyTCPorUDPcount += 1
                elif len(p.payload) == 0:
                    emptyTCPorUDPcount += 1

        if emptyTCPorUDPcount == len(self.packets):
            raise RuntimeError('Flow {} does not contain any packets({}) with non-empty layer4 payload.'.format(self.flow_id, len(self.packets)))

        if self.pktdump is None:
            if self.flow_id == 0:
                self.pktdump = scapy.all.PcapWriter('packet-{}.pcap'.format(self.__suffix),
                                                    append=True, sync=True)
            else:
                self.pktdump = scapy.all.PcapWriter('flow-{}-{}.pcap'.format(self.__suffix, self.flow_id),
                                                    append=False, sync=True)

        for packet in self.packets:
            self.pktdump.write(PcapPacket.getIp(packet))

        self.pktdump.close()
        self.__dumped = True

        return True

def defaultArgumentParser():
    parser = argparse.ArgumentParser(description='nDPIsrvd options', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--host', type=str, help='nDPIsrvd host IP')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='nDPIsrvd TCP port')
    parser.add_argument('--unix', type=str, help='nDPIsrvd unix socket path')
    return parser

def validateAddress(args):
    tcp_addr_set = False
    address = None

    if args.host is None:
        address_tcpip = (DEFAULT_HOST, DEFAULT_PORT)
    else:
        address_tcpip = (args.host, args.port)
        tcp_addr_set = True

    if args.unix is None:
        address_unix = DEFAULT_UNIX
    else:
        address_unix = args.unix

    possible_sock_mode = 0
    try:
        possible_sock_mode = os.stat(address_unix).st_mode
    except:
        pass
    if tcp_addr_set == False and stat.S_ISSOCK(possible_sock_mode):
        address = address_unix
    else:
        address = address_tcpip

    return address

global schema
schema = {'packet_event_schema' : None, 'basic_event_schema' : None, 'daemon_event_schema' : None, 'flow_event_schema' : None}

def initSchemaValidator(schema_dir='./schema'):
    for key in schema:
        with open(schema_dir + '/' + str(key) + '.json', 'r') as schema_file:
            schema[key] = json.load(schema_file)

def validateAgainstSchema(json_dict):
    import jsonschema

    if 'packet_event_id' in json_dict:
        jsonschema.validate(instance=json_dict, schema=schema['packet_event_schema'])
        return True
    if 'basic_event_id' in json_dict:
        jsonschema.validate(instance=json_dict, schema=schema['basic_event_schema'])
        return True
    if 'daemon_event_id' in json_dict:
        jsonschema.validate(instance=json_dict, schema=schema['daemon_event_schema'])
        return True
    if 'flow_event_id' in json_dict:
        jsonschema.validate(instance=json_dict, schema=schema['flow_event_schema'])
        return True

    return False
