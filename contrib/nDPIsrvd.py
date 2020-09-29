#!/usr/bin/env python3

import argparse
import json
import re
import os
import scapy.all
import stat
import socket

DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 7000
DEFAULT_UNIX = '/tmp/ndpid-distributor.sock'

NETWORK_BUFFER_MIN_SIZE = 5
NETWORK_BUFFER_MAX_SIZE = 9216 # Please keep this value in sync with the one in config.h

PKT_TYPE_ETH_IP4 = 0x0800
PKT_TYPE_ETH_IP6 = 0x86DD

EVENT_UNKNOWN = 'Unknown'
DAEMON_EVENTS = ['Invalid', 'Init', 'Reconnect', 'Shutdown']
BASIC_EVENTS = ['Invalid', 'Unknown-Datalink-Layer', 'Unknown-Layer3-Protocol', 'Non-IP-Packet',
                'Ethernet-Packet-Too-Short', 'Ethernet-Packet-Unknown', 'IP4-Packet-Too-Short',
                'IP4-Size-Smaller-Than-Header', 'IP4-Layer4-Payload-Detection-Failed', 'IP6-Packet-Too-Short',
                'IP6-Size-Smaller-Than-Header', 'IP6-Layer4-Payload-Detection-Failed', 'TCP-Packet-Too-Short',
                'UDP-Packet-Too-Short', 'Capture-Size-Smaller-Than-Packet-Size', 'Max-Flow-To-Track',
                'Flow-Memory-Allocation-Failed', 'NDPI-Flow-Memory-Allocation-Failed',
                'NDPI-ID-Memory-Allocation-Failed']
PACKET_EVENTS = ['Invalid', 'Packet', 'Packet-Flow']
FLOW_EVENTS = ['Invalid', 'New', 'End', 'Idle', 'Guessed', 'Detected', 'Detection-Update', 'Not-Detected']

class TermColor:
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'
    BLINK = "\x1b[5m"

class nDPIsrvdSocket:
    def __init__(self):
        self.sock_family = None

    def connect(self, addr):
        if type(addr) is tuple:
            self.sock_family = socket.AF_INET
        elif type(addr) is str:
            self.sock_family = socket.AF_UNIX
        else:
            raise RuntimeError('Unsupported address type:: {}'.format(str(addr)))

        self.sock = socket.socket(self.sock_family, socket.SOCK_STREAM)
        self.sock.connect(addr)
        self.buffer = bytes()
        self.msglen = 0
        self.digitlen = 0

    def receive(self):
        recvd = self.sock.recv(NETWORK_BUFFER_MAX_SIZE - len(self.buffer))

        if len(recvd) == 0:
            raise RuntimeError('socket connection broken')
        self.buffer += recvd

        retval = []
        while self.msglen + self.digitlen < len(self.buffer):

            if self.msglen == 0:
                starts_with_digits = re.match(r'(^\d+){', self.buffer[:NETWORK_BUFFER_MIN_SIZE].decode(errors='strict'))
                if starts_with_digits is None:
                    if len(self.buffer) < NETWORK_BUFFER_MIN_SIZE:
                        break
                    raise RuntimeError('Invalid packet received: {}'.format(self.buffer))
                self.msglen = int(starts_with_digits[1])
                self.digitlen = len(starts_with_digits[1])

            if len(self.buffer) >= self.msglen + self.digitlen:
                recvd = self.buffer[self.digitlen:self.msglen + self.digitlen]
                self.buffer = self.buffer[self.msglen + self.digitlen:]
                retval += [(recvd,self.msglen,self.digitlen)]

                self.msglen = 0
                self.digitlen = 0

        return retval

class PcapPacket:
    def __init__(self, flow_id=-1):
        self.pktdump = None
        self.was_dumped = False
        self.was_detected = False
        self.flow_id = flow_id
        self.packets = []

    def addPacket(self, pkt, pkt_type, pkt_ipoffset):
        self.packets += [ ( pkt, pkt_type, pkt_ipoffset ) ]

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

    def detected(self):
        self.was_detected = True

    def fin(self, filename_suffix):
        if self.was_dumped is True:
            return 'Flow already dumped.'
        if self.was_detected is True:
            return 'Flow detected.'

        emptyTCPorUDPcount = 0;
        for packet in self.packets:
            p = PcapPacket.getTCPorUDP(packet)
            if p is not None:
                if p.haslayer(scapy.all.Padding) and len(p.payload) - len(p[scapy.all.Padding]) == 0:
                    emptyTCPorUDPcount += 1
                if len(p.payload) == 0:
                    emptyTCPorUDPcount += 1

        if emptyTCPorUDPcount == len(self.packets):
            return 'Flow does not contain any packets with non-empty layer4 payload.'

        if self.pktdump is None:
            if self.flow_id == -1:
                self.pktdump = scapy.all.PcapWriter('packet-{}.pcap'.format(filename_suffix),
                                                    append=True, sync=True)
            else:
                self.pktdump = scapy.all.PcapWriter('flow-{}-{}.pcap'.format(filename_suffix, self.flow_id),
                                                    append=False, sync=True)

        for packet in self.packets:
            self.pktdump.write(PcapPacket.getIp(packet))

        self.pktdump.close()
        self.was_dumped = True

        return 'Success.'

def JsonParseBytes(json_bytes):
    return json.loads(json_bytes.decode('ascii', errors='replace'), strict=False)

class nDPIdEvent:
    isValid = False
    DaemonEventID = -1
    DaemonEventName = EVENT_UNKNOWN
    BasicEventID = -1
    BasicEventName = EVENT_UNKNOWN
    PacketEventID = -1
    PacketEventName = EVENT_UNKNOWN
    FlowEventID = -1
    FlowEventName = EVENT_UNKNOWN

def validateFlowEventID(event_id):
    if type(event_id) is not int:
        raise RuntimeError('Argument is not an Integer/EventID!')

    if event_id < 0 or event_id > len(FLOW_EVENTS):
        raise RuntimeError('Unknown flow event id: {}.'.format(event_id))
    else:
        event_str = FLOW_EVENTS[event_id]

    return event_str

def validatePacketEventID(event_id):
    if type(event_id) is not int:
        raise RuntimeError('Argument is not an Integer/EventID!')

    if event_id < 0 or event_id > len(PACKET_EVENTS):
        raise RuntimeError('Unknown packet event id: {}.'.format(event_id))
    else:
        event_str = PACKET_EVENTS[event_id]

    return event_str

def validateBasicEventID(event_id):
    if type(event_id) is not int:
        raise RuntimeError('Argument is not an Integer/EventID!')

    if event_id < 0 or event_id > len(BASIC_EVENTS):
        raise RuntimeError('Unknown basic event id: {}.'.format(event_id))
    else:
        event_str = BASIC_EVENTS[event_id]

    return event_str

def validateDaemonEventID(event_id):
    if type(event_id) is not int:
        raise RuntimeError('Argument is not an Integer/EventID!')

    if event_id < 0 or event_id > len(DAEMON_EVENTS):
        raise RuntimeError('Unknown daemon event id: {}.'.format(event_id))
    else:
        event_str = DAEMON_EVENTS[event_id]

    return event_str

def validateJsonEventTypes(json_dict):
    if type(json_dict) is not dict:
        raise RuntimeError('Argument is not a dictionary!')

    nev = nDPIdEvent()

    if 'daemon_event_id' in json_dict:
        nev.DaemonEventID = json_dict['daemon_event_id']
        nev.DaemonEventName = validateDaemonEventID(nev.DaemonEventID)
        nev.isValid = True
    if 'basic_event_id' in json_dict:
        nev.BasicEventID = json_dict['basic_event_id']
        nev.BasicEventName = validateBasicEventID(nev.BasicEventID)
        nev.isValid = True
    if 'packet_event_id' in json_dict:
        nev.PacketEventID = json_dict['packet_event_id']
        nev.PacketEventName = validatePacketEventID(nev.PacketEventID)
        nev.isValid = True
    if 'flow_event_id' in json_dict:
        nev.FlowEventID = json_dict['flow_event_id']
        nev.FlowEventName = validateFlowEventID(nev.FlowEventID)
        nev.isValid = True

    return nev

def defaultArgumentParser():
    parser = argparse.ArgumentParser(description='nDPIsrvd options', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--host', type=str, help='nDPIsrvd host IP')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='nDPIsrvd TCP port')
    parser.add_argument('--unix', type=str, help='nDPIsrvd unix socket path')
    return parser

def validateAddress(args):
    address = None

    if args.host is None:
        address_tcpip = (DEFAULT_HOST, DEFAULT_PORT)
    else:
        address_tcpip = (args.host, args.port)

    if args.unix is None:
        address_unix = DEFAULT_UNIX
    else:
        address_unix = args.unix

    possible_sock_mode = 0
    try:
        possible_sock_mode = os.stat(address_unix).st_mode
    except:
        pass
    if stat.S_ISSOCK(possible_sock_mode):
        address = address_unix
    else:
        address = address_tcpip

    return address
