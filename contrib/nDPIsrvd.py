#!/usr/bin/env python3

import json
import re
import scapy.all
import socket

DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 7000
NETWORK_BUFFER_MIN_SIZE = 5
NETWORK_BUFFER_MAX_SIZE = 9216 # Please keep this value in sync with the one in config.h

PKT_TYPE_ETH_IP4 = 0x0800
PKT_TYPE_ETH_IP6 = 0x86DD

class TermColor:
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'
    BLINK = "\x1b[5m"

class nDPIsrvdSocket:
    def __init__(self, sock=None):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self, host, port):
        self.sock.connect((host, port))
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

def validateEventName(json_dict):
    if type(json_dict) is not dict:
        raise RuntimeError('Argument is not a dictionary!')

    event_str = None

    if 'flow_event_name' in json_dict:
        event = j['flow_event_name'].lower()
        if event == 'new':
            event_str = 'New flow'
        elif event == 'end':
            event_str = 'End flow'
        elif event == 'idle':
            event_str = 'Idle flow'
        elif event == 'detected':
            event_str = 'Detected'
        elif event == 'detection-update':
            event_str = 'Update'
        elif event == 'guessed':
            event_str = 'Guessed'
        elif event == 'not-detected':
            event_str = 'Not detected'
        else:
            return None

    return event_str
