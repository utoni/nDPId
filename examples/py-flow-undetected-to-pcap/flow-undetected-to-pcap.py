#!/usr/bin/env python3

import base64
import json
import re
import sys
import socket
import scapy.all

HOST = '127.0.0.1'
PORT = 7000
NETWORK_BUFFER_MIN_SIZE = 5
NETWORK_BUFFER_MAX_SIZE = 8192

FLOWS = dict()

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

        if recvd == '':
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

class Flow:
    def __init__(self, flow_id=-1):
        self.pktdump = None
        self.was_dumped = False
        self.was_detected = False
        self.flow_id = flow_id
        self.packets = []

    def addPacket(self, pkt):
        self.packets += [pkt]

    def detected(self):
        self.was_detected = True

    def fin(self):
        if self.was_dumped is True:
            return
        if self.was_detected is True:
            return

        if self.pktdump is None:
            if self.flow_id == -1:
                self.pktdump = scapy.all.PcapWriter('packet-undetected.pcap', append=True, sync=True)
            else:
                self.pktdump = scapy.all.PcapWriter('flow-undetected-{}.pcap'.format(self.flow_id), append=False, sync=True)

        for packet in self.packets:
            self.pktdump.write(scapy.all.Raw(packet))

        self.pktdump.close()
        self.was_dumped = True

def parse_json_str(json_str):

    try:
        j = json.loads(json_str[0])
    except json.decoder.JSONDecodeError as exc:
        raise RuntimeError('JSON Exception: {}\n\nJSON String: {}\n'.format(str(exc), str(json_str)))

    global FLOWS

    if 'flow_event_name' in j:

        event = j['flow_event_name'].lower()
        flow_id = j['flow_id']

        if 'midstream' in j and j['midstream'] == 1:
            return

        if event == 'new':
            print('New flow with id {}.'.format(flow_id))
            FLOWS[flow_id] = Flow(flow_id)
        elif flow_id not in FLOWS:
            print('Ignore flow event with id {} as we did not get any flow-new event.'.format(flow_id))
            return
        elif event == 'end' or event == 'idle':
            if event == 'end':
                print('End flow with id {}.'.format(flow_id))
            elif event == 'idle':
                print('Idle flow with id {}.'.format(flow_id))
            FLOWS[flow_id].fin()
            del FLOWS[flow_id]
        elif event == 'detected':
            FLOWS[flow_id].detected()
        elif event == 'guessed' or event == 'not-detected':
            if event == 'guessed':
                print('Guessed flow with id {}.'.format(flow_id))
            else:
                print('Not-detected flow with id {}.'.format(flow_id))
            FLOWS[flow_id].fin()
        else:
            raise RuntimeError('unknown flow event name: {}'.format(event))

    elif 'packet_event_name' in j:

        buffer_decoded = base64.b64decode(j['pkt'], validate=True)

        if j['packet_event_name'] == 'packet-flow':

            flow_id = j['flow_id']

            if flow_id not in FLOWS:
                return

            FLOWS[flow_id].addPacket(buffer_decoded)

        if j['packet_event_name'] == 'packet':

            flow = Flow()
            flow.addPacket(buffer_decoded)


if __name__ == '__main__':
    host = HOST
    port = PORT

    if len(sys.argv) == 1:
        sys.stderr.write('usage: {} [host] [port]\n'.format(sys.argv[0]))
    if len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port = int(sys.argv[2])

    sys.stderr.write('Recv buffer size: {}\n'.format(NETWORK_BUFFER_MAX_SIZE))
    sys.stderr.write('Connecting to {}:{} ..\n'.format(host, port))

    nsock = nDPIsrvdSocket()
    nsock.connect(host, port)

    while True:
        received = nsock.receive()
        for received_json_pkt in received:
            parse_json_str(received_json_pkt)

