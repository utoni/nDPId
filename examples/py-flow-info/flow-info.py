#!/usr/bin/env python3

import json
import re
import sys
import socket

HOST = '127.0.0.1'
PORT = 7000
NETWORK_BUFFER_MAX_SIZE = 8192

class nDPIsrvdSocket:
    def __init__(self, sock=None):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self, host, port):
        self.sock.connect((host, port))
        self.buffer = str()
        self.msglen = 0
        self.digitlen = 0

    def receive(self):
        recvd = self.sock.recv(NETWORK_BUFFER_MAX_SIZE - len(self.buffer)).decode(errors='strict')
        if recvd == '':
            raise RuntimeError('socket connection broken')
        self.buffer += recvd

        retval = []
        while self.msglen + self.digitlen < len(self.buffer):

            if self.msglen == 0:
                starts_with_digits = re.match(r'(^\d+){', self.buffer)
                if starts_with_digits is None:
                    break
                self.msglen = int(starts_with_digits[1])
                self.digitlen = len(starts_with_digits[1])

            if len(self.buffer) >= self.msglen + self.digitlen:
                recvd = self.buffer[self.digitlen:self.msglen + self.digitlen]
                self.buffer = self.buffer[self.msglen + self.digitlen:]
                self.msglen = 0
                self.digitlen = 0
                retval += [recvd]

        return retval

def parse_json_str(json_str):

    j = json.loads(json_str)

    if 'flow_event_name' in j:
        event = j['flow_event_name'].lower()
        if event == 'new':
            event_str = 'New flow'
        elif event == 'end':
            event_str = 'End flow'
        elif event == 'idle':
            event_str = 'Idle flow'
        elif event == 'detected':
            event_str = 'Detected flow'
        elif event == 'guessed':
            event_str = 'Guessed'
        elif event == 'not-detected':
            event_str = 'Not detected'
        else:
            raise RuntimeError('unknown flow event name: {}'.format(event))

        if j['l3_proto'] == 'ip4':
            print('{:>14}: [{:>8}] [{}][{:>5}] [{:>15}][{:>5}] -> [{:>15}][{:>5}]'.format(event_str,
                  j['flow_id'], j['l3_proto'], j['l4_proto'],
                  j['src_ip'].lower(),
                  j['src_port'] if 'src_port' in j else '',
                  j['dst_ip'].lower(),
                  j['dst_port'] if 'dst_port' in j else ''))
        elif j['l3_proto'] == 'ip6':
            print('{:>14}: [{:>8}] [{}][{:>5}] [{:>39}][{:>5}] -> [{:>39}][{:>5}]'.format(event_str,
                  j['flow_id'], j['l3_proto'], j['l4_proto'],
                  j['src_ip'].lower(),
                  j['src_port'] if 'src_port' in j else '',
                  j['dst_ip'].lower(),
                  j['dst_port'] if 'dst_port' in j else ''))
        else:
            raise RuntimeError('unsupported l3 protocol: {}'.format(j['l3_proto']))


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
        for line in received:
            #print(line)
            parse_json_str(line)

