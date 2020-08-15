#!/usr/bin/env python3

import re
import socket

DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 7000
NETWORK_BUFFER_MIN_SIZE = 5
NETWORK_BUFFER_MAX_SIZE = 8448

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
