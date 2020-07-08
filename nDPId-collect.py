#!/usr/bin/env python3

import sys
import asyncio

JSON_SOCKPATH = '/tmp/ndpid-collector.sock'

class EchoServer(asyncio.Protocol):
    def connection_made(self, transport):
        sys.stderr.write('New Connection.\n')
        self.transport = transport

    def data_received(self, data):
        message = data.decode()
        print('{!r}'.format(message))

loop = asyncio.get_event_loop()
coro = loop.create_unix_server(EchoServer, JSON_SOCKPATH)
server = loop.run_until_complete(coro)
sys.stderr.write('Serving on {}\n'.format(server.sockets[0].getsockname()))
loop.run_forever()
