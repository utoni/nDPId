#!/usr/bin/env python3

import json
import sys
import asyncio

JSON_SOCKPATH = '/tmp/ndpid-collector.sock'

class EchoServer(asyncio.Protocol):
    def connection_made(self, transport):
        sys.stderr.write('New Connection.\n')
        self.transport = transport

    def data_received(self, data):
        message = data.decode()
        out = str()
        for line in message.split('\n'):
            if len(line) == 0:
                continue
            try:
                json_object = json.loads(line)
                line = json.dumps(json_object, indent=2)
            except json.decoder.JSONDecodeError as err:
                sys.stderr.write('{}\n  ERROR: {} -> {!r}\n{}\n'.format('-'*64, str(err), str(line), '-'*64))
                return
            print('{}'.format(line))

loop = asyncio.get_event_loop()
coro = loop.create_unix_server(EchoServer, JSON_SOCKPATH)
server = loop.run_until_complete(coro)
sys.stderr.write('Serving on {}\n'.format(server.sockets[0].getsockname()))
loop.run_forever()
