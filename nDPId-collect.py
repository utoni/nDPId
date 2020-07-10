#!/usr/bin/env python3

import json
import sys
import asyncio

JSON_SOCKPATH = '/tmp/ndpid-collector.sock'
JSON_FILTER = []

def json_filter_add(key, value):
    global JSON_FILTER
    JSON_FILTER += [ (key, value) ]

def json_filter_check(json_object):
    global JSON_FILTER
    if len(JSON_FILTER) == 0:
        return True
    for (key, value) in JSON_FILTER:
        if key in json_object:
            if value is None:
                return True
            if str(json_object[key]) == str(value):
                return True
    return False

class JsonCollector(asyncio.Protocol):
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
                if json_filter_check(json_object) is False:
                    continue
                line = json.dumps(json_object, indent=2)
            except json.decoder.JSONDecodeError as err:
                sys.stderr.write('{}\n  ERROR: {} -> {!r}\n{}\n'.format('-'*64, str(err), str(line), '-'*64))
                return
            print('{}'.format(line))


def main():
    for arg in sys.argv[1:]:
        kv = arg.split('=')
        if len(kv) == 1:
            json_filter_add(kv[0], None)
        elif len(kv) == 2:
            json_filter_add(kv[0], kv[1])
        else:
            sys.stderr.write('JSON filter format invalid for argument "{}", required format: either "key" or "key=value"\n'.format(str(arg)))
            sys.exit(1)

    loop = asyncio.get_event_loop()
    coro = loop.create_unix_server(JsonCollector, JSON_SOCKPATH)
    server = loop.run_until_complete(coro)
    sys.stderr.write('Serving on {}\n'.format(server.sockets[0].getsockname()))
    loop.run_forever()

main()
