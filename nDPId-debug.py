#!/usr/bin/env python3

import json
import sys
import asyncio
import base64

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

class nDPIdFlow(object):
    def __init__(self, thread_id):
        self.thread_id = thread_id

class JsonCollector(asyncio.Protocol):
    def log_key_error(self, exception):
        sys.stderr.write('ERROR: {}'.format(str(exception)))

    def add_flow(self, json_object):
        try:
            thread_id = json_object['thread_id']
            flow_id = str(json_object['flow_id'])
            self.flows[flow_id] = nDPIdFlow(thread_id)
        except KeyError as exc:
            self.log_key_error(exc)

    def del_flow(self, json_object):
        try:
            flow_id = str(json_object['flow_id'])
            del self.flows[flow_id]
        except KeyError as exc:
            self.log_key_error(exc)

    def cleanup(self, json_object):
        try:
            thread_id = json_object['thread_id']
        except KeyError:
            return
        for flow_id in self.flows:
            if self.flows[flow_id].thread_id == thread_id:
                self.flows[flow_id] = None

    def connection_made(self, transport):
        sys.stderr.write('New Connection.\n')
        self.transport = transport
        self.flows = {}

    def data_received(self, data):
        message = data.decode()
        out = str()
        for line in message.split('\n'):
            if len(line) == 0:
                continue
            try:
                json_object = json.loads(line)

                if 'init_complete' in json_object:
                    self.cleanup(json_object)
                if 'flow_event_name' in json_object:
                    if json_object['flow_event_name'] == 'new':
                        self.add_flow(json_object)
                    elif json_object['flow_event_name'] == 'end':
                        self.del_flow(json_object)
                    elif json_object['flow_event_name'] == 'idle':
                        self.del_flow(json_object)

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
