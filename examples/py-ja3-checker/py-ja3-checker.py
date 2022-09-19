#!/usr/bin/env python3

import io
import json
import os
import pandas
import requests
import sys
import time

sys.path.append(os.path.dirname(sys.argv[0]) + '/../../dependencies')
sys.path.append(os.path.dirname(sys.argv[0]) + '/../share/nDPId')
sys.path.append(os.path.dirname(sys.argv[0]))
sys.path.append(sys.base_prefix + '/share/nDPId')
import nDPIsrvd
from nDPIsrvd import nDPIsrvdSocket

global ja3_fps
ja3_fps = dict()
# 1 hour = 3600 sec/hour = (60 minutes/hour) * (60 seconds/minute)
JA3_FP_MAX_AGE = 60 * 60

global ja3_bl
ja3_bl = None

global ja3_bl_printed
ja3_bl_printed = dict()


def downloadJA3Blacklist():
    response = requests.get(
        'https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv'
    )
    if response.status_code == 200:
        global ja3_bl
        ja3_bl = pandas.read_csv(io.StringIO(response.text), header=9)
        return True
    return False


def getBlacklisted(ja3_hash):
    global ja3_bl
    return ja3_bl[(ja3_bl['# ja3_md5'] == ja3_hash)]


def checkBlacklisted(ja3_hash):
    if ja3_bl is None:
        return
    csv_entry = getBlacklisted(ja3_hash)
    if not csv_entry.empty and ja3_hash not in ja3_bl_printed:
        print('Found CSV JA3 blacklist entry:')
        print(csv_entry)
        ja3_bl_printed[ja3_hash] = True


class JA3ER(object):
    def __init__(self, json_dict):
        self.json = json_dict
        self.last_checked = time.time()

    def isTooOld(self):
        current_time = time.time()
        if current_time - self.last_checked >= JA3_FP_MAX_AGE:
            return True
        return False


def isJA3InfoTooOld(ja3_hash):
    global ja3_fps
    if ja3_hash in ja3_fps:
        if ja3_fps[ja3_hash].isTooOld() is True:
            print('Fingerprint {} too old, re-newing..'.format(ja3_hash))
            return True
    else:
        return True

    return False


def getInfoFromJA3ER(ja3_hash):
    global ja3_fps
    response = requests.get('https://ja3er.com/search/' + ja3_hash)
    if response.status_code == 200:
        ja3_fps[ja3_hash] = JA3ER(json.loads(response.text, strict=True))
        if 'error' not in ja3_fps[ja3_hash].json:
            print('Fingerprints for JA3 {}:'.format(ja3_hash))
            for ua in ja3_fps[ja3_hash].json:
                if 'User-Agent' in ua:
                    print('\tUser-Agent: {}\n'
                          '\t            Last seen: {}, '
                          'Count: {}'.format(ua['User-Agent'],
                                             ua['Last_seen'],
                                             ua['Count']))
                elif 'Comment' in ua:
                    print('\tComment...: {}\n'
                          '\t            Reported: {}'
                          .format(ua['Comment'].replace('\r', '')
                                  .replace('\n', ' '), ua['Reported']))
                else:
                    print(ua)
        else:
            print('No fingerprint for JA3 {} found.'.format(ja3_hash))


def onJsonLineRecvd(json_dict, instance, current_flow, global_user_data):
    if 'tls' in json_dict and 'ja3' in json_dict['tls']:

        if json_dict['tls']['client_requested_server_name'] == 'ja3er.com':
            return True

        if isJA3InfoTooOld(json_dict['tls']['ja3']) is True:
            getInfoFromJA3ER(json_dict['tls']['ja3'])

        if isJA3InfoTooOld(json_dict['tls']['ja3']) is True:
            getInfoFromJA3ER(json_dict['tls']['ja3s'])

        checkBlacklisted(json_dict['tls']['ja3'])

    return True


if __name__ == '__main__':
    argparser = nDPIsrvd.defaultArgumentParser()
    args = argparser.parse_args()
    address = nDPIsrvd.validateAddress(args)

    sys.stderr.write('Recv buffer size: {}\n'
                     .format(nDPIsrvd.NETWORK_BUFFER_MAX_SIZE))
    sys.stderr.write('Connecting to {} ..\n'
                     .format(address[0] + ':' +
                             str(address[1])
                             if type(address) is tuple else address))

    if downloadJA3Blacklist() is False:
        print('Could not download JA3 blacklist.')
    nsock = nDPIsrvdSocket()
    nsock.connect(address)
    try:
        nsock.loop(onJsonLineRecvd, None, None)
    except nDPIsrvd.SocketConnectionBroken as err:
        sys.stderr.write('\n{}\n'.format(err))
    except KeyboardInterrupt:
        print()
