#!/usr/bin/env python3

# pip3 install -U scikit-learn scipy matplotlib

import os
import sklearn
import sklearn.ensemble
import sys

sys.path.append(os.path.dirname(sys.argv[0]) + '/../../dependencies')
sys.path.append(os.path.dirname(sys.argv[0]) + '/../share/nDPId')
sys.path.append(os.path.dirname(sys.argv[0]))
sys.path.append(sys.base_prefix + '/share/nDPId')
import nDPIsrvd
from nDPIsrvd import nDPIsrvdSocket, TermColor

class RFC(sklearn.ensemble.RandomForestClassifier):
    def __init__(self, max_samples):
        self.max_samples = max_samples
        self.samples_x = []
        self.samples_y = []
        super().__init__(verbose=1, n_estimators=1000, max_samples=max_samples)

    def addSample(self, x, y):
        self.samples_x += x
        self.samples_y += y

    def fit(self):
        if len(self.samples_x) != self.max_samples or \
           len(self.samples_y) != self.max_samples:
            return False

        super().fit(self.samples_x, self.samples_y)
        self.samples_x = []
        self.samples_y = []
        return True

def onJsonLineRecvd(json_dict, instance, current_flow, global_user_data):
    if 'flow_event_name' not in json_dict:
        return True
    if json_dict['flow_event_name'] != 'analyse':
        return True

    if 'ndpi' not in json_dict:
        return True
    if 'proto' not in json_dict['ndpi']:
        return True

    #print(json_dict)

    features = [[]]
    features[0] += json_dict['data_analysis']['bins']['c_to_s']
    features[0] += json_dict['data_analysis']['bins']['s_to_c']
    #print(features)

    out = ''
    rfc = global_user_data
    try:
        out += '[Predict: {}]'.format(rfc.predict(features)[0])
    except sklearn.exceptions.NotFittedError:
        pass

    # TLS.DoH_DoT
    if json_dict['ndpi']['proto'].startswith('TLS.') is not True and \
       json_dict['ndpi']['proto'] != 'TLS':
        rfc.addSample(features, [0])
    else:
        rfc.addSample(features, [1])

    if rfc.fit() is True:
        out += '*** FIT *** '
    out += '[{}]'.format(json_dict['ndpi']['proto'])
    print(out)

    return True

if __name__ == '__main__':
    argparser = nDPIsrvd.defaultArgumentParser()
    args = argparser.parse_args()
    address = nDPIsrvd.validateAddress(args)

    sys.stderr.write('Recv buffer size: {}\n'.format(nDPIsrvd.NETWORK_BUFFER_MAX_SIZE))
    sys.stderr.write('Connecting to {} ..\n'.format(address[0]+':'+str(address[1]) if type(address) is tuple else address))

    rfc = RFC(10)

    nsock = nDPIsrvdSocket()
    nsock.connect(address)
    nsock.loop(onJsonLineRecvd, None, rfc)
