#!/usr/bin/env python3

import csv
import numpy
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


N_DIRS = 0
N_BINS = 0

ENABLE_FEATURE_IAT    = True
ENABLE_FEATURE_PKTLEN = True
ENABLE_FEATURE_DIRS   = True
ENABLE_FEATURE_BINS   = True

def getFeatures(json):
    return [json['flow_src_packets_processed'],
            json['flow_dst_packets_processed'],
            json['flow_src_tot_l4_payload_len'],
            json['flow_dst_tot_l4_payload_len']]

def getFeaturesFromArray(json, expected_len=0):
    if type(json) is str:
        dirs = numpy.fromstring(json, sep=',', dtype=int)
        dirs = numpy.asarray(dirs, dtype=int).tolist()
    elif type(json) is list:
        dirs = json
    else:
        raise TypeError('Invalid type: {}.'.format(type(json)))

    if expected_len > 0 and len(dirs) != expected_len:
        raise RuntimeError('Invalid array length; Expected {}, Got {}.'.format(expected_len, len(dirs)))

    return dirs

def getRelevantFeaturesCSV(line):
    return [
             getFeatures(line) + \
             getFeaturesFromArray(line['iat_data'], N_DIRS - 1) if ENABLE_FEATURE_IAT is True else [] + \
             getFeaturesFromArray(line['pktlen_data'], N_DIRS) if ENABLE_FEATURE_PKTLEN is True else [] + \
             getFeaturesFromArray(line['directions'], N_DIRS) if ENABLE_FEATURE_DIRS is True else [] + \
             getFeaturesFromArray(line['bins_c_to_s'], N_BINS) if ENABLE_FEATURE_BINS is True else [] + \
             getFeaturesFromArray(line['bins_s_to_c'], N_BINS) if ENABLE_FEATURE_BINS is True else [] + \
             []
           ]

def getRelevantFeaturesJSON(line):
    return [
              getFeatures(line) + \
              getFeaturesFromArray(line['data_analysis']['iat']['data'], N_DIRS - 1) if ENABLE_FEATURE_IAT is True else [] + \
              getFeaturesFromArray(line['data_analysis']['pktlen']['data'], N_DIRS) if ENABLE_FEATURE_PKTLEN is True else [] + \
              getFeaturesFromArray(line['data_analysis']['directions'], N_DIRS) if ENABLE_FEATURE_DIRS is True else [] + \
              getFeaturesFromArray(line['data_analysis']['bins']['c_to_s'], N_BINS) if ENABLE_FEATURE_BINS is True else [] + \
              getFeaturesFromArray(line['data_analysis']['bins']['s_to_c'], N_BINS) if ENABLE_FEATURE_BINS is True else [] + \
              []
           ]

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

    model, = global_user_data

    try:
        print('DPI Engine detected: "{}", Prediction: "{}"'.format(
              json_dict['ndpi']['proto'], model.predict(getRelevantFeaturesJSON(json_dict))))
    except Exception as err:
        print('Got exception `{}\'\nfor json: {}'.format(err, json_dict))

    return True


if __name__ == '__main__':
    argparser = nDPIsrvd.defaultArgumentParser()
    argparser.add_argument('--csv', action='store', required=True,
                           help='Input CSV file generated with nDPIsrvd-analysed.')
    argparser.add_argument('--proto-class', action='store', required=True,
                           help='nDPId protocol class of interest, used for training and prediction. Example: tls.youtube')
    argparser.add_argument('--enable-iat', action='store', default=True,
                           help='Use packet (I)nter (A)rrival (T)ime for learning and prediction.')
    argparser.add_argument('--enable-pktlen', action='store', default=False,
                           help='Use layer 4 packet lengths for learning and prediction.')
    argparser.add_argument('--enable-dirs', action='store', default=True,
                           help='Use packet directions for learning and prediction.')
    argparser.add_argument('--enable-bins', action='store', default=True,
                           help='Use packet length distribution for learning and prediction.')
    args = argparser.parse_args()
    address = nDPIsrvd.validateAddress(args)

    ENABLE_FEATURE_IAT    = args.enable_iat
    ENABLE_FEATURE_PKTLEN = args.enable_pktlen
    ENABLE_FEATURE_DIRS   = args.enable_dirs
    ENABLE_FEATURE_BINS   = args.enable_bins

    sys.stderr.write('Recv buffer size: {}\n'.format(nDPIsrvd.NETWORK_BUFFER_MAX_SIZE))
    sys.stderr.write('Connecting to {} ..\n'.format(address[0]+':'+str(address[1]) if type(address) is tuple else address))

    sys.stderr.write('Learning via CSV..\n')
    with open(args.csv, newline='\n') as csvfile:
        reader = csv.DictReader(csvfile, delimiter=',', quotechar='"')
        X = list()
        y = list()

        for line in reader:
            N_DIRS = len(getFeaturesFromArray(line['directions']))
            N_BINS = len(getFeaturesFromArray(line['bins_c_to_s']))
            break

        for line in reader:
            try:
                X += getRelevantFeaturesCSV(line)
                y += [1 if line['proto'].lower().startswith(args.proto_class) is True else 0]
            except RuntimeError as err:
                print('Error: `{}\'\non line: {}'.format(err, line))

        model = sklearn.ensemble.RandomForestClassifier()
        model.fit(X, y)

    sys.stderr.write('Predicting realtime traffic..\n')
    nsock = nDPIsrvdSocket()
    nsock.connect(address)
    nsock.loop(onJsonLineRecvd, None, (model,))
