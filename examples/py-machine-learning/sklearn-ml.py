#!/usr/bin/env python3

import csv
import matplotlib.pyplot
import numpy
import os
import pandas
import sklearn
import sklearn.ensemble
import sklearn.inspection
import sys
import time

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
    ret = list()
    ret.extend(getFeatures(line));
    if ENABLE_FEATURE_IAT is True:
        ret.extend(getFeaturesFromArray(line['iat_data'], N_DIRS - 1))
    if ENABLE_FEATURE_PKTLEN is True:
        ret.extend(getFeaturesFromArray(line['pktlen_data'], N_DIRS))
    if ENABLE_FEATURE_DIRS is True:
        ret.extend(getFeaturesFromArray(line['directions'], N_DIRS))
    if ENABLE_FEATURE_BINS is True:
        ret.extend(getFeaturesFromArray(line['bins_c_to_s'], N_BINS))
        ret.extend(getFeaturesFromArray(line['bins_s_to_c'], N_BINS))
    return [ret]

def getRelevantFeaturesJSON(line):
    ret = list()
    ret.extend(getFeatures(line))
    if ENABLE_FEATURE_IAT is True:
        ret.extend(getFeaturesFromArray(line['data_analysis']['iat']['data'], N_DIRS - 1))
    if ENABLE_FEATURE_PKTLEN is True:
        ret.extend(getFeaturesFromArray(line['data_analysis']['pktlen']['data'], N_DIRS))
    if ENABLE_FEATURE_DIRS is True:
        ret.extend(getFeaturesFromArray(line['data_analysis']['directions'], N_DIRS))
    if ENABLE_FEATURE_BINS is True:
        ret.extend(getFeaturesFromArray(line['data_analysis']['bins']['c_to_s'], N_BINS))
        ret.extend(getFeaturesFromArray(line['data_analysis']['bins']['s_to_c'], N_BINS) )
    return [ret]

def getRelevantFeatureNames():
    names = list()
    names.extend(['flow_src_packets_processed', 'flow_dst_packets_processed',
                  'flow_src_tot_l4_payload_len', 'flow_dst_tot_l4_payload_len'])
    if ENABLE_FEATURE_IAT is True:
        for x in range(N_DIRS - 1):
            names.append('iat_{}'.format(x))
    if ENABLE_FEATURE_PKTLEN is True:
        for x in range(N_DIRS):
            names.append('pktlen_{}'.format(x))
    if ENABLE_FEATURE_DIRS is True:
        for x in range(N_DIRS):
            names.append('dirs_{}'.format(x))
    if ENABLE_FEATURE_BINS is True:
        for x in range(N_BINS):
            names.append('bins_c_to_s_{}'.format(x))
        for x in range(N_BINS):
            names.append('bins_s_to_c_{}'.format(x))
    return names

def plotPermutatedImportance(model, X, y):
    result = sklearn.inspection.permutation_importance(model, X, y, n_repeats=10, random_state=42, n_jobs=-1)
    forest_importances = pandas.Series(result.importances_mean, index=getRelevantFeatureNames())

    fig, ax = matplotlib.pyplot.subplots()
    forest_importances.plot.bar(yerr=result.importances_std, ax=ax)
    ax.set_title("Feature importances using permutation on full model")
    ax.set_ylabel("Mean accuracy decrease")
    fig.tight_layout()
    matplotlib.pyplot.show()

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
        X = getRelevantFeaturesJSON(json_dict)
        y = model.predict(X)
        s = model.score(X, y)
        p = model.predict_log_proba(X)
        print('DPI Engine detected: {:>24}, Prediction: {:>3}, Score: {}, Probabilities: {}'.format(
              '"' + str(json_dict['ndpi']['proto']) + '"', '"' + str(y) + '"', s, p[0]))
    except Exception as err:
        print('Got exception `{}\'\nfor json: {}'.format(err, json_dict))

    return True

def isProtoClass(proto_class, line):
    s = line.lower()

    for x in range(len(proto_class)):
        if s.startswith(proto_class[x].lower()) is True:
            return x + 1

    return 0

if __name__ == '__main__':
    argparser = nDPIsrvd.defaultArgumentParser()
    argparser.add_argument('--csv', action='store', required=True,
                           help='Input CSV file generated with nDPIsrvd-analysed.')
    argparser.add_argument('--proto-class', action='append', required=True,
                           help='nDPId protocol class of interest used for training and prediction. Can be specified multiple times. Example: tls.youtube')
    argparser.add_argument('--generate-feature-importance', action='store_true',
                           help='Generates the permutated feature importance with matplotlib.')
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

    numpy.set_printoptions(formatter={'float_kind': "{:.1f}".format}, sign=' ')
    numpy.seterr(divide = 'ignore')

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
                y += [isProtoClass(args.proto_class, line['proto'])]
            except RuntimeError as err:
                print('Error: `{}\'\non line: {}'.format(err, line))

        model = sklearn.ensemble.RandomForestClassifier()
        model.fit(X, y)

        if args.generate_feature_importance is True:
            sys.stderr.write('Generating feature importance .. this may take some time')
            plotPermutatedImportance(model, X, y)

    print('Map[*] -> [0]')
    for x in range(len(args.proto_class)):
        print('Map["{}"] -> [{}]'.format(args.proto_class[x], x + 1))

    sys.stderr.write('Predicting realtime traffic..\n')
    nsock = nDPIsrvdSocket()
    nsock.connect(address)
    nsock.loop(onJsonLineRecvd, None, (model,))
