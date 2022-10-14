#!/usr/bin/env python3

import csv
import joblib
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

ENABLE_FEATURE_IAT    = False
ENABLE_FEATURE_PKTLEN = False
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

    model, proto_class, disable_colors = global_user_data

    try:
        X = getRelevantFeaturesJSON(json_dict)
        y = model.predict(X)
        s = model.score(X, y)
        p = model.predict_log_proba(X)

        if y[0] <= 0:
            y_text = 'n/a'
        else:
            y_text = proto_class[y[0] - 1]

        color_start = ''
        color_end = ''
        pred_failed = False
        if disable_colors is False:
            if json_dict['ndpi']['proto'].lower().startswith(y_text) is True:
                color_start = TermColor.BOLD
                color_end = TermColor.END
            elif y_text not in proto_class and \
                 json_dict['ndpi']['proto'].lower() not in proto_class:
                pass
            else:
                pred_failed = True
                color_start = TermColor.FAIL + TermColor.BOLD + TermColor.BLINK
                color_end = TermColor.END

        probs = str()
        for i in range(len(p[0])):
            if json_dict['ndpi']['proto'].lower().startswith(proto_class[i - 1]) and disable_colors is False:
                probs += '{}{:>2.1f}{}, '.format(TermColor.BOLD + TermColor.BLINK if pred_failed is True else '',
                                               p[0][i], TermColor.END)
            elif i == y[0]:
                probs += '{}{:>2.1f}{}, '.format(color_start, p[0][i], color_end)
            else:
                probs += '{:>2.1f}, '.format(p[0][i])
        probs = probs[:-2]

        print('DPI Engine detected: {}{:>24}{}, Predicted: {}{:>24}{}, Score: {}, Probabilities: {}'.format(
              color_start, json_dict['ndpi']['proto'].lower(), color_end,
              color_start, y_text, color_end, s, probs))
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
    argparser.add_argument('--load-model', action='store',
                           help='Load a pre-trained model file.')
    argparser.add_argument('--save-model', action='store',
                           help='Save the trained model to a file.')
    argparser.add_argument('--csv', action='store',
                           help='Input CSV file generated with nDPIsrvd-analysed.')
    argparser.add_argument('--proto-class', action='append', required=True,
                           help='nDPId protocol class of interest used for training and prediction. ' +
                                'Can be specified multiple times. Example: tls.youtube')
    argparser.add_argument('--generate-feature-importance', action='store_true',
                           help='Generates the permutated feature importance with matplotlib.')
    argparser.add_argument('--enable-iat', action='store_true', default=False,
                           help='Enable packet (I)nter (A)rrival (T)ime for learning and prediction.')
    argparser.add_argument('--enable-pktlen', action='store_true', default=False,
                           help='Enable layer 4 packet lengths for learning and prediction.')
    argparser.add_argument('--disable-dirs', action='store_true', default=False,
                           help='Disable packet directions for learning and prediction.')
    argparser.add_argument('--disable-bins', action='store_true', default=False,
                           help='Disable packet length distribution for learning and prediction.')
    argparser.add_argument('--disable-colors', action='store_true', default=False,
                           help='Disable any coloring.')
    argparser.add_argument('--sklearn-jobs', action='store', type=int, default=1,
                           help='Number of sklearn processes during training.')
    argparser.add_argument('--sklearn-estimators', action='store', type=int, default=1000,
                           help='Number of trees in the forest.')
    argparser.add_argument('--sklearn-min-samples-leaf', action='store', type=int, default=5,
                           help='The minimum number of samples required to be at a leaf node.')
    argparser.add_argument('--sklearn-class-weight', default='balanced', const='balanced', nargs='?',
                           choices=['balanced', 'balanced_subsample'],
                           help='Weights associated with the protocol classes.')
    argparser.add_argument('--sklearn-max-features', default='sqrt', const='sqrt', nargs='?',
                           choices=['sqrt', 'log2'],
                           help='The number of features to consider when looking for the best split.')
    argparser.add_argument('--sklearn-verbosity', action='store', type=int, default=0,
                           help='Controls the verbosity of sklearn\'s random forest classifier.')
    args = argparser.parse_args()
    address = nDPIsrvd.validateAddress(args)

    if args.csv is None and args.load_model is None:
        sys.stderr.write('{}: Either `--csv` or `--load-model` required!\n'.format(sys.argv[0]))
        sys.exit(1)

    if args.csv is None and args.generate_feature_importance is True:
        sys.stderr.write('{}: `--generate-feature-importance` requires `--csv`.\n'.format(sys.argv[0]))
        sys.exit(1)

    ENABLE_FEATURE_IAT    = args.enable_iat
    ENABLE_FEATURE_PKTLEN = args.enable_pktlen
    ENABLE_FEATURE_DIRS   = args.disable_dirs is False
    ENABLE_FEATURE_BINS   = args.disable_bins is False

    numpy.set_printoptions(formatter={'float_kind': "{:.1f}".format}, sign=' ')
    numpy.seterr(divide = 'ignore')

    for i in range(len(args.proto_class)):
        args.proto_class[i] = args.proto_class[i].lower()

    if args.load_model is not None:
        sys.stderr.write('Loading model from {}\n'.format(args.load_model))
        model = joblib.load(args.load_model)

    if args.csv is not None:
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

            sys.stderr.write('CSV data set contains {} entries.\n'.format(len(X)))

            if args.load_model is None:
                model = sklearn.ensemble.RandomForestClassifier(bootstrap=False,
                                                                class_weight     = args.sklearn_class_weight,
                                                                n_jobs           = args.sklearn_jobs,
                                                                n_estimators     = args.sklearn_estimators,
                                                                verbose          = args.sklearn_verbosity,
                                                                min_samples_leaf = args.sklearn_min_samples_leaf,
                                                                max_features     = args.sklearn_max_features
                                                               )
            sys.stderr.write('Training model..\n')
            model.fit(X, y)

            if args.generate_feature_importance is True:
                sys.stderr.write('Generating feature importance .. this may take some time\n')
                plotPermutatedImportance(model, X, y)

    if args.save_model is not None:
        sys.stderr.write('Saving model to {}\n'.format(args.save_model))
        joblib.dump(model, args.save_model)

    print('Map[*] -> [0]')
    for x in range(len(args.proto_class)):
        print('Map["{}"] -> [{}]'.format(args.proto_class[x], x + 1))

    sys.stderr.write('Predicting realtime traffic..\n')
    sys.stderr.write('Recv buffer size: {}\n'.format(nDPIsrvd.NETWORK_BUFFER_MAX_SIZE))
    sys.stderr.write('Connecting to {} ..\n'.format(address[0]+':'+str(address[1]) if type(address) is tuple else address))
    nsock = nDPIsrvdSocket()
    nsock.connect(address)
    nsock.loop(onJsonLineRecvd, None, (model, args.proto_class, args.disable_colors))
