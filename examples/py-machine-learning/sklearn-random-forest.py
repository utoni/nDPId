#!/usr/bin/env python3

import csv
import itertools
import joblib
import matplotlib.pyplot
import numpy
import os
import pandas
import sklearn
import sklearn.ensemble
import sklearn.inspection
import sklearn.metrics
import sklearn.model_selection
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

PROTO_CLASSES = None

PREDICTION_MIN_PROBABILITY      = 0.70
PREDICTION_MIN_MARGIN_TO_NONE   = 1.50
PREDICTION_MIN_MARGIN_TO_SECOND = 1.00
MESSAGE_INDENT                  = 46

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

def isProtoClass(proto_class, line):
    if type(proto_class) != list or type(line) != str:
        raise TypeError('Invalid type: {}/{}.'.format(type(proto_class), type(line)))

    s = line.lower()

    for x in range(len(proto_class)):
        if s.startswith(proto_class[x].lower()) is True:
            return x + 1

    return 0

def predictClassFromProbabilities(probabilities, log_probabilities,
                                  min_probability,
                                  min_margin_to_none,
                                  min_margin_to_second):
    predicted_class = int(numpy.argmax(probabilities))
    rejection_reason = None

    if predicted_class <= 0:
        return predicted_class, rejection_reason

    predicted_log_probability = log_probabilities[predicted_class]
    none_log_probability = log_probabilities[0]
    sorted_classes = numpy.argsort(log_probabilities)[::-1]
    second_best_class = int(sorted_classes[1]) if len(sorted_classes) > 1 else 0
    second_best_log_probability = log_probabilities[second_best_class]

    if probabilities[predicted_class] < min_probability:
        predicted_class = 0
        rejection_reason = 'min-probability'
    elif predicted_log_probability - none_log_probability < min_margin_to_none:
        predicted_class = 0
        rejection_reason = 'min-margin-to-none'
    elif predicted_log_probability - second_best_log_probability < min_margin_to_second:
        predicted_class = 0
        rejection_reason = 'min-margin-to-second'

    return predicted_class, rejection_reason

def evaluateModel(model, X_test, y_test,
                  min_probability,
                  min_margin_to_none,
                  min_margin_to_second):
    predicted_probabilities = model.predict_proba(X_test)
    predicted_log_probabilities = model.predict_log_proba(X_test)
    y_pred = list()

    for probabilities, log_probabilities in zip(predicted_probabilities, predicted_log_probabilities):
        predicted_class, _ = predictClassFromProbabilities(probabilities,
                                                           log_probabilities,
                                                           min_probability,
                                                           min_margin_to_none,
                                                           min_margin_to_second)
        y_pred.append(predicted_class)

    y_test = numpy.asarray(y_test)
    y_pred = numpy.asarray(y_pred)

    accepted_prediction_mask = y_pred > 0
    known_class_mask = y_test > 0
    false_positive_mask = numpy.logical_and(y_test == 0, y_pred > 0)
    true_positive_mask = numpy.logical_and(y_test > 0, y_pred == y_test)

    accepted_prediction_count = int(numpy.count_nonzero(accepted_prediction_mask))
    known_class_count = int(numpy.count_nonzero(known_class_mask))
    negative_class_count = int(numpy.count_nonzero(y_test == 0))
    true_positive_count = int(numpy.count_nonzero(true_positive_mask))
    false_positive_count = int(numpy.count_nonzero(false_positive_mask))

    accepted_precision = (true_positive_count / accepted_prediction_count) if accepted_prediction_count > 0 else 0.0
    known_class_recall = (true_positive_count / known_class_count) if known_class_count > 0 else 0.0
    false_positive_rate = (false_positive_count / negative_class_count) if negative_class_count > 0 else 0.0
    prediction_coverage = (accepted_prediction_count / len(y_pred)) if len(y_pred) > 0 else 0.0

    return {
        'accuracy': sklearn.metrics.accuracy_score(y_test, y_pred),
        'balanced_accuracy': sklearn.metrics.balanced_accuracy_score(y_test, y_pred),
        'macro_precision': sklearn.metrics.precision_score(y_test, y_pred, average='macro', zero_division=0),
        'accepted_precision': accepted_precision,
        'known_class_recall': known_class_recall,
        'false_positive_rate': false_positive_rate,
        'prediction_coverage': prediction_coverage
    }

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

    model, proto_class, disable_colors, min_probability, min_margin_to_none, min_margin_to_second = global_user_data

    try:
        X = getRelevantFeaturesJSON(json_dict)
        probabilities = model.predict_proba(X)[0]
        log_probabilities = model.predict_log_proba(X)[0]
        predicted_class, rejection_reason = predictClassFromProbabilities(probabilities,
                                                                          log_probabilities,
                                                                          min_probability,
                                                                          min_margin_to_none,
                                                                          min_margin_to_second)

        if predicted_class <= 0:
            y_text = 'n/a'
        else:
            y_text = proto_class[predicted_class - 1]

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
                color_start = TermColor.WARNING + TermColor.BOLD
                color_end = TermColor.END

        probs = str()
        for i in range(len(log_probabilities)):
            if i > 0 and json_dict['ndpi']['proto'].lower().startswith(proto_class[i - 1]) and disable_colors is False:
                probs += '{}{:>2.1f}{}, '.format(TermColor.BOLD + TermColor.BLINK if pred_failed is True else '',
                                               log_probabilities[i], TermColor.END)
            elif i == predicted_class:
                probs += '{}{:>2.1f}{}, '.format(color_start, log_probabilities[i], color_end)
            else:
                probs += '{:>2.1f}, '.format(log_probabilities[i])
        probs = probs[:-2]

        print('DPI Engine detected: {}{:>24}{}, Predicted: {}{:>24}{}, Probabilities: {}'.format(
              color_start, json_dict['ndpi']['proto'].lower(), color_end,
              color_start, y_text, color_end, probs))

        if rejection_reason is not None:
            print('{:>{}} {} rejected by {}'.format('[*]', MESSAGE_INDENT, y_text, rejection_reason))

        if pred_failed is True:
            pclass = isProtoClass(args.proto_class, json_dict['ndpi']['proto'].lower())
            if pclass == 0:
                msg = 'false positive'
            else:
                msg = 'false negative'

            print('{:>{}} {}{}{}'.format('[-]', MESSAGE_INDENT, TermColor.FAIL + TermColor.BOLD + TermColor.BLINK, msg, TermColor.END))

    except Exception as err:
        print('Got exception `{}\'\nfor json: {}'.format(err, json_dict))

    return True

if __name__ == '__main__':
    argparser = nDPIsrvd.defaultArgumentParser()
    argparser.add_argument('--load-model', action='store',
                           help='Load a pre-trained model file.')
    argparser.add_argument('--save-model', action='store',
                           help='Save the trained model to a file.')
    argparser.add_argument('--csv', action='store',
                           help='Input CSV file generated with nDPIsrvd-analysed.')
    argparser.add_argument('--proto-class', action='append', required=False,
                           help='nDPId protocol class of interest used for training and prediction. ' +
                                'Can be specified multiple times. Example: tls.youtube')
    argparser.add_argument('--generate-feature-importance', action='store_true',
                           help='Generates the permutated feature importance with matplotlib.')
    argparser.add_argument('--enable-iat', action='store_true', default=None,
                           help='Enable packet (I)nter (A)rrival (T)ime for learning and prediction.')
    argparser.add_argument('--enable-pktlen', action='store_true', default=None,
                           help='Enable layer 4 packet lengths for learning and prediction.')
    argparser.add_argument('--disable-dirs', action='store_true', default=None,
                           help='Disable packet directions for learning and prediction.')
    argparser.add_argument('--disable-bins', action='store_true', default=None,
                           help='Disable packet length distribution for learning and prediction.')
    argparser.add_argument('--disable-colors', action='store_true', default=False,
                           help='Disable any coloring.')
    argparser.add_argument('--sklearn-jobs', action='store', type=int, default=1,
                           help='Number of sklearn processes during training.')
    argparser.add_argument('--sklearn-estimators', action='store', type=int, default=1000,
                           help='Number of trees in the forest.')
    argparser.add_argument('--sklearn-min-samples-leaf', action='store', type=float, default=0.0001,
                           help='The minimum number of samples required to be at a leaf node.')
    argparser.add_argument('--sklearn-class-weight', default='balanced', const='balanced', nargs='?',
                           choices=['balanced', 'balanced_subsample'],
                           help='Weights associated with the protocol classes.')
    argparser.add_argument('--sklearn-max-features', default='sqrt', const='sqrt', nargs='?',
                           choices=['sqrt', 'log2'],
                           help='The number of features to consider when looking for the best split.')
    argparser.add_argument('--sklearn-max-depth', action='store', type=int, default=128,
                           help='The maximum depth of a tree.')
    argparser.add_argument('--sklearn-no-bootstrap', action='store_false', dest='sklearn_bootstrap',
                           help='Disable bootstrap sampling when building trees. ' +
                                'Bootstrap is enabled by default and allows out-of-bag error estimation.')
    argparser.add_argument('--sklearn-verbosity', action='store', type=int, default=0,
                           help='Controls the verbosity of sklearn\'s random forest classifier.')
    argparser.add_argument('--test-split', action='store', type=float, default=0.2,
                           help='Fraction of CSV data to hold out as a test set (e.g. 0.2 for 20%%). ' +
                                'Reports accuracy on the held-out set after training. Requires --csv.')
    argparser.add_argument('--prediction-min-probability', action='store', type=float, default=PREDICTION_MIN_PROBABILITY,
                           help='Minimum predicted class probability required before returning a non-n/a class.')
    argparser.add_argument('--prediction-min-margin-to-none', action='store', type=float, default=PREDICTION_MIN_MARGIN_TO_NONE,
                           help='Minimum log-probability margin over class 0 (n/a) required before returning a non-n/a class.')
    argparser.add_argument('--prediction-min-margin-to-second', action='store', type=float, default=PREDICTION_MIN_MARGIN_TO_SECOND,
                           help='Minimum log-probability margin over the runner-up class required before returning a non-n/a class.')
    args = argparser.parse_args()
    address = nDPIsrvd.validateAddress(args)

    if args.csv is None and args.load_model is None:
        sys.stderr.write('{}: Either `--csv` or `--load-model` required!\n'.format(sys.argv[0]))
        sys.exit(1)

    if args.csv is None and args.generate_feature_importance is True:
        sys.stderr.write('{}: `--generate-feature-importance` requires `--csv`.\n'.format(sys.argv[0]))
        sys.exit(1)

    if args.proto_class is None or len(args.proto_class) == 0:
        if args.csv is None and args.load_model is None:
            sys.stderr.write('{}: `--proto-class` missing, no useful classification can be performed.\n'.format(sys.argv[0]))
    else:
        if args.load_model is not None:
            sys.stderr.write('{}: `--proto-class` set, but you want to load an existing model.\n'.format(sys.argv[0]))
            sys.exit(1)

    if args.load_model is not None:
        sys.stderr.write('{}: You are loading an existing model file. ' \
                         'Some --sklearn-* command line parameters won\'t have any effect!\n'.format(sys.argv[0]))

        if args.enable_iat is not None:
            sys.stderr.write('{}: `--enable-iat` set, but you want to load an existing model.\n'.format(sys.argv[0]))
            sys.exit(1)
        if args.enable_pktlen is not None:
            sys.stderr.write('{}: `--enable-pktlen` set, but you want to load an existing model.\n'.format(sys.argv[0]))
            sys.exit(1)
        if args.disable_dirs is not None:
            sys.stderr.write('{}: `--disable-dirs` set, but you want to load an existing model.\n'.format(sys.argv[0]))
            sys.exit(1)
        if args.disable_bins is not None:
            sys.stderr.write('{}: `--disable-bins` set, but you want to load an existing model.\n'.format(sys.argv[0]))
            sys.exit(1)

    ENABLE_FEATURE_IAT    = args.enable_iat if args.enable_iat is not None else ENABLE_FEATURE_IAT
    ENABLE_FEATURE_PKTLEN = args.enable_pktlen if args.enable_pktlen is not None else ENABLE_FEATURE_PKTLEN
    ENABLE_FEATURE_DIRS   = not args.disable_dirs if args.disable_dirs is not None else ENABLE_FEATURE_DIRS
    ENABLE_FEATURE_BINS   = not args.disable_bins if args.disable_bins is not None else ENABLE_FEATURE_BINS
    PROTO_CLASSES         = args.proto_class

    numpy.set_printoptions(formatter={'float_kind': "{:.1f}".format}, sign=' ')
    numpy.seterr(divide = 'ignore')

    if args.proto_class is not None:
        for i in range(len(args.proto_class)):
            args.proto_class[i] = args.proto_class[i].lower()

    if args.load_model is not None:
        sys.stderr.write('Loading model from {}\n'.format(args.load_model))
        model, options = joblib.load(args.load_model)
        ENABLE_FEATURE_IAT, ENABLE_FEATURE_PKTLEN, ENABLE_FEATURE_DIRS, ENABLE_FEATURE_BINS, args.proto_class = options

    if args.csv is not None:
        sys.stderr.write('Learning via CSV..\n')
        with open(args.csv, newline='\n') as csvfile:
            reader = csv.DictReader(csvfile, delimiter=',', quotechar='"')
            X = list()
            y = list()

            first_line = None
            for line in reader:
                N_DIRS = len(getFeaturesFromArray(line['directions']))
                N_BINS = len(getFeaturesFromArray(line['bins_c_to_s']))
                first_line = line
                break

            for line in itertools.chain([first_line] if first_line is not None else [], reader):
                try:
                    X += getRelevantFeaturesCSV(line)
                except RuntimeError as err:
                    print('Runtime Error: `{}\'\non line {}: {}'.format(err, reader.line_num - 1, line))
                    continue
                except TypeError as err:
                    print('Type Error: `{}\'\non line {}: {}'.format(err, reader.line_num - 1, line))
                    continue

                try:
                    y += [isProtoClass(args.proto_class, line['proto'])]
                except TypeError as err:
                    X.pop()
                    print('Type Error: `{}\'\non line {}: {}'.format(err, reader.line_num - 1, line))
                    continue

            sys.stderr.write('CSV data set contains {} entries.\n'.format(len(X)))

            if args.load_model is None:
                model = sklearn.ensemble.RandomForestClassifier(bootstrap        = args.sklearn_bootstrap,
                                                                class_weight     = args.sklearn_class_weight,
                                                                n_jobs           = args.sklearn_jobs,
                                                                n_estimators     = args.sklearn_estimators,
                                                                verbose          = args.sklearn_verbosity,
                                                                min_samples_leaf = args.sklearn_min_samples_leaf,
                                                                max_features     = args.sklearn_max_features,
                                                                max_depth        = args.sklearn_max_depth
                                                               )
                options = (ENABLE_FEATURE_IAT, ENABLE_FEATURE_PKTLEN, ENABLE_FEATURE_DIRS, ENABLE_FEATURE_BINS, args.proto_class)

            if args.test_split > 0.0 and args.load_model is None:
                try:
                    X_train, X_test, y_train, y_test = sklearn.model_selection.train_test_split(
                        X, y, test_size=args.test_split, random_state=42, stratify=y)
                except ValueError:
                    sys.stderr.write('Warning: stratified split failed (too few samples per class), ' \
                                     'falling back to random split.\n')
                    X_train, X_test, y_train, y_test = sklearn.model_selection.train_test_split(
                        X, y, test_size=args.test_split, random_state=42)
                sys.stderr.write('Training model on {} samples, holding out {} for testing..\n'.format(
                    len(X_train), len(X_test)))
                model.fit(X_train, y_train)
                metrics = evaluateModel(model,
                                        X_test,
                                        y_test,
                                        args.prediction_min_probability,
                                        args.prediction_min_margin_to_none,
                                        args.prediction_min_margin_to_second)
                sys.stderr.write('Test set accuracy...............: {:.4f} ({:.1f}%)\n'.format(metrics['accuracy'],
                                                                                               metrics['accuracy'] * 100))
                sys.stderr.write('Balanced accuracy...............: {:.4f}\n'.format(metrics['balanced_accuracy']))
                sys.stderr.write('Macro precision.................: {:.4f}\n'.format(metrics['macro_precision']))
                sys.stderr.write('Accepted precision..............: {:.4f}\n'.format(metrics['accepted_precision']))
                sys.stderr.write('Known-class recall..............: {:.4f}\n'.format(metrics['known_class_recall']))
                sys.stderr.write('False-positive rate on n/a class: {:.4f}\n'.format(metrics['false_positive_rate']))
                sys.stderr.write('Prediction coverage.............: {:.4f}\n'.format(metrics['prediction_coverage']))
                sys.stderr.write('Re-training model on the full CSV data set..\n')
                model.fit(X, y)
            else:
                sys.stderr.write('Training model..\n')
                model.fit(X, y)

            if args.generate_feature_importance is True:
                sys.stderr.write('Generating feature importance .. this may take some time\n')
                plotPermutatedImportance(model, X, y)

    if args.save_model is not None:
        sys.stderr.write('Saving model to {}\n'.format(args.save_model))
        joblib.dump([model, options], args.save_model)

    print('ENABLE_FEATURE_PKTLEN.: {}'.format(ENABLE_FEATURE_PKTLEN))
    print('ENABLE_FEATURE_BINS...: {}'.format(ENABLE_FEATURE_BINS))
    print('ENABLE_FEATURE_DIRS...: {}'.format(ENABLE_FEATURE_DIRS))
    print('ENABLE_FEATURE_IAT....: {}'.format(ENABLE_FEATURE_IAT))
    print('PRED_MIN_PROBABILITY..: {}'.format(args.prediction_min_probability))
    print('PRED_MIN_MARGIN_NONE..: {}'.format(args.prediction_min_margin_to_none))
    print('PRED_MIN_MARGIN_SECOND: {}'.format(args.prediction_min_margin_to_second))
    print('Map[*] -> [0]')
    if args.proto_class is not None:
        for x in range(len(args.proto_class)):
            print('Map["{}"] -> [{}]'.format(args.proto_class[x], x + 1))

    sys.stderr.write('Predicting traffic..\n')
    sys.stderr.write('Recv buffer size: {}\n'.format(nDPIsrvd.NETWORK_BUFFER_MAX_SIZE))
    sys.stderr.write('Connecting to {} ..\n'.format(address[0]+':'+str(address[1]) if type(address) is tuple else address))
    nsock = nDPIsrvdSocket()
    nsock.connect(address)
    nsock.loop(onJsonLineRecvd, None, (model,
                                      args.proto_class,
                                      args.disable_colors,
                                      args.prediction_min_probability,
                                      args.prediction_min_margin_to_none,
                                      args.prediction_min_margin_to_second))
