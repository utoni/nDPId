#!/usr/bin/env python3

import base64
import binascii
import joblib
import multiprocessing as mp
import numpy as np
import os
import queue
import sys

sys.path.append(os.path.dirname(sys.argv[0]) + '/../../dependencies')
sys.path.append(os.path.dirname(sys.argv[0]) + '/../share/nDPId')
sys.path.append(os.path.dirname(sys.argv[0]))
sys.path.append(sys.base_prefix + '/share/nDPId')
import nDPIsrvd
from nDPIsrvd import nDPIsrvdSocket, TermColor

INPUT_SIZE = nDPIsrvd.nDPId_PACKETS_PLEN_MAX
LATENT_SIZE = 8
TRAINING_SIZE = 500
EPOCH_COUNT = 5
BATCH_SIZE = 10

def generate_autoencoder():
    input_i = Input(shape=(), name='input_i')
    input_e = Embedding(input_dim=INPUT_SIZE, output_dim=INPUT_SIZE, mask_zero=True, name='input_e')(input_i)
    encoded_h1 = Dense(1024, activation='relu', name='encoded_h1')(input_e)
    encoded_h2 = Dense(512, activation='relu', name='encoded_h2')(encoded_h1)
    encoded_h3 = Dense(128, activation='relu', name='encoded_h3')(encoded_h2)
    encoded_h4 = Dense(64, activation='relu', name='encoded_h4')(encoded_h3)
    encoded_h5 = Dense(32, activation='relu', name='encoded_h5')(encoded_h4)
    latent = Dense(LATENT_SIZE, activation='relu', name='latent')(encoded_h5)

    input_l = Input(shape=(LATENT_SIZE), name='input_l')
    decoder_h1 = Dense(32, activation='relu', name='decoder_h1')(input_l)
    decoder_h2 = Dense(64, activation='relu', name='decoder_h2')(decoder_h1)
    decoder_h3 = Dense(128, activation='relu', name='decoder_h3')(decoder_h2)
    decoder_h4 = Dense(512, activation='relu', name='decoder_h4')(decoder_h3)
    decoder_h5 = Dense(1024, activation='relu', name='decoder_h5')(decoder_h4)
    output_i = Dense(INPUT_SIZE, activation='sigmoid', name='output_i')(decoder_h5)

    encoder = Model(input_e, latent, name='encoder')
    decoder = Model(input_l, output_i, name='decoder')
    return encoder, decoder, Model(input_e, decoder(encoder(input_e)), name='VAE')

def compile_autoencoder():
    encoder, decoder, autoencoder = generate_autoencoder()
    autoencoder.compile(loss='mse', optimizer='adam', metrics=[tf.keras.metrics.Accuracy()])
    return encoder, decoder, autoencoder

def onJsonLineRecvd(json_dict, instance, current_flow, global_user_data):
    if 'packet_event_name' not in json_dict:
        return True

    if json_dict['packet_event_name'] != 'packet' and \
        json_dict['packet_event_name'] != 'packet-flow':
        return True

    shutdown_event, training_event, padded_pkts = global_user_data
    if shutdown_event.is_set():
        return False

    try:
        buf = base64.b64decode(json_dict['pkt'], validate=True)
    except binascii.Error as err:
        sys.stderr.write('\nBase64 Exception: {}\n'.format(str(err)))
        sys.stderr.write('Affected JSON: {}\n'.format(str(json_dict)))
        sys.stderr.flush()
        return False

    # Generate decimal byte buffer with valus from 0-255
    int_buf = []
    for v in buf:
        int_buf.append(int(v))

    mat = np.array([int_buf], dtype='float64')

    # Normalize the values
    mat = mat.astype('float64') / 255.0

    # Mean removal
    matmean = np.mean(mat, dtype='float64')
    mat -= matmean

    # Pad resulting matrice
    buf = preprocessing.sequence.pad_sequences(mat, padding="post", maxlen=INPUT_SIZE, truncating='post', dtype='float64')
    padded_pkts.put(buf[0])

    #print(list(buf[0]))

    if not training_event.is_set():
        sys.stdout.write('.')
        sys.stdout.flush()

    return True

def nDPIsrvd_worker(address, shared_shutdown_event, shared_training_event, shared_packet_list):
    nsock = nDPIsrvdSocket()

    try:
        nsock.connect(address)
        padded_pkts = list()
        nsock.loop(onJsonLineRecvd, None, (shared_shutdown_event, shared_training_event, shared_packet_list))
    except nDPIsrvd.SocketConnectionBroken as err:
        sys.stderr.write('\nnDPIsrvd-Worker Socket Error: {}\n'.format(err))
    except KeyboardInterrupt:
        sys.stderr.write('\n')
    except Exception as err:
        sys.stderr.write('\nnDPIsrvd-Worker Exception: {}\n'.format(str(err)))
    sys.stderr.flush()

    shared_shutdown_event.set()

def keras_worker(load_model, save_model, shared_shutdown_event, shared_training_event, shared_packet_queue):
    shared_training_event.set()
    if load_model is not None:
        sys.stderr.write('Loading model from {}\n'.format(load_model))
        sys.stderr.flush()
        try:
            encoder, decoder, autoencoder = joblib.load(load_model)
        except:
            sys.stderr.write('Could not load model from {}\n'.format(load_model))
            sys.stderr.write('Compiling new Autoencoder..\n')
            sys.stderr.flush()
            encoder, decoder, autoencoder = compile_autoencoder()
    else:
        encoder, decoder, autoencoder = compile_autoencoder()
    decoder.summary()
    encoder.summary()
    autoencoder.summary()
    shared_training_event.clear()

    try:
        packets = list()
        while not shared_shutdown_event.is_set():
            try:
                packet = shared_packet_queue.get(timeout=1)
            except queue.Empty:
                packet = None

            if packet is None:
                continue

            packets.append(packet)
            if len(packets) % TRAINING_SIZE == 0:
                shared_training_event.set()
                print('\nGot {} packets, training..'.format(len(packets)))
                tmp = np.array(packets)
                x_test_encoded = encoder.predict(tmp, batch_size=BATCH_SIZE)
                history = autoencoder.fit(
                                          tmp, tmp, epochs=EPOCH_COUNT, batch_size=BATCH_SIZE,
                                          validation_split=0.2,
                                          shuffle=True
                                         )
                packets.clear()
                shared_training_event.clear()
    except KeyboardInterrupt:
        sys.stderr.write('\n')
    except Exception as err:
        if len(str(err)) == 0:
            err = 'Unknown'
        sys.stderr.write('\nKeras-Worker Exception: {}\n'.format(str(err)))
    sys.stderr.flush()

    if save_model is not None:
        sys.stderr.write('Saving model to {}\n'.format(save_model))
        sys.stderr.flush()
        joblib.dump([encoder, decoder, autoencoder], save_model)

    try:
        shared_shutdown_event.set()
    except:
        pass

if __name__ == '__main__':
    sys.stderr.write('\b\n***************\n')
    sys.stderr.write('*** WARNING ***\n')
    sys.stderr.write('***************\n')
    sys.stderr.write('\nThis is an unmature Autoencoder example.\n')
    sys.stderr.write('Please do not rely on any of it\'s output!\n\n')

    argparser = nDPIsrvd.defaultArgumentParser()
    argparser.add_argument('--load-model', action='store',
                           help='Load a pre-trained model file.')
    argparser.add_argument('--save-model', action='store',
                           help='Save the trained model to a file.')
    argparser.add_argument('--training-size', action='store', type=int,
                           help='Set the amount of captured packets required to start the training phase.')
    argparser.add_argument('--batch-size', action='store', type=int,
                           help='Set the batch size used for the training phase.')
    args = argparser.parse_args()
    address = nDPIsrvd.validateAddress(args)

    TRAINING_SIZE = args.training_size if args.training_size is not None else TRAINING_SIZE
    BATCH_SIZE    = args.batch_size if args.batch_size is not None else BATCH_SIZE

    sys.stderr.write('Recv buffer size: {}\n'.format(nDPIsrvd.NETWORK_BUFFER_MAX_SIZE))
    sys.stderr.write('Connecting to {} ..\n'.format(address[0]+':'+str(address[1]) if type(address) is tuple else address))
    sys.stderr.write('TRAINING_SIZE={}, BATCH_SIZE={}\n\n'.format(TRAINING_SIZE, BATCH_SIZE))

    import tensorflow as tf
    from tensorflow.keras import layers, preprocessing
    from tensorflow.keras.layers import Embedding, Input, Dense
    from tensorflow.keras.models import Model, Sequential
    from tensorflow.keras.utils import plot_model

    mgr = mp.Manager()

    shared_training_event = mgr.Event()
    shared_training_event.clear()

    shared_shutdown_event = mgr.Event()
    shared_shutdown_event.clear()

    shared_packet_queue = mgr.JoinableQueue()

    nDPIsrvd_job = mp.Process(target=nDPIsrvd_worker, args=(
                                                            address,
                                                            shared_shutdown_event,
                                                            shared_training_event,
                                                            shared_packet_queue
                                                           ))
    nDPIsrvd_job.start()

    keras_job = mp.Process(target=keras_worker, args=(
                                                      args.load_model,
                                                      args.save_model,
                                                      shared_shutdown_event,
                                                      shared_training_event,
                                                      shared_packet_queue
                                                     ))
    keras_job.start()

    try:
        shared_shutdown_event.wait()
    except KeyboardInterrupt:
        print('\nShutting down worker processess..')

    nDPIsrvd_job.terminate()
    nDPIsrvd_job.join()
    keras_job.join()
