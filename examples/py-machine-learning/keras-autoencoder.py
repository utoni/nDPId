#!/usr/bin/env python3

import base64
import binascii
import datetime as dt
import math
import matplotlib.animation as ani
import matplotlib.pyplot as plt
import multiprocessing as mp
import numpy as np
import os
import queue
import sys

import tensorflow as tf
from tensorflow.keras import models, layers, preprocessing
from tensorflow.keras.layers import Embedding, Masking, Input, Dense
from tensorflow.keras.models import Model
from tensorflow.keras.utils import plot_model
from tensorflow.keras.losses import MeanSquaredError, KLDivergence
from tensorflow.keras.optimizers import Adam, SGD
from tensorflow.keras.callbacks import TensorBoard, EarlyStopping

sys.path.append(os.path.dirname(sys.argv[0]) + '/../../dependencies')
sys.path.append(os.path.dirname(sys.argv[0]) + '/../share/nDPId')
sys.path.append(os.path.dirname(sys.argv[0]))
sys.path.append(sys.base_prefix + '/share/nDPId')
import nDPIsrvd
from nDPIsrvd import nDPIsrvdSocket, TermColor

INPUT_SIZE    = nDPIsrvd.nDPId_PACKETS_PLEN_MAX
LATENT_SIZE   = 16
TRAINING_SIZE = 8192
EPOCH_COUNT   = 50
BATCH_SIZE    = 512
LEARNING_RATE = 0.0000001
ES_PATIENCE   = 10
PLOT          = False
PLOT_HISTORY  = 100
TENSORBOARD   = False
TB_LOGPATH    = 'logs/' + dt.datetime.now().strftime("%Y%m%d-%H%M%S")
VAE_USE_KLDIV = False
VAE_USE_SGD   = False

def generate_autoencoder():
    # TODO: The current model does handle *each* packet separatly.
    #       But in fact, depending on the nDPId settings (nDPId_PACKETS_PER_FLOW_TO_SEND), packets can be in relation to each other.
    #       The accuracy may (or may not) improve significantly, but some of changes in the code are required.
    input_i = Input(shape=(), name='input_i')
    input_e = Embedding(input_dim=INPUT_SIZE, output_dim=INPUT_SIZE, mask_zero=True, name='input_e')(input_i)
    masked_e = Masking(mask_value=0.0, name='masked_e')(input_e)
    encoded_h1 = Dense(4096, activation='relu', name='encoded_h1')(masked_e)
    encoded_h2 = Dense(2048, activation='relu', name='encoded_h2')(encoded_h1)
    encoded_h3 = Dense(1024, activation='relu', name='encoded_h3')(encoded_h2)
    encoded_h4 = Dense(512, activation='relu', name='encoded_h4')(encoded_h3)
    encoded_h5 = Dense(128, activation='relu', name='encoded_h5')(encoded_h4)
    encoded_h6 = Dense(64, activation='relu', name='encoded_h6')(encoded_h5)
    encoded_h7 = Dense(32, activation='relu', name='encoded_h7')(encoded_h6)
    latent = Dense(LATENT_SIZE, activation='relu', name='latent')(encoded_h7)

    input_l = Input(shape=(LATENT_SIZE), name='input_l')
    decoder_h1 = Dense(32, activation='relu', name='decoder_h1')(input_l)
    decoder_h2 = Dense(64, activation='relu', name='decoder_h2')(decoder_h1)
    decoder_h3 = Dense(128, activation='relu', name='decoder_h3')(decoder_h2)
    decoder_h4 = Dense(512, activation='relu', name='decoder_h4')(decoder_h3)
    decoder_h5 = Dense(1024, activation='relu', name='decoder_h5')(decoder_h4)
    decoder_h6 = Dense(2048, activation='relu', name='decoder_h6')(decoder_h5)
    decoder_h7 = Dense(4096, activation='relu', name='decoder_h7')(decoder_h6)
    output_i = Dense(INPUT_SIZE, activation='sigmoid', name='output_i')(decoder_h7)

    encoder = Model(input_e, latent, name='encoder')
    decoder = Model(input_l, output_i, name='decoder')
    return KLDivergence() if VAE_USE_KLDIV else MeanSquaredError(), \
           SGD() if VAE_USE_SGD else Adam(learning_rate=LEARNING_RATE), \
           Model(input_e, decoder(encoder(input_e)), name='VAE')

def compile_autoencoder():
    loss, optimizer, autoencoder = generate_autoencoder()
    autoencoder.compile(loss=loss, optimizer=optimizer, metrics=[])
    return autoencoder

def get_autoencoder(load_from_file=None):
    if load_from_file is None:
        autoencoder = compile_autoencoder()
    else:
        autoencoder = models.load_model(load_from_file)

    encoder_submodel = autoencoder.layers[1]
    decoder_submodel = autoencoder.layers[2]
    return encoder_submodel, decoder_submodel, autoencoder

def onJsonLineRecvd(json_dict, instance, current_flow, global_user_data):
    if 'packet_event_name' not in json_dict:
        return True

    if json_dict['packet_event_name'] != 'packet' and \
        json_dict['packet_event_name'] != 'packet-flow':
        return True

    shutdown_event, training_event, padded_pkts, print_dots = global_user_data
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
        sys.stdout.write('.' * print_dots)
        sys.stdout.flush()
        print_dots = 1
    else:
        print_dots += 1

    return True

def nDPIsrvd_worker(address, shared_shutdown_event, shared_training_event, shared_packet_list):
    nsock = nDPIsrvdSocket()

    try:
        nsock.connect(address)
        print_dots = 1
        nsock.loop(onJsonLineRecvd, None, (shared_shutdown_event, shared_training_event, shared_packet_list, print_dots))
    except nDPIsrvd.SocketConnectionBroken as err:
        sys.stderr.write('\nnDPIsrvd-Worker Socket Error: {}\n'.format(err))
    except KeyboardInterrupt:
        sys.stderr.write('\n')
    except Exception as err:
        sys.stderr.write('\nnDPIsrvd-Worker Exception: {}\n'.format(str(err)))
    sys.stderr.flush()

    shared_shutdown_event.set()

def keras_worker(load_model, save_model, shared_shutdown_event, shared_training_event, shared_packet_queue, shared_plot_queue):
    shared_training_event.set()
    try:
        encoder, decoder, autoencoder = get_autoencoder(load_model)
    except Exception as err:
        sys.stderr.write('Could not load Keras model from file: {}\n'.format(str(err)))
        sys.stderr.flush()
        encoder, decoder, autoencoder = get_autoencoder()
    autoencoder.summary()
    tensorboard = TensorBoard(log_dir=TB_LOGPATH, histogram_freq=1)
    early_stopping = EarlyStopping(monitor='val_loss', min_delta=0.0001, patience=ES_PATIENCE, restore_best_weights=True, start_from_epoch=0, verbose=0, mode='auto')
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
                history = autoencoder.fit(
                                          tmp, tmp, epochs=EPOCH_COUNT, batch_size=BATCH_SIZE,
                                          validation_split=0.2,
                                          shuffle=True,
                                          callbacks=[tensorboard, early_stopping]
                                         )
                reconstructed_data = autoencoder.predict(tmp)
                mse = np.mean(np.square(tmp - reconstructed_data))
                reconstruction_accuracy = (1.0 / mse)
                encoded_data = encoder.predict(tmp)
                latent_activations = encoder.predict(tmp)
                shared_plot_queue.put((reconstruction_accuracy, history.history['val_loss'], encoded_data[:, 0], encoded_data[:, 1], latent_activations))
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
        autoencoder.save(save_model)

    try:
        shared_shutdown_event.set()
    except:
        pass

def plot_animate(i, shared_plot_queue, ax, xs, ys):
    if not shared_plot_queue.empty():
        accuracy, loss, encoded_data0, encoded_data1, latent_activations = shared_plot_queue.get(timeout=1)
        epochs = len(loss)
        loss_mean = sum(loss) / epochs
    else:
        return

    (ax1, ax2, ax3, ax4) = ax
    (ys1, ys2, ys3, ys4) = ys

    if len(xs) == 0:
        xs.append(epochs)
    else:
        xs.append(xs[-1] + epochs)
    ys1.append(accuracy)
    ys2.append(loss_mean)

    xs = xs[-PLOT_HISTORY:]
    ys1 = ys1[-PLOT_HISTORY:]
    ys2 = ys2[-PLOT_HISTORY:]

    ax1.clear()
    ax1.plot(xs, ys1, '-')
    ax2.clear()
    ax2.plot(xs, ys2, '-')
    ax3.clear()
    ax3.scatter(encoded_data0, encoded_data1, marker='.')
    ax4.clear()
    ax4.imshow(latent_activations, cmap='viridis', aspect='auto')

    ax1.set_xlabel('Epoch Count')
    ax1.set_ylabel('Accuracy')
    ax2.set_xlabel('Epoch Count')
    ax2.set_ylabel('Validation Loss')
    ax3.set_title('Latent Space')
    ax4.set_title('Latent Space Heatmap')
    ax4.set_xlabel('Latent Dimensions')
    ax4.set_ylabel('Datapoints')

def plot_worker(shared_shutdown_event, shared_plot_queue):
    try:
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2)
        fig.tight_layout()
        ax1.set_xlabel('Epoch Count')
        ax1.set_ylabel('Accuracy')
        ax2.set_xlabel('Epoch Count')
        ax2.set_ylabel('Validation Loss')
        ax3.set_title('Latent Space')
        ax4.set_title('Latent Space Heatmap')
        ax4.set_xlabel('Latent Dimensions')
        ax4.set_ylabel('Datapoints')
        xs = []
        ys1 = []
        ys2 = []
        ys3 = []
        ys4 = []
        x = 0
        a = ani.FuncAnimation(fig, plot_animate, fargs=(shared_plot_queue, (ax1, ax2, ax3, ax4), xs, (ys1, ys2, ys3, ys4)), interval=1000, cache_frame_data=False)
        plt.subplots_adjust(left=0.05, right=0.95, top=0.95, bottom=0.05)
        plt.margins(x=0, y=0)
        plt.show()
    except Exception as err:
        sys.stderr.write('\nPlot-Worker Exception: {}\n'.format(str(err)))
        sys.stderr.flush()
        shared_shutdown_event.set()
        return

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
    argparser.add_argument('--training-size', action='store', default=TRAINING_SIZE,
                           help='Set the amount of captured packets required to start the training phase.')
    argparser.add_argument('--batch-size', action='store', default=BATCH_SIZE,
                           help='Set the batch size used for the training phase.')
    argparser.add_argument('--learning-rate', action='store', default=LEARNING_RATE,
                           help='Set the (initial) learning rate for the optimizer.')
    argparser.add_argument('--plot', action='store_true', default=PLOT,
                           help='Show some model metrics using pyplot.')
    argparser.add_argument('--plot-history', action='store', default=PLOT_HISTORY,
                           help='Set the history size of Line plots. Requires --plot')
    argparser.add_argument('--tensorboard', action='store_true', default=TENSORBOARD,
                           help='Enable TensorBoard compatible logging callback.')
    argparser.add_argument('--tensorboard-logpath', action='store', default=TB_LOGPATH,
                           help='TensorBoard logging path.')
    argparser.add_argument('--use-sgd', action='store_true', default=VAE_USE_SGD,
                           help='Use SGD optimizer instead of Adam.')
    argparser.add_argument('--use-kldiv', action='store_true', default=VAE_USE_KLDIV,
                           help='Use Kullback-Leibler loss function instead of Mean-Squared-Error.')
    argparser.add_argument('--patience', action='store', default=ES_PATIENCE,
                           help='Epoch value for EarlyStopping. This value forces VAE fitting to if no improvment achieved.')
    args = argparser.parse_args()
    address = nDPIsrvd.validateAddress(args)

    LEARNING_RATE = args.learning_rate
    TRAINING_SIZE = args.training_size
    BATCH_SIZE    = args.batch_size
    PLOT          = args.plot
    PLOT_HISTORY  = args.plot_history
    TENSORBOARD   = args.tensorboard
    TB_LOGPATH    = args.tensorboard_logpath if args.tensorboard_logpath is not None else TB_LOGPATH
    VAE_USE_SGD   = args.use_sgd
    VAE_USE_KLDIV = args.use_kldiv
    ES_PATIENCE   = args.patience

    sys.stderr.write('Recv buffer size: {}\n'.format(nDPIsrvd.NETWORK_BUFFER_MAX_SIZE))
    sys.stderr.write('Connecting to {} ..\n'.format(address[0]+':'+str(address[1]) if type(address) is tuple else address))
    sys.stderr.write('PLOT={}, PLOT_HISTORY={}, LEARNING_RATE={}, TRAINING_SIZE={}, BATCH_SIZE={}\n\n'.format(PLOT, PLOT_HISTORY, LEARNING_RATE, TRAINING_SIZE, BATCH_SIZE))

    mgr = mp.Manager()

    shared_training_event = mgr.Event()
    shared_training_event.clear()

    shared_shutdown_event = mgr.Event()
    shared_shutdown_event.clear()

    shared_packet_queue = mgr.JoinableQueue()
    shared_plot_queue = mgr.JoinableQueue()

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
                                                      shared_packet_queue,
                                                      shared_plot_queue
                                                     ))
    keras_job.start()

    if PLOT is True:
        plot_job = mp.Process(target=plot_worker, args=(shared_shutdown_event, shared_plot_queue))
        plot_job.start()

    try:
        shared_shutdown_event.wait()
    except KeyboardInterrupt:
        print('\nShutting down worker processess..')

    if PLOT is True:
        plot_job.terminate()
        plot_job.join()
    nDPIsrvd_job.terminate()
    nDPIsrvd_job.join()
    keras_job.join(timeout=3)
    keras_job.terminate()
