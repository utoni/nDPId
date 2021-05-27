#!/usr/bin/env python3

from collections import deque
import dash
from dash.dependencies import Output, Input
import dash_core_components as dcc
import dash_html_components as html
import multiprocessing
import os
import plotly
import plotly.graph_objs as go
import random
import sys
import time

sys.path.append(os.path.dirname(sys.argv[0]) + '/../share/nDPId')
sys.path.append(os.path.dirname(sys.argv[0]) + '/../usr/share/nDPId')
try:
    import nDPIsrvd
    from nDPIsrvd import nDPIsrvdSocket, TermColor
except ImportError:
    sys.path.append(os.path.dirname(sys.argv[0]) + '/../../dependencies')
    import nDPIsrvd
    from nDPIsrvd import nDPIsrvdSocket, TermColor

mgr = multiprocessing.Manager()

global shared_flow_dict
shared_flow_dict = mgr.dict()

X = deque(maxlen = 20)
X.append(1)
  
Y = deque(maxlen = 20)
Y.append(1)
  
app = dash.Dash(__name__)
  
app.layout = html.Div(
    [
        dcc.Graph(id = 'live-graph', animate = True),
        dcc.Interval(
            id = 'graph-update',
            interval = 1000,
            n_intervals = 0
        ),
    ]
)


@app.callback(
    Output('live-graph', 'figure'),
    [ Input('graph-update', 'n_intervals') ]
)
def update_graph_scatter(n):
    X.append(X[-1]+1)
    Y.append(len(shared_flow_dict))
  
    data = plotly.graph_objs.Scatter(
            x=list(X),
            y=list(Y),
            name='Scatter',
            mode= 'lines+markers'
    )
  
    return {'data': [data],
            'layout' : go.Layout(xaxis=dict(range=[min(X),max(X)]),yaxis = dict(range = [min(Y),max(Y)]),)}

def web_worker():
    app.run_server()

    import time
    while True:
        s = str()
        for key in shared_flow_dict.keys():
            s += '{}, '.format(str(key))
        time.sleep(1)

def nDPIsrvd_worker_onJsonLineRecvd(json_dict, current_flow, global_user_data):
    if not 'flow_event_name' in json_dict:
        return True

    if json_dict['flow_event_name'] == 'new':
        shared_flow_dict[json_dict['flow_id']] = current_flow
    elif json_dict['flow_event_name'] == 'idle' or \
         json_dict['flow_event_name'] == 'end':
        if json_dict['flow_id'] in shared_flow_dict:
            del shared_flow_dict[json_dict['flow_id']]

    return True

def nDPIsrvd_worker(address, nDPIsrvd_global_user_data):
    sys.stderr.write('Recv buffer size: {}\n'.format(nDPIsrvd.NETWORK_BUFFER_MAX_SIZE))
    sys.stderr.write('Connecting to {} ..\n'.format(address[0]+':'+str(address[1]) if type(address) is tuple else address))

    nsock = nDPIsrvdSocket()
    nsock.connect(address)
    nsock.loop(nDPIsrvd_worker_onJsonLineRecvd, nDPIsrvd_global_user_data)

if __name__ == '__main__':
    argparser = nDPIsrvd.defaultArgumentParser()
    args = argparser.parse_args()
    address = nDPIsrvd.validateAddress(args)

    nDPIsrvd_job = multiprocessing.Process(target = nDPIsrvd_worker, args = (address, None))
    nDPIsrvd_job.start()

    web_job = multiprocessing.Process(target = web_worker, args = ())
    web_job.start()

    nDPIsrvd_job.join()
    web_job.terminate()
    web_job.join()
