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
import sys

sys.path.append(os.path.dirname(sys.argv[0]) + '/../share/nDPId')
sys.path.append(os.path.dirname(sys.argv[0]) + '/../usr/share/nDPId')
try:
    import nDPIsrvd
    from nDPIsrvd import nDPIsrvdSocket
except ImportError:
    sys.path.append(os.path.dirname(sys.argv[0]) + '/../../dependencies')
    import nDPIsrvd
    from nDPIsrvd import nDPIsrvdSocket

mgr = multiprocessing.Manager()

global shared_flow_dict
shared_flow_dict = mgr.dict()

FLOW_COUNT_DATAPOINTS = 50

global live_flow_count_X
live_flow_count_X = deque(maxlen=FLOW_COUNT_DATAPOINTS)
live_flow_count_X.append(1)
global live_flow_count_Y
live_flow_count_Y = deque(maxlen=FLOW_COUNT_DATAPOINTS)
live_flow_count_Y.append(1)

live_flow_bars = ['risky', 'midstream', 'detected', 'guessed', 'not-detected']
fig = go.Figure()

app = dash.Dash(__name__)
app.layout = html.Div(
    [
        dcc.Graph(id='live-flow-count', animate=True),
        dcc.Graph(id='live-flow-bars',  animate=True, figure=fig),
        dcc.Interval(
            id='graph-update',
            interval=1000,
            n_intervals=0
        ),
    ]
)


@app.callback(
    Output('live-flow-count', 'figure'),
    [Input('graph-update', 'n_intervals')]
)
def update_graph_scatter(n):
    live_flow_count_X.append(live_flow_count_X[-1]+1)
    live_flow_count_Y.append(len(shared_flow_dict))

    data = plotly.graph_objs.Scatter(
        x=list(live_flow_count_X),
        y=list(live_flow_count_Y),
        name='Scatter',
        mode='lines+markers'
    )

    return {
            'data': [data],
            'layout':
            go.Layout(
                xaxis=dict(
                    range=[min(live_flow_count_X), max(live_flow_count_X)]
                ),
                yaxis=dict(
                    range=[min(live_flow_count_Y), max(live_flow_count_Y)]
                ),
            )}


@app.callback(
    Output('live-flow-bars', 'figure'),
    [Input('graph-update', 'n_intervals')]
)
def update_pie(n):
    values = [0, 0, 0, 0, 0]

    for flow_id in shared_flow_dict.keys():
        try:
            flow = shared_flow_dict[flow_id]
        except KeyError:
            continue

        if flow['is_risky'] is True:
            values[0] += 1

        if flow['is_midstream'] is True:
            values[1] += 1

        if flow['is_detected'] is True:
            values[2] += 1

        if flow['is_guessed'] is True:
            values[3] += 1

        if flow['is_not_detected'] is True:
            values[4] += 1

    # print(values)

    return {
            'data': [
                        go.Bar(name='', x=live_flow_bars, y=values)
                    ],
            'layout': go.Layout(yaxis=dict(range=[0, max(values)]))
           }


def web_worker():
    app.run_server()


def nDPIsrvd_worker_onFlowCleanup(instance, current_flow, global_user_data):
    del shared_flow_dict[current_flow.flow_id]

    return True

def nDPIsrvd_worker_onJsonLineRecvd(json_dict, instance, current_flow, global_user_data):
    if 'flow_id' not in json_dict:
        return True

    # print(json_dict)

    if json_dict['flow_id'] not in shared_flow_dict:
        shared_flow_dict[json_dict['flow_id']] = mgr.dict()
        shared_flow_dict[json_dict['flow_id']]['is_detected'] = False
        shared_flow_dict[json_dict['flow_id']]['is_guessed'] = False
        shared_flow_dict[json_dict['flow_id']]['is_not_detected'] = False
        shared_flow_dict[json_dict['flow_id']]['is_midstream'] = False
        shared_flow_dict[json_dict['flow_id']]['is_risky'] = False

    if 'flow_event_name' not in json_dict:
        return True

    if json_dict['flow_event_name'] == 'new':
        if 'midstream' in json_dict and json_dict['midstream'] != 0:
            shared_flow_dict[json_dict['flow_id']]['is_midstream'] = True
    elif json_dict['flow_event_name'] == 'guessed':
        shared_flow_dict[json_dict['flow_id']]['is_guessed'] = True
    elif json_dict['flow_event_name'] == 'not-detected':
        shared_flow_dict[json_dict['flow_id']]['is_not_detected'] = True
    elif json_dict['flow_event_name'] == 'detected':
        shared_flow_dict[json_dict['flow_id']]['is_detected'] = True
        shared_flow_dict[json_dict['flow_id']]['is_guessed'] = False
        if 'ndpi' in json_dict and 'flow_risk' in json_dict['ndpi']:
            shared_flow_dict[json_dict['flow_id']]['is_risky'] = True

    return True


def nDPIsrvd_worker(address, nDPIsrvd_global_user_data):
    sys.stderr.write('Recv buffer size: {}\n'
                     .format(nDPIsrvd.NETWORK_BUFFER_MAX_SIZE))
    sys.stderr.write('Connecting to {} ..\n'
                     .format(address[0]+':'+str(address[1])
                             if type(address) is tuple else address))

    nsock = nDPIsrvdSocket()
    nsock.connect(address)
    nsock.loop(nDPIsrvd_worker_onJsonLineRecvd,
               nDPIsrvd_worker_onFlowCleanup,
               nDPIsrvd_global_user_data)


if __name__ == '__main__':
    argparser = nDPIsrvd.defaultArgumentParser()
    args = argparser.parse_args()
    address = nDPIsrvd.validateAddress(args)

    nDPIsrvd_job = multiprocessing.Process(target=nDPIsrvd_worker,
                                           args=(address, None))
    nDPIsrvd_job.start()

    web_job = multiprocessing.Process(target=web_worker, args=())
    web_job.start()

    nDPIsrvd_job.join()
    web_job.terminate()
    web_job.join()
