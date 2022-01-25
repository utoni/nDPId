import math

import dash
from dash.dependencies import Input, Output, State
import dash_core_components as dcc
import dash_html_components as html
import dash_daq as daq
import dash_table as dt

import plotly.graph_objects as go

global shared_flow_dict

app = dash.Dash(__name__)

def generate_box():
    return { \
        'display': 'flex', 'flex-direction': 'row', \
        'box-shadow': '0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.24)', \
        'background-color': '#082255' \
    }

def generate_led_display(div_id, label_name):
    return daq.LEDDisplay( \
        id=div_id, \
        label={'label': label_name, 'style': {'color': '#C4CDD5'}}, \
        labelPosition='bottom', \
        value='0', \
        backgroundColor='#082255', \
        color='#C4CDD5', \
    )

def generate_gauge(div_id, label_name, max_value=10):
    return daq.Gauge( \
        id=div_id, \
        value=0, \
        label={'label': label_name, 'style': {'color': '#C4CDD5'}}, \
        max=max_value, \
        min=0, \
    )

app.layout = html.Div([
    html.Div(children=[
        dcc.Interval(id="default-interval", interval=1 * 2000, n_intervals=0),

        html.Div(children=[

            dt.DataTable(
                id='table-info',
                columns=[{'id': c.lower(), 'name': c, 'editable': False}
                         for c in ['Key', 'Value']],
            )

        ], style={'display': 'flex', 'flex-direction': 'row'}),

        html.Div(children=[
            dcc.Graph(
                id='piechart-flows',
                config={
                    'displayModeBar': False,
                },
            ),
        ], style={'padding': 10, 'flex': 1}),

        html.Div(children=[
            dcc.Graph(
                id='piechart-midstream-flows',
                config={
                    'displayModeBar': False,
                },
            ),
        ], style={'padding': 10, 'flex': 1}),

        html.Div(children=[
            dcc.Graph(
                id='piechart-risky-flows',
                config={
                    'displayModeBar': False,
                },
            ),
        ], style={'padding': 10, 'flex': 1}),
    ], style=generate_box()),

    html.Div(children=[
        dcc.Interval(id="graph-interval", interval=4 * 1000, n_intervals=0),
        dcc.Store(id="graph-traces"),

        html.Div(children=[
            dcc.Graph(
                id="graph-flows",
                config={
                    'displayModeBar': False,
                },
                style={'height':'60vh'},
            ),
        ], style={'padding': 10, 'flex': 1})
    ], style=generate_box()),
])

def build_gauge(key, max_value=100):
    gauge_max = int(max(max_value,
                        shared_flow_dict[key]))
    grad_green  = [0,                    int(gauge_max * 1/3)]
    grad_yellow = [int(gauge_max * 1/3), int(gauge_max * 2/3)]
    grad_red    = [int(gauge_max * 2/3), gauge_max]

    grad_dict   = \
        { \
            "gradient":True, \
            "ranges":{ \
                "green":grad_green, \
                "yellow":grad_yellow, \
                "red":grad_red \
            } \
        }

    return shared_flow_dict[key], gauge_max, grad_dict

def build_piechart(labels, values):
    lay = dict(
        plot_bgcolor = '#082255',
        paper_bgcolor = '#082255',
        font={"color": "#fff"},
        autosize=True,
        height=250,
        margin = {'autoexpand': False, 'b': 0, 'l': 0, 'r': 0, 't': 0, 'pad': 0},
        width = 500,
        uniformtext_minsize = 12,
        uniformtext_mode = 'hide',
    )

    return go.Figure(layout=lay, data=[go.Pie(labels=labels, values=values, textinfo='percent', textposition='inside')])

def prettifyBytes(bytes_received):
    size_names = ['B', 'KB', 'MB', 'GB', 'TB']
    if bytes_received == 0:
        i = 0
    else:
        i = min(int(math.floor(math.log(bytes_received, 1024))), len(size_names) - 1)
    p = math.pow(1024, i)
    s = round(bytes_received / p, 2)
    return '{:.2f} {}'.format(s, size_names[i])

@app.callback(output=[Output('table-info', 'data'),
                      Output('piechart-flows', 'figure'),
                      Output('piechart-midstream-flows', 'figure'),
                      Output('piechart-risky-flows', 'figure')],

              inputs=[Input('default-interval', 'n_intervals')])
def update_led_gauge(n):
    return [[{'key': 'Total JSON Events',        'value': shared_flow_dict['total-events']},
             {'key': 'Total JSON Bytes',         'value': prettifyBytes(shared_flow_dict['total-bytes'])},
             {'key': 'Total Flows',              'value': shared_flow_dict['total-flows']},
             {'key': 'Total Risky Flows',        'value': shared_flow_dict['total-risky-flows']},
             {'key': 'Total Midstream Flows',    'value': shared_flow_dict['total-midstream-flows']},
             {'key': 'Total Guessed Flows',      'value': shared_flow_dict['total-guessed-flows']},
             {'key': 'Total Not Detected Flows', 'value': shared_flow_dict['total-not-detected-flows']}],
            build_piechart(['Detected', 'Guessed', 'Undetected', 'Unclassified'],
                           [shared_flow_dict['current-detected-flows'],
                            shared_flow_dict['current-guessed-flows'],
                            shared_flow_dict['current-not-detected-flows'],
                            shared_flow_dict['current-flows']
                                - shared_flow_dict['current-detected-flows']
                                - shared_flow_dict['current-guessed-flows']
                                - shared_flow_dict['current-not-detected-flows']]),
            build_piechart(['Midstream', 'Not Midstream'],
                           [shared_flow_dict['current-midstream-flows'],
                            shared_flow_dict['current-flows'] -
                            shared_flow_dict['current-midstream-flows']]),
            build_piechart(['Risky', 'Not Risky'],
                           [shared_flow_dict['current-risky-flows'],
                            shared_flow_dict['current-flows'] -
                            shared_flow_dict['current-risky-flows']])]

@app.callback(output=[Output('graph-flows', 'figure'),
                      Output('graph-traces', 'data')],
              inputs=[Input('graph-interval', 'n_intervals'),
                      Input('graph-interval', 'interval')],
              state=[State('graph-traces', 'data')])
def update_graph(n, i, traces):
    if traces is None:
        traces = ([], [], [], [], [], [])

    max_bins = 50

    traces[0].append(shared_flow_dict['current-flows'])
    traces[1].append(shared_flow_dict['current-risky-flows'])
    traces[2].append(shared_flow_dict['current-midstream-flows'])
    traces[3].append(shared_flow_dict['current-guessed-flows'])
    traces[4].append(shared_flow_dict['current-not-detected-flows'])
    traces[5].append(shared_flow_dict['current-flows']
                        - shared_flow_dict['current-detected-flows']
                        - shared_flow_dict['current-guessed-flows']
                        - shared_flow_dict['current-not-detected-flows'])
    if len(traces[0]) > max_bins:
        traces[0] = traces[0][1:]
        traces[1] = traces[1][1:]
        traces[2] = traces[2][1:]
        traces[3] = traces[3][1:]
        traces[4] = traces[4][1:]
        traces[5] = traces[5][1:]

    i /= 1000.0
    x = list(range(max(n - max_bins, 0) * int(i), n * int(i), max(int(i), 1)))

    lay = dict(
        plot_bgcolor = '#082255',
        paper_bgcolor = '#082255',
        font={"color": "#fff"},
        xaxis = {
            'title': 'Time (sec)',
            "showgrid": False,
            "showline": False,
            "fixedrange": True,
            "tickmode": 'linear',
            "dtick": i,
        },
        yaxis = {
            'title': 'Flow Count',
            "showgrid": False,
            "showline": False,
            "zeroline": False,
            "fixedrange": True,
            "tickmode": 'linear',
            "dtick": 10,
        },
        autosize=True,
        bargap=0.01,
        bargroupgap=0,
        hovermode="closest",
        margin = {'b': 0, 'l': 0, 'r': 0, 't': 0, 'pad': 0},
        legend = {'borderwidth': 0},
    )

    fig = go.Figure(layout=lay)
    fig.update_xaxes(showgrid=True, gridwidth=1, gridcolor='#007ACE', zeroline=True, zerolinewidth=1)
    fig.update_yaxes(showgrid=True, gridwidth=1, gridcolor='#007ACE', zeroline=True, zerolinewidth=1)
    fig.add_trace(go.Scatter(
        x=x,
        y=traces[0],
        name='Current Active Flows',
    ))
    fig.add_trace(go.Scatter(
        x=x,
        y=traces[1],
        name='Current Risky Flows',
    ))
    fig.add_trace(go.Scatter(
        x=x,
        y=traces[2],
        name='Current Midstream Flows',
    ))
    fig.add_trace(go.Scatter(
        x=x,
        y=traces[3],
        name='Current Guessed Flows',
    ))
    fig.add_trace(go.Scatter(
        x=x,
        y=traces[4],
        name='Current Not Detected Flows',
    ))
    fig.add_trace(go.Scatter(
        x=x,
        y=traces[5],
        name='Current Unclassified Flows',
    ))

    return [fig, traces]

def web_worker(mp_shared_flow_dict):
    global shared_flow_dict

    shared_flow_dict = mp_shared_flow_dict

    app.run_server(debug=False)
