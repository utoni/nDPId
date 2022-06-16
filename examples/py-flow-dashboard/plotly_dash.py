import math

import dash

try:
    from dash import dcc
except ImportError:
    import dash_core_components as dcc

try:
    from dash import html
except ImportError:
    import dash_html_components as html

try:
    from dash import dash_table as dt
except ImportError:
    import dash_table as dt

from dash.dependencies import Input, Output, State

import dash_daq as daq

import plotly.graph_objects as go

global shared_flow_dict

app = dash.Dash(__name__)

def generate_box():
    return {
        'display': 'flex', 'flex-direction': 'row',
        'background-color': '#082255'
    }

def generate_led_display(div_id, label_name):
    return daq.LEDDisplay(
        id=div_id,
        label={'label': label_name, 'style': {'color': '#C4CDD5'}},
        labelPosition='bottom',
        value='0',
        backgroundColor='#082255',
        color='#C4CDD5',
    )

def generate_gauge(div_id, label_name, max_value=10):
    return daq.Gauge(
        id=div_id,
        value=0,
        label={'label': label_name, 'style': {'color': '#C4CDD5'}},
        max=max_value,
        min=0,
    )

def build_gauge(key, max_value=100):
    gauge_max = int(max(max_value,
                        shared_flow_dict[key]))
    grad_green  = [0,                    int(gauge_max * 1/3)]
    grad_yellow = [int(gauge_max * 1/3), int(gauge_max * 2/3)]
    grad_red    = [int(gauge_max * 2/3), gauge_max]

    grad_dict   = {
        "gradient":True,
        "ranges":{
            "green":grad_green,
            "yellow":grad_yellow,
            "red":grad_red
        }
    }

    return shared_flow_dict[key], gauge_max, grad_dict

def build_piechart(labels, values, color_map=None):
    lay = dict(
        plot_bgcolor = '#082255',
        paper_bgcolor = '#082255',
        font={"color": "#fff"},
        uirevision=True,
        autosize=True,
        height=250,
        margin = {'autoexpand': True, 'b': 0, 'l': 0, 'r': 0, 't': 0, 'pad': 0},
        width = 500,
        uniformtext_minsize = 12,
        uniformtext_mode = 'hide',
    )

    return go.Figure(layout=lay, data=[go.Pie(labels=labels, values=values, sort=False, marker_colors=color_map, textinfo='percent', textposition='inside')])

COLOR_MAP = {
    'piechart-flows': ['rgb(153, 153, 255)', 'rgb(153, 204, 255)', 'rgb(255, 204, 153)', 'rgb(255, 255, 255)'],
    'piechart-midstream-flows': ['rgb(255, 255, 153)', 'rgb(153, 153, 255)'],
    'piechart-risky-flows': ['rgb(255, 0, 0)', 'rgb(255, 128, 0)', 'rgb(255, 255, 0)', 'rgb(128, 255, 0)', 'rgb(153, 153, 255)'],
    'graph-flows': {'Current Active Flows': {'color': 'rgb(153, 153, 255)', 'width': 1},
                    'Current Risky Flows': {'color': 'rgb(255, 153, 153)', 'width': 3},
                    'Current Midstream Flows': {'color': 'rgb(255, 255, 153)', 'width': 3},
                    'Current Guessed Flows': {'color': 'rgb(153, 204, 255)', 'width': 1},
                    'Current Not-Detected Flows': {'color': 'rgb(255, 204, 153)', 'width': 1},
                    'Current Unclassified Flows': {'color': 'rgb(255, 255, 255)', 'width': 1},
                   },
}

def generate_tab_flow():
    return html.Div([
    html.Div(children=[
        dcc.Interval(id="tab-flow-default-interval", interval=1 * 2000, n_intervals=0),

        html.Div(children=[

            dt.DataTable(
                id='table-info',
                columns=[{'id': c.lower(), 'name': c, 'editable': False}
                         for c in ['Name', 'Total']],
                style_header={
                    'backgroundColor': '#082233',
                    'color': 'white'
                },
                style_data={
                    'backgroundColor': '#082244',
                    'color': 'white'
                },
            )

        ], style={'display': 'flex', 'flex-direction': 'row'}),

        html.Div(children=[
            dcc.Graph(
                id='piechart-flows',
                config={
                    'displayModeBar': False,
                },
                figure=build_piechart(['Detected', 'Guessed', 'Not-Detected', 'Unclassified'],
                                      [0, 0, 0, 0], COLOR_MAP['piechart-flows']),
            ),
        ], style={'padding': 10, 'flex': 1}),

        html.Div(children=[
            dcc.Graph(
                id='piechart-midstream-flows',
                config={
                    'displayModeBar': False,
                },
                figure=build_piechart(['Midstream', 'Not Midstream'],
                                      [0, 0], COLOR_MAP['piechart-midstream-flows']),
            ),
        ], style={'padding': 10, 'flex': 1}),

        html.Div(children=[
            dcc.Graph(
                id='piechart-risky-flows',
                config={
                    'displayModeBar': False,
                },
                figure=build_piechart(['Severy Risk', 'High Risk', 'Medium Risk', 'Low Risk', 'No Risk'],
                                      [0, 0], COLOR_MAP['piechart-risky-flows']),
            ),
        ], style={'padding': 10, 'flex': 1}),
    ], style=generate_box()),

    html.Div(children=[
        dcc.Interval(id="tab-flow-graph-interval", interval=4 * 1000, n_intervals=0),
        dcc.Store(id="graph-traces"),

        html.Div(children=[
            dcc.Graph(
                id="graph-flows",
                config={
                    'displayModeBar': True,
                    'displaylogo': False,
                },
                style={'height':'60vh'},
            ),
        ], style={'padding': 10, 'flex': 1})
    ], style=generate_box())
    ])

def generate_tab_other():
    return html.Div([
    html.Div(children=[
        dcc.Interval(id="tab-other-default-interval", interval=1 * 2000, n_intervals=0),

        html.Div(children=[
            dcc.Graph(
                id='piechart-events',
                config={
                    'displayModeBar': False,
                },
            ),
        ], style={'padding': 10, 'flex': 1}),
    ], style=generate_box())
    ])

TABS_STYLES = {
    'height': '34px'
}
TAB_STYLE = {
    'borderBottom': '1px solid #d6d6d6',
    'backgroundColor': '#385285',
    'padding': '6px',
    'fontWeight': 'bold',
}
TAB_SELECTED_STYLE = {
    'borderTop': '1px solid #d6d6d6',
    'borderBottom': '1px solid #d6d6d6',
    'backgroundColor': '#119DFF',
    'color': 'white',
    'padding': '6px'
}

app.layout = html.Div([
    dcc.Tabs(id="tabs-flow-dash", value="tab-flows", children=[
        dcc.Tab(label="Flow", value="tab-flows", style=TAB_STYLE,
                                                 selected_style=TAB_SELECTED_STYLE,
                                                 children=generate_tab_flow()),
        dcc.Tab(label="Other", value="tab-other", style=TAB_STYLE,
                                                  selected_style=TAB_SELECTED_STYLE,
                                                  children=generate_tab_other()),
    ], style=TABS_STYLES),
    html.Div(id="tabs-content")
])

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

              inputs=[Input('tab-flow-default-interval', 'n_intervals')])
def tab_flow_update_components(n):
    return [[{'name': 'JSON Events',        'total': shared_flow_dict['total-events']},
             {'name': 'JSON Bytes',         'total': prettifyBytes(shared_flow_dict['total-json-bytes'])},
             {'name': 'Layer4 Bytes',       'total': prettifyBytes(shared_flow_dict['total-l4-bytes'])},
             {'name': 'Flows',              'total': shared_flow_dict['total-flows']},
             {'name': 'Risky Flows',        'total': shared_flow_dict['total-risky-flows']},
             {'name': 'Midstream Flows',    'total': shared_flow_dict['total-midstream-flows']},
             {'name': 'Guessed Flows',      'total': shared_flow_dict['total-guessed-flows']},
             {'name': 'Not Detected Flows', 'total': shared_flow_dict['total-not-detected-flows']}],
            build_piechart(['Detected', 'Guessed', 'Not-Detected', 'Unclassified'],
                           [shared_flow_dict['current-detected-flows'],
                            shared_flow_dict['current-guessed-flows'],
                            shared_flow_dict['current-not-detected-flows'],
                            shared_flow_dict['current-flows']
                                - shared_flow_dict['current-detected-flows']
                                - shared_flow_dict['current-guessed-flows']
                                - shared_flow_dict['current-not-detected-flows']],
                           COLOR_MAP['piechart-flows']),
            build_piechart(['Midstream', 'Not Midstream'],
                           [shared_flow_dict['current-midstream-flows'],
                            shared_flow_dict['current-flows'] -
                            shared_flow_dict['current-midstream-flows']],
                           COLOR_MAP['piechart-midstream-flows']),
            build_piechart(['Severe', 'High', 'Medium', 'Low', 'No Risk'],
                           [shared_flow_dict['current-risky-flows-severe'],
                            shared_flow_dict['current-risky-flows-high'],
                            shared_flow_dict['current-risky-flows-medium'],
                            shared_flow_dict['current-risky-flows-low'],
                            shared_flow_dict['current-flows'] -
                            shared_flow_dict['current-risky-flows']],
                           COLOR_MAP['piechart-risky-flows'])]

@app.callback(output=[Output('graph-flows', 'figure'),
                      Output('graph-traces', 'data')],
              inputs=[Input('tab-flow-graph-interval', 'n_intervals'),
                      Input('tab-flow-graph-interval', 'interval')],
              state=[State('graph-traces', 'data')])
def tab_flow_update_graph(n, i, traces):
    if traces is None:
        traces = ([], [], [], [], [], [])

    max_bins = 75

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
    x = list(range(max(n - max_bins, 0) * int(i), n * int(i), max(int(i), 0)))
    if len(x) > 0 and x[0] > 60:
        x = [round(t / 60, 2) for t in x]
        x_div = 60
        x_axis_title = 'Time (min)'
    else:
        x_div = 1
        x_axis_title = 'Time (sec)'
    min_x = max(0, x[0] if len(x) >= max_bins else 0)
    max_x = max((max_bins * i) / x_div, x[max_bins - 1] if len(x) >= max_bins else 0)

    lay = dict(
        plot_bgcolor = '#082255',
        paper_bgcolor = '#082255',
        font={"color": "#fff"},
        xaxis = {
            'title': x_axis_title,
            "showgrid": False,
            "showline": False,
            "fixedrange": True,
            "tickmode": 'linear',
            "tick0": round(max_bins / x_div, 2),
            "dtick": round(max_bins / x_div, 2),
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
        uirevision=True,
        autosize=True,
        bargap=0.01,
        bargroupgap=0,
        hovermode="closest",
        margin = {'b': 0, 'l': 0, 'r': 0, 't': 30, 'pad': 0},
        legend = {'borderwidth': 0},
    )

    fig = go.Figure(layout=lay)
    fig.update_xaxes(showgrid=True, gridwidth=1, gridcolor='#004D80', zeroline=True, zerolinewidth=1, range=[min_x, max_x])
    fig.update_yaxes(showgrid=True, gridwidth=1, gridcolor='#004D80', zeroline=True, zerolinewidth=1)
    fig.add_trace(go.Scatter(
        x=x,
        y=traces[0],
        name='Current Active Flows',
        mode='lines+markers',
        line=COLOR_MAP['graph-flows']['Current Active Flows'],
    ))
    fig.add_trace(go.Scatter(
        x=x,
        y=traces[1],
        name='Current Risky Flows',
        mode='lines+markers',
        line=COLOR_MAP['graph-flows']['Current Risky Flows'],
    ))
    fig.add_trace(go.Scatter(
        x=x,
        y=traces[2],
        name='Current Midstream Flows',
        mode='lines+markers',
        line=COLOR_MAP['graph-flows']['Current Midstream Flows'],
    ))
    fig.add_trace(go.Scatter(
        x=x,
        y=traces[3],
        name='Current Guessed Flows',
        mode='lines+markers',
        line=COLOR_MAP['graph-flows']['Current Guessed Flows'],
    ))
    fig.add_trace(go.Scatter(
        x=x,
        y=traces[4],
        name='Current Not-Detected Flows',
        mode='lines+markers',
        line=COLOR_MAP['graph-flows']['Current Not-Detected Flows'],
    ))
    fig.add_trace(go.Scatter(
        x=x,
        y=traces[5],
        name='Current Unclassified Flows',
        mode='lines+markers',
        line=COLOR_MAP['graph-flows']['Current Unclassified Flows'],
    ))

    return [fig, traces]

@app.callback(output=[Output('piechart-events', 'figure')],
              inputs=[Input('tab-other-default-interval', 'n_intervals')])
def tab_other_update_components(n):
    return [build_piechart(['Base', 'Daemon', 'Packet',
                            'Flow New', 'Flow Update', 'Flow End', 'Flow Idle',
                            'Flow Detection', 'Flow Detection-Updates', 'Flow Guessed', 'Flow Not-Detected'],
                           [shared_flow_dict['total-base-events'],
                            shared_flow_dict['total-daemon-events'],
                            shared_flow_dict['total-packet-events'],
                            shared_flow_dict['total-flow-new-events'],
                            shared_flow_dict['total-flow-update-events'],
                            shared_flow_dict['total-flow-end-events'],
                            shared_flow_dict['total-flow-idle-events'],
                            shared_flow_dict['total-flow-detected-events'],
                            shared_flow_dict['total-flow-detection-update-events'],
                            shared_flow_dict['total-flow-guessed-events'],
                            shared_flow_dict['total-flow-not-detected-events']])]

def web_worker(mp_shared_flow_dict, listen_host, listen_port):
    global shared_flow_dict

    shared_flow_dict = mp_shared_flow_dict

    try:
        app.run_server(debug=False, host=listen_host, port=listen_port)
    except KeyboardInterrupt:
        pass
