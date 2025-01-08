import threading
from queue import Queue
from dash import Dash, dcc, html, dash_table
from dash.dependencies import Output, Input, State
from scapy.all import sniff
import pandas as pd

# Queue for sharing data between threads
packet_queue = Queue()
packet_history = []  # Store captured packets

# Define a function to handle packet sniffing (using Scapy)
def packet_callback(packet):
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dest_ip = packet['IP'].dst
        protocol = packet['IP'].proto
        ttl = packet['IP'].ttl
        src_mac = packet.src
        dest_mac = packet.dst

        # Store packet data in the queue and history
        packet_data = {
            'Source MAC': src_mac,
            'Destination MAC': dest_mac,
            'Source IP': src_ip,
            'Destination IP': dest_ip,
            'Protocol': protocol,
            'TTL': ttl
        }
        packet_queue.put(packet_data)
        packet_history.append(packet_data)

# Function to start sniffing packets
def start_sniffing():
    print("Packet sniffer started using Scapy.")
    sniff(prn=packet_callback, store=0, filter="ip", iface="Wi-Fi", timeout=60)

# Start sniffing in a separate thread
threading.Thread(target=start_sniffing, daemon=True).start()

# Initialize Dash app
app = Dash(__name__)

# App layout
app.layout = html.Div([
    html.H1("Network Sniffer Dashboard"),
    
    # Filter Inputs
    html.Div([
        dcc.Input(id='filter-src-ip', type='text', placeholder='Source IP'),
        dcc.Input(id='filter-dest-ip', type='text', placeholder='Destination IP'),
        dcc.Input(id='filter-protocol', type='text', placeholder='Protocol (e.g., 6 for TCP, 17 for UDP)'),
        html.Button('Apply Filters', id='apply-filters', n_clicks=0),
    ], style={'marginBottom': '20px'}),
    
    # Save to CSV Button
    html.Button('Save to CSV', id='save-csv', n_clicks=0, style={'marginBottom': '20px'}),
    
    # Data Table
    dash_table.DataTable(
        id='packet-table',
        columns=[
            {"name": "Source MAC", "id": "Source MAC"},
            {"name": "Destination MAC", "id": "Destination MAC"},
            {"name": "Source IP", "id": "Source IP"},
            {"name": "Destination IP", "id": "Destination IP"},
            {"name": "Protocol", "id": "Protocol"},
            {"name": "TTL", "id": "TTL"}
        ],
        style_table={'overflowX': 'auto'},
        style_cell={'textAlign': 'left'},
    ),

    # Interval for auto-refresh
    dcc.Interval(id='interval', interval=1000, n_intervals=0)
])

# Callback to update the table with filtered data
@app.callback(
    Output('packet-table', 'data'),
    [Input('interval', 'n_intervals'),
     Input('apply-filters', 'n_clicks')],
    [State('filter-src-ip', 'value'),
     State('filter-dest-ip', 'value'),
     State('filter-protocol', 'value')]
)
def update_table(n, n_clicks, src_ip_filter, dest_ip_filter, protocol_filter):
    packets = []
    while not packet_queue.empty():
        packets.append(packet_queue.get())
    
    # Apply filters
    filtered_packets = packet_history
    if src_ip_filter:
        filtered_packets = [p for p in filtered_packets if p['Source IP'] == src_ip_filter]
    if dest_ip_filter:
        filtered_packets = [p for p in filtered_packets if p['Destination IP'] == dest_ip_filter]
    if protocol_filter:
        try:
            protocol_filter = int(protocol_filter)
            filtered_packets = [p for p in filtered_packets if p['Protocol'] == protocol_filter]
        except ValueError:
            pass  # Ignore invalid protocol filter

    return filtered_packets

# Callback to save data to CSV
@app.callback(
    Output('save-csv', 'children'),
    [Input('save-csv', 'n_clicks')]
)
def save_to_csv(n_clicks):
    if n_clicks > 0:
        df = pd.DataFrame(packet_history)
        df.to_csv('captured_packets.csv', index=False)
        return "Saved!"
    return "Save to CSV"

if __name__ == '__main__':
    print("Starting Dash app...")
    app.run_server(debug=True)
