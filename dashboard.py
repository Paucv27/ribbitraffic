import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from scapy.all import IP, TCP, UDP, ICMP, sniff, Packet
from collections import defaultdict
import time
from datetime import datetime
import threading
import warnings
import logging
from typing import Dict, List, Optional
import socket

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s]: %(message)s"
    )
logger = logging.getLogger(__name__)

COMMON_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    123: "NTP"
}


class PacketProcessor:
    """ Processes and analyses network packets """

    def __init__(self):
        self.protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
        }
        self.packet_data = []
        self.start_time = datetime.now()
        self.packet_count = 0
        self.lock = threading.Lock()

    def get_protocol_name(self, proto_num: int) -> str:
        """ Returns the protocol name for a given protocol number """
        return self.protocol_map.get(proto_num, f'OTHER({proto_num})')

    def process_packet(self, packet: Packet) -> None:
        """ Processes a single packet and extracts relevant information """
        # This can be further extended to enable the project to have parallel packet processing

        try:
            if IP in packet:
                # lock so that multiple threads don't modify packet_data at the same time
                with self.lock:

                    # extract core packet information
                    packet_info = {
                        'timestamp': datetime.now(),
                        'src_ip': packet[IP].src,
                        'src_hostname': resolve_hostname(packet[IP].src),
                        'dst_ip': packet[IP].dst,
                        'dst_hostname': resolve_hostname(packet[IP].dst),
                        'protocol': self.get_protocol_name(packet[IP].proto),
                        'size': len(packet),
                        'time_relative': (datetime.now() - self.start_time).total_seconds(),
                    }

                    # add source and destination ports for TCP or UDP
                    if TCP in packet:
                        packet_info.update({
                            'src_port': packet[TCP].sport,
                            'dst_port': packet[TCP].dport,
                        })
                    elif UDP in packet:
                        packet_info.update({
                            'src_port': packet[UDP].sport,
                            'dst_port': packet[UDP].dport,
                        })
                    
                    self.packet_data.append(packet_info)
                    self.packet_count += 1

                    if self.packet_count % 10 == 0:
                        logger.info(f"Captured {self.packet_count} packets so far")

                    # limit the size of packet_data to avoid memory issues
                    if len(self.packet_data) > 10000:
                        self.packet_data.pop(0)

        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")

    def get_dataframe(self) -> pd.DataFrame:
        """ Returns the packet data as a pandas DataFrame """
 
        with self.lock:
            return pd.DataFrame(self.packet_data)
        

def create_visualisations(df: pd.DataFrame) -> None:
    """ Creates dashboard visualisations for the packet data """

    if len(df) > 0:
        # Protocol distribution pie chart -----------
        # displays proportion of different protocols in the captured packets

        protocol_counts = df['protocol'].value_counts() 
        fig_protocol = px.pie(
            values=protocol_counts.values,
            names=protocol_counts.index,
            title='Protocol Distribution',
            labels={'names': 'Protocol', 'values': 'Packet Count'}
        )
        st.plotly_chart(fig_protocol, use_container_width='stretch')

        # Packets Timeline --------------------------
        # displays the number of packets captured per second over time

        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df_grouped = df.groupby(df['timestamp'].dt.floor('s')).size()
        fig_timeline = px.line(
            x = df_grouped.index,
            y = df_grouped.values,
            title='Packets per Second',
            labels={'x': 'Time', 'y': 'Packet Count'}
        )
        st.plotly_chart(fig_timeline, use_container_width='stretch')

        # Top Source IPs Bar Chart -------------------
        # displays the top 10 source IPs by packet count

        top_src_ips = df['src_ip'].value_counts().head(10)
        fig_src_ips = px.bar(
            x=top_src_ips.index,
            y=top_src_ips.values,
            title='Top 10 Source IPs',
            labels={'x': 'Source IP', 'y': 'Packet Count'}
        )
        st.plotly_chart(fig_src_ips, use_container_width='stretch')

        top_src_hosts = df['src_hostname'].value_counts().head(10)
        fig_src_hosts = px.bar(
            x=top_src_hosts.index,
            y=top_src_hosts.values,
            title='Top 10 Source Hostnames',
            labels={'x': 'Source Hostname', 'y': 'Packet Count'}
        )
        st.plotly_chart(fig_src_hosts, use_container_width='stretch')

        # Top Ports Used ----------------------------
        top_dst_ports = df['dst_port'].value_counts().head(20).reset_index()
        top_dst_ports.columns = ['Port', 'Count']
        top_dst_ports['Label'] = top_dst_ports['Port'].map(
            lambda p: f"{p} ({COMMON_PORTS[p]})" if p in COMMON_PORTS else str(p)
        )
        fig_dst_ports = px.bar(
            top_dst_ports,
            x='Label',
            y='Count',
            title='Top 20 Destination Ports',
            labels={'Label': 'Destination Port', 'Count': 'Packet Count'}
        )
        fig_dst_ports.update_xaxes(type='category')
        st.plotly_chart(fig_dst_ports, use_container_width='stretch')


def start_packet_capture() -> None:
    """ Start packet capture and processing in a separate thread """

    # create an instance of PacketProcessor to handle packet processing
    processor = PacketProcessor()

    def capture_packets():
        """ Capture packets using scapy's sniff function """
        try:
            sniff(prn=processor.process_packet, store=False)
        except Exception as e:
            logger.error(f"Error during scapy packet capture: {str(e)}")
    
    # ensure that the packet capturing operation does not block other operations like updating the dashboard in real-time
    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()

    # return the processor instance so that it can be used to retrieve packet data for visualizations
    return processor


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


def main():
    """ Main function to run the Streamlit dashboard """

    # bugfix: set the page configuration before any other Streamlit commands
    st.set_page_config(page_title="Network Traffic Dashboard", layout="wide")
    st.title("Real-time Network Traffic Analysis")
    
    # Initialize the packet processor and start packet capture if not already done
    if 'processor' not in st.session_state:
        st.session_state.processor = start_packet_capture()
        st.session_state.start_time = time.time()

    # Create Dashboard Layout
    col1, col2 = st.columns(2)

    # Get current data
    df = st.session_state.processor.get_dataframe()

    # Display Metrics
    with col1:
        # col1 displays the total number of packets captured so far
        st.metric("Total Packets", len(df))
    with col2:
        # col2 displays the duration of the packet capture session in seconds
        duration = time.time() - st.session_state.start_time
        st.metric("Capture Duration (s)", f"{duration:.2f}s")
    
    create_visualisations(df)

    # Display recent packets
    st.subheader("Recent Packets")
    if len(df) > 0:
        st.dataframe(
            df.tail(10)[['timestamp', 'src_ip', 'src_hostname', 'dst_ip', 'dst_hostname', 'protocol', 'size', 'src_port', 'dst_port']],
            use_container_width='stretch'
        )

    if st.button('Refresh'):
        st.rerun()  # refresh the dashboard to update visualizations and metrics
    
    time.sleep(2)  # add a small 2s delay to avoid overwhelming the CPU with rapid refreshes
    st.rerun() # rerun the Streamlit app to update the dashboard in real-time
    

if __name__ == "__main__":
    main()
