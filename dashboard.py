import json
import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import IP, TCP, UDP, ICMP, sniff, Packet
import time
from datetime import datetime
import threading
import logging
import socket
import ipaddress


# ==================================================================== GLOBALS


logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s]: %(message)s"
    )
logger = logging.getLogger(__name__)

COMMON_PORTS = {
    # --- Standard Web & Remote Access ---
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
    23: "Telnet",
    3389: "RDP",       # Windows Remote Desktop

    # --- Core Infrastructure & File Transfer ---
    53: "DNS",
    67: "DHCP (Srv)",  # Dynamic IP assignment server
    68: "DHCP (Cli)",  # Dynamic IP assignment client
    123: "NTP",        # Network Time Protocol
    161: "SNMP",       # Network Management
    21: "FTP",         # File Transfer Protocol
    69: "TFTP",        # Trivial File Transfer Protocol

    # --- Email Services ---
    25: "SMTP",        # Simple Mail Transfer (Outbound)
    587: "SMTP (TLS)", 
    110: "POP3",       # Post Office Protocol (Inbound)
    995: "POP3 (SSL)",
    143: "IMAP",       # Internet Message Access (Inbound)
    993: "IMAP (SSL)",

    # --- Active Directory & Authentication ---
    88: "Kerberos",
    389: "LDAP",       # Directory Services
    636: "LDAPS",      # Secure LDAP
    445: "SMB",        # Windows File Sharing

    # --- Databases ---
    1433: "MSSQL",     # Microsoft SQL Server
    3306: "MySQL",     # MySQL Database
    5432: "PostgreSQL",# PostgreSQL Database
    27017: "MongoDB",  # MongoDB

    # --- Development & Automation ---
    8080: "HTTP-Alt",  # Common for internal tools/Streamlit
    5000: "Flask/Dev", # Common development port
    9000: "Portainer"  # Docker management tools
}

DNS_LOCK = threading.Lock()


# ==================================================================== CLASSES


# "custom" log formatter for packet logs
class PacketLogFormatter(logging.Formatter):
    def format(self, record):
        # literally just returns the raw message, in this case packet_info in json format
        return record.getMessage()
    

class PacketProcessor:
    """ Processes and analyses network packets """

    def __init__(self):
        self.protocol_map = {
            1: 'ICMP',      # Ping and Network Error messages
            2: 'IGMP',      # Internet Group Management (Multicast)
            6: 'TCP',       # Transmission Control Protocol
            17: 'UDP',      # User Datagram Protocol
            41: 'IPv6',     # IPv6 encapsulation (6to4 tunnels)
            47: 'GRE',      # Generic Routing Encapsulation (VPNs)
            50: 'ESP',      # IPSec Encryption (VPN traffic)
            51: 'AH',       # IPSec Authentication
            89: 'OSPF',     # Open Shortest Path First (Router traffic)
            115: 'L2TP',    # Layer 2 Tunnelling Protocol
        }
        self.packet_data = []
        self.start_time = datetime.now()
        self.packet_count = 0
        self.lock = threading.Lock()

        self.packet_logger = logging.getLogger('packets')

        self.dns_cache = {}

    def get_protocol_name(self, proto_num: int) -> str:
        """ Returns the protocol name for a given protocol number """
        return self.protocol_map.get(proto_num, f'OTHER({proto_num})')

    def resolve_hostname(self, ip: str) -> str:
        """
        Resolves IP Address hostnames by creating a background lookup thread for efficiency. Stores results in local cache.
        """

        # get result from cache if we have it, otherwise set value to Resolving... to not spam duplicate threads
        with DNS_LOCK:
            if ip in self.dns_cache:
                return self.dns_cache[ip]
            self.dns_cache[ip] = 'Resolving...'

        # if no cache hit, this runs and tries to resolve the hostname for the specified IP
        def lookup():
            try:
                name = str(socket.gethostbyaddr(ip)[0])
            except Exception:
                logger.error(f"DNS Lookup couldn't resolve hostname for {ip} :( ")
                name = '???'
            with DNS_LOCK:
                self.dns_cache[ip] = name

        # threaded so it runs in background since DNS lookups can take a bit
        threading.Thread(target=lookup, daemon=True).start()

        # initially return 'Resolving...' to let user know DNS lookup is happening
        return 'Resolving...'
    

    def is_private_ip(self, ip: str) -> bool:
        """ 
        Check if an IP address is private 

        True if the IP is private (e.g. 192.168.x.x, 10.x.x.x, 172.16.x.x - 172.31.x.x), 
        
        False otherwise
        """
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def process_packet(self, packet: Packet) -> None:
        """ Processes a single packet and extracts relevant information """
        # This can be further extended to enable the project to have parallel packet processing

        try:
            if IP in packet:
                # lock so that multiple threads don't modify packet_data at the same time
                # e.g. capture thread is adding new packets while the main thread is reading packet_data to update visualizations
                # this ensures thread safety and prevents inconsistencies
                with self.lock:

                    # extract core packet information
                    packet_info = {
                        'timestamp': datetime.now().isoformat(),
                        'src_ip': packet[IP].src,
                        'src_hostname': self.resolve_hostname(packet[IP].src),
                        'src_location': 'Local' if self.is_private_ip(packet[IP].src) else 'Remote',
                        'dst_ip': packet[IP].dst,
                        'dst_hostname': self.resolve_hostname(packet[IP].dst),
                        'dst_location': 'Local' if self.is_private_ip(packet[IP].dst) else 'Remote',
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

                    if self.packet_count % 100 == 0:
                        logger.info(f"Captured {self.packet_count} packets so far")
                        
                    # save in log file
                    self.packet_logger.info(json.dumps(packet_info))

                    # limit the size of packet_data to avoid memory issues
                    if len(self.packet_data) > 10000:
                        self.packet_data.pop(0)

        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")

    def get_dataframe(self) -> pd.DataFrame:
        """ Returns the packet data as a pandas DataFrame """
 
        with self.lock:
            return pd.DataFrame(self.packet_data)


# ==================================================================== HELPERS


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
        st.plotly_chart(fig_protocol, width='stretch')

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
        st.plotly_chart(fig_timeline, width='stretch')

        # Top Source IPs Bar Chart -------------------
        # displays the top 10 source IPs by packet count

        # create a new column that combines source IP and hostname for better visualization
        df['src_label'] = (
            df['src_ip'].astype(str)
            + ' ('
            + df['src_hostname'].fillna('Unknown')
            + ')'
        )
        top_sources = df['src_label'].value_counts().head(10)
        fig_src = px.bar(
            x=top_sources.index,
            y=top_sources.values,
            title='Top 10 Source Hosts',
            labels={
                'x': 'Source (IP + Hostname)',
                'y': 'Packet Count'
            }
        )
        fig_src.update_xaxes(type='category')
        st.plotly_chart(fig_src, width='stretch')

        # Top Destination IPs Bar Chart -------------
        df['dst_label'] = (
            df['dst_ip'].astype(str)
            + ' ('
            + df['dst_hostname'].fillna('Unknown')
            + ')'
        )
        top_dst_ips = df['dst_label'].value_counts().head(10)
        fig_dst_ips = px.bar(
            x=top_dst_ips.index,
            y=top_dst_ips.values,
            title='Top 10 Destination IPs',
            labels={'x': 'Destination IP', 'y': 'Packet Count'}
        )

        st.plotly_chart(fig_dst_ips, width='stretch')

        # Top Ports Used ----------------------------
        valid_ports_df = df.dropna(subset=['dst_port']) # discard packets without dst port (ICMP/Ping)

        if len(valid_ports_df) > 0:
            top_dst_ports = valid_ports_df['dst_port'].value_counts().head(20).reset_index()
            top_dst_ports.columns = ['dst_port', 'count']

            top_dst_ports['dst_port'] = top_dst_ports['dst_port'].astype(int) # bugfix: stored as float in df

            top_dst_ports['Label'] = top_dst_ports['dst_port'].map(
                lambda p: f"{p} ({COMMON_PORTS[p]})" if p in COMMON_PORTS else f"Port {p}"
            )
            fig_dst_ports = px.bar(
                top_dst_ports,
                x='Label',
                y='count',
                title='Top 20 Destination Ports',
                labels={'Label': 'Destination Port', 'count': 'Packet Count'}
            )
            fig_dst_ports.update_xaxes(type='category')
            st.plotly_chart(fig_dst_ports, width='stretch')


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
    
    # ensure that the packet capturing operation does not block other operations
    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()

    # return the processor instance so that it can be used to retrieve packet data for visualizations
    return processor


# ==================================================================== STREAMLIT UI


@st.fragment(run_every=1.0) # ONLY refreshes the visualizations container every 1 second, instead of the whole thing (like it was before)
def render_live_dashboard():
    """ Renders the metrics and charts without reloading the entire main() script. Reruns every 1s """
    
    df = st.session_state.processor.get_dataframe()
    duration = time.time() - st.session_state.start_time

    # metrics layout
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Total Packets", len(df))
    with col2:
        st.metric("Capture Duration (s)", f"{duration:.2f}s")
    
    create_visualisations(df)

    st.subheader("Recent Packets")
    if len(df) > 0:
        display_cols = ['timestamp', 'src_ip', 'src_hostname', 'dst_ip', 'dst_hostname', 'dst_location', 'protocol', 'size', 'src_port', 'dst_port']
        # dynamically matches present columns to avoid premature TCP/UDP metric failures
        existing_cols = [c for c in display_cols if c in df.columns]
        st.dataframe(df.tail(10)[existing_cols], width='stretch')

    st.subheader("Top Conversations (By Packet Count)")
    if len(df) > 0:
        # pandas series (floating column that gets discarded if I dont put in a df)
        conversation = (
            df['src_hostname'].fillna('Unknown') + ' (' + df['src_location'].fillna('Unknown') + ':' + df['src_ip'].astype(str) + ') -> ' + 
            df['dst_hostname'].fillna('Unknown') + ' (' + df['dst_location'].fillna('Unknown') + ':' + df['dst_ip'].astype(str) + ')'
        )

        st.dataframe(
            conversation.value_counts().head(10).reset_index().rename(columns={'count': 'Count'}),
            width='stretch'
        )

    st.subheader("Top Conversations (By Volume)")
    if len(df) > 0:

        # new temp conversation column for formatting
        conversation = (
            df['src_hostname'].fillna('Unknown') + ' (' + df['src_location'].fillna('Unknown') + ':' + df['src_ip'].astype(str) + ') -> ' + 
            df['dst_hostname'].fillna('Unknown') + ' (' + df['dst_location'].fillna('Unknown') + ':' + df['dst_ip'].astype(str) + ')'
        )

        # get total bytes transferred
        volume_df = (
        df.groupby(conversation)['size']
        .sum()
        .reset_index()
        .rename(columns={'index': 'Conversation', 'size': 'Total Bytes'})
        .sort_values(by='Total Bytes', ascending=False)
        .head(10)
        )

        def format_bytes(b):
            if b >= 1_048_576: return f"{b / 1_048_576:.2f} MB"
            if b >= 1024: return f"{b / 1024:.2f} KB"
            return f"{b} B"

        volume_df['Data Transferred'] = volume_df['Total Bytes'].apply(format_bytes)

        st.dataframe(
            volume_df[['Conversation', 'Data Transferred']].reset_index(), 
            width='stretch'
        )


def main():
    """ Main function for the Streamlit dashboard execution flow """

    st.set_page_config(page_title="Ribbitraffic", layout="wide")
    st.title("Ribbitraffic | Real-time Network Traffic Analysis")
    
    # Initialize the packet processor once into persistent session memory
    if 'processor' not in st.session_state:
        # packet logger ------------
        logger.info('New logger created for packet info - logs stored in ./logs/')

        log_filename = f'packets_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'

        packet_logger = logging.getLogger('packets')
        packet_log_handler = logging.FileHandler(f'logs/{log_filename}')
        packet_log_handler.setFormatter(PacketLogFormatter())
        packet_logger.addHandler(packet_log_handler)
        packet_logger.setLevel(logging.INFO)
        packet_logger.propagate = False # prevents printing to terminal by root logger
        st.session_state.log_initialized = True
        st.session_state.log_filename = log_filename

        # packet sniffer ------------
        st.session_state.processor = start_packet_capture()
        st.session_state.start_time = time.time()
        logger.info('Sniffer created and bound to background thread')

        time.sleep(1)  
        st.rerun()  

    render_live_dashboard()
    

if __name__ == "__main__":
    main()

# Note: could use https://iplocation.io/ for remote IP info ?