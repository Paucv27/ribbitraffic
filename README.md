# Ribbitraffic

Proof-of-concept local network traffic analysis tool to identify security patterns, detect anomalies, and ensure the security and efficiency of your local network

Foundation built from tutorial at https://www.freecodecamp.org/news/build-a-real-time-network-traffic-dashboard-with-python-and-streamlit/#heading-prerequisites

# Libraries Used

- Streamlit for the dashboard visualizations
- Pandas for the data processing
- Scapy for network packet capturing and packet processing
- Plotly for plotting charts with collected data

# Usage

In an admin command prompt (Windows):
```
pip install -r requirements.txt

streamlit run dashboard.py
```
If on linux, use sudo before the run command

# Findings


Most of the TCP traffic is probably one of these categories:

Address type | Likely meaning
--- | ---
192.168.x.x	| Devices on your home network
10.x.x.x | Private network devices
172.16–31.x.x | Private network devices
127.0.0.1 | Your own computer (localhost)
Public IPs | Internet servers (Google, Cloudflare, Microsoft, etc.)

# Potential Next Steps

- Add hostname resolution

- Add a Top 10 destination ports chart

- Add a filter dropdown for TCP/UDP/ICMP

- Add machine learning capabilities for anomaly detection

- Implement geographical IP mapping

- Create custom alerts based on traffic analysis patterns

- Add packet payload analysis options