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
20.x.x.x & 52.x.x.x| Probably Microsoft
Public IPs | Internet servers (Google, Cloudflare, Microsoft, etc.)

# What have I learnt?

- Most network traffic comes from your own device - I thought maybe watching a youtube video would cause a lot more traffic.
- Lots of different ports being used in my network -> ephimeral (temporary) ports used by my device for communication. Doesn't really mean much.
- Using locks to prevent concurrency issues (in this case, sniff being a continuous packet getter, and the dashboard generating visualisations every 2 seconds from the processed packet data). I had already learned about this at uni through C/C++ concurrency, but doing it in Python refreshed some knowledge and actually let me apply it in a simple but useful scenario.
- Streamlit is a good data visualisation library! A lot more modern that MatPlotLib, but apparently less customisable.
- How to basically use Scapy to get packets from my local network traffic.

# Potential Next Steps

- Add a filter dropdown for TCP/UDP/ICMP

- Add machine learning capabilities for anomaly detection

- Implement geographical IP mapping

- Create custom alerts based on traffic analysis patterns

- Add packet payload analysis options

- Create a real-time dashboard using a database and analytics tools (maybe using AWS?)