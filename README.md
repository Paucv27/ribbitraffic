# Ribbitraffic

Local network traffic analysis tool to identify security patterns, detect anomalies, and ensure the security and efficiency of your local network

# Libraries Used

- Streamlit for the dashboard visualizations
- Pandas for the data processing
- Scapy for network packet capturing and packet processing
- Plotly for plotting charts with collected data
- logging for basic logs - one for terminal info, one for json logs (found in ./logs/ after running since *.log files are .gitignored)

# Usage (local)

```
git clone <this repo> <optional name>

pip install -r requirements.txt

streamlit run dashboard.py
```
If on Windows, probably need to install Npcap to run
| Might have to be Admin Command Prompt (Windows) / sudo (Linux)

**Dashboard refreshes every 1s, or you can manually refresh by pressing 'R'**

# Docker Usage

Packet capture requires access to host network interfaces, so full packet capture functionality may require elevated privileges and may not work identically inside Docker on Windows due to network isolation. Currently working on this so keep an eye out :p

```bash
docker build -t ribbitraffic .
```

# Findings / Learning


Most of the TCP traffic is probably one of these categories:

Address type | Likely meaning
--- | ---
192.168.x.x	| Devices on your home network
10.x.x.x | Private network devices
172.16–31.x.x | Private network devices
127.0.0.1 | Your own computer (localhost)
20.x.x.x & 52.x.x.x| Probably Microsoft
Public IPs | Internet servers (Google, Cloudflare, Microsoft, etc.)

- Reverse DNS lookups can provide useful hostnames but many IP addresses don't expose reverse DNS records which results in unknown hostnames (like the Microsoft ones, probably... | or devices in your private network, since they have private IP addresses!)

- Lots of different 5XXXX ports being used in my network -> ephimeral (temporary) ports assigned by my device's OS. Destination ports are generally more useful for identifying services such as HTTPS (443), DNS (53), etc.

- Using locks to prevent concurrency issues (in this case, sniff being a continuous packet getter, and the dashboard generating visualisations every 2 seconds from the processed packet data). I had already learned about this at uni through C/C++ concurrency, but doing it in Python refreshed some knowledge and actually let me apply it in a simple but useful scenario

- Streamlit is a nice data visualisation library! A lot more modern that MatPlotLib, but apparently less customisable...

# Potential Next Steps

Lots of different things I can do over time to improve this "dashboard"

- Containerising and integrating with Splunk

- Filtering specific IPs, protocols, ports...

- Add machine learning capabilities for anomaly detection

- Implement geographical IP mapping

- Create custom alerts based on traffic analysis patterns

- Add packet payload analysis options

- Create a real-time dashboard using a database and analytics tools (maybe using AWS?)

- Top talkers (highest bandwidth consumers)

- Top protocols by volume

- Packet size distribution analysis

- MAC address collection

- Export captured traffic statistics to CSV

- Generate summary reports

- Save and reload capture sessions
