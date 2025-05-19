# Overview

A CLI-based exploration into wireless probe request capturing and geolocation inference. Inspired by a wireless hacking presentation at [IVU ](https://www.irvineunderground.org/) by [alexlynd](https://github.com/AlexLynd?tab=repositories), this repo captures Wi-Fi probe requests, identifies SSIDs devices seek, and correlates these SSIDs with physical locations via WiGLE.

##  Directory structure
```powershell
WiFi-Probing/
├── .env
├── .gitignore
├── readme.md
├── __pycache__/
├── linux/
│   ├── capture_filtered.py
│   ├── capture_all.py
│   │   └── probe_requests_log.csv (generated)
│   ├── configure_nic.sh
│   └── run_wigle_on_csv.py
│       └── probe_requests_with_wigle_loc.csv (generated)
├── windows/
│   ├── capture.py
│   └── configure_nic_windows.ps1
├── utils/
│   ├── mac-vendor.txt
│   └── requirements.txt        
```


## Usage Notes

###  Linux :
Steps:

1) Run configure_nic.sh to set your interface to monitor mode.
2) Update the interface name in capture.py and start capturing.
3) Optionally, run python3 run_wigle_on_csv.py to enrich captured SSIDs with geolocation (use cautiously due to rate limits).

### Windows (work in progress)

1) Configure NIC to monitor mode with Npcap: `configure_nic_windows.ps1` attempts to streamline this process.
2) Call `C:\Windows\System32\Npcap\WlanHelper.exe Wi-Fi mode monitor` to put the card in monitor mode.
3) Run capture.py (channel hopping is currently a limitation on Windows preventing me from capturing any requests)  
 
### Next steps for linux
- Similar to the (https://github.com/mgp25/Probe-Hunter)  I want implement real-time SSID geolocation with WiGLE API:
 1) Option 1: Use a NIC supporting Virtual Functions (VFs).
 2) Option 2: Use dual NIC setup one for monitoring, one for internet connectivity.
- Rate limiting on WiGLE poses a current challenge, so I'll need to look into workarounds or ways to increase maximum daily API calls.
- Make the menu more comprehensive, better formatted. 

### Target setup 
Raspberry Pi 3B with ALFA Network AWUS036ACM Wi-Fi dongle, touch screen LCD, and battery power for portability. Aim to streamline scripts for NIC configuration, automated packet capture, and real-time display at system startup.

##  Probe Capturing Notes
- Sequential sniffing (one channel at a time) is slow. Background hopping + sniffing allows for higher capture rates.
- MAC randomization is a challenge—most modern devices (iOS 14+, Android 10+, Windows 10/11) implement it.
- You can attempt MAC de-randomization with deauth techniques, but they are out-of-scope for now.
- Windows does not offer channel hopping as easily through libraries like `Airmon-ng`
- Windows has to use [PNCAP](https://npcap.com/) with  802.11 packet capture enabled to be put in monitor mode.
- Using Scapy instead of tcpdump for packet capture and analysis because it simplifies parsing directly in Python.
- Scapy provides native access to packet fields, makes processing Wi-Fi probe requests simpler then tcpdump outputs
- Downloading the npcap on windows doesn't put the network card in monitor mode by default, you have to go to `C:\Windows\System32\Npcap\WlanHelper.exe` and calling `WlanHelper Wi-Fi mode monitor`
- Monitor Mode: wireless NIC can only passively listen to all 802.11 traffic in the air. Has no output connection though
- Managed Mode: Standard mode for network connections

# helper commands
windows:
- `netsh wlan show interfaces` 
- `netsh wlan show wirelesscapabilities`
- `WlanHelper Wi-Fi mode managed` 
- `WlanHelper Wi-Fi mode`

linux: 

# References
Some stuff I read while tinkering with this. 

- [Probe-Hunter](https://github.com/mgp25/Probe-Hunter) (took a lot of inspiration from this as it looks awesome)
- [ONZOsint/geowifi](https://github.com/GONZOsint/geowifi)
- https://api.wigle.net/
- https://wigle.net/account
- https://0xbharath.github.io/art-of-packet-crafting-with-scapy/scapy/sniffing/index.html
- [Network Adapter in Monitoring Mode - Rasp Pi 3B](https://classes.engineering.wustl.edu/ese205/core/index.php?title=Network_Adapter_in_Monitoring_Mode_-_Rasp_Pi_3B) 
- [A question about channel hopping on monitor mode (probe requests with scapy)](https://www.reddit.com/r/AskNetsec/comments/gq7f1b/a_question_about_channel_hopping_on_monitor_mode/) 
-  [802.11: Probe request/response packets? ](https://www.reddit.com/r/networking/comments/2n5o6x/80211_probe_requestresponse_packets/)  
- [ List of MAC addresses with vendors identities ](https://gist.github.com/aallan/b4bb86db86079509e6159810ae9bd3e4)  
- [Capturing Wi-Fi WLAN Packets on Windows for Free! ](https://www.cellstream.com/2017/02/22/capturing-wi-fi-wlan-packets-on-windows-for-free/) 
- [ Npcap Users' Guide ](https://npcap.com/guide/npcap-users-guide.html)

  # Preview
  Below is a preview of screenshots on current usage.

- `configure_nic.sh`    
 ![image](https://github.com/user-attachments/assets/753f0be4-6a20-42c1-9976-a401b15f889d)


- `capture.py`
![image](https://github.com/user-attachments/assets/25186138-14a7-4efd-912f-76d835fec3bd)

- `capture_probe_csv`
![image](https://github.com/user-attachments/assets/64a2c424-5e3a-4a2b-8271-8b98e7c69574)

- `run_wigle_on_csv.py`
  ![image](https://github.com/user-attachments/assets/f9752679-ffc3-4d57-a3b9-ef05361840c3)

- `probe_requests_with_wigle_loc.csv`
![image](https://github.com/user-attachments/assets/0723315e-4e53-4282-a505-e7cddbf0c2c6)

