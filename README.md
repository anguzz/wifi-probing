# Overview

This repo is a CLI-based exploration into wireless probe request capturing and geolocation inference. After attending a great talk at [IVU ](https://www.irvineunderground.org/) by [alexlynd](https://github.com/AlexLynd?tab=repositories) geared towards wireless hacking, I became curious in Preferred Network Lists (PNL) of Wi-Fi-enabled devices. I liked the idea that you could capture these probe requests, identify the SSIDs devices are searching for, and correlate those SSIDs to physical locations using WiGLE. I aim to explore this idea and possibly similar ones in this repo.

# Directory structure

WiFi-Probing/
├── .env                          
├── .gitignore
├── readme.md                   
├── __pycache__/                  
├── linux/                        
│   ├── capture.py                
│   │   └── probe_requests_log.csv             
│   ├── configure_nic.sh          
│   └── run_wigle_on_csv.py       
│       └── probe_requests_with_wigle_loc.csv (generated) 
├── windows/                      
│   ├── capture.py                
│   └── configure_nic_windows.ps1 (generated) 
├── utils/                        
│   ├── mac-vendor.txt            
│   └── requirements.txt          



# Usage Notes

##  Linux :
Steps:

Call `configure_nic.sh` and whichever interface you configure to be in listen mode add that to the `capture.py` file at the top, then start the capture.

If you want to run Wigle on all the logged devices run `python3 run_wigle_on_csv.py`. I'd advise against it since you'll more then likely get rate limited, or comb through `probe_requests_log.csv` and remove devices you don't want currently. 

Currently was able to run the python3 files and get valid entries and coordinates.
 
### Next steps for linux
- Similar to the (https://github.com/mgp25/Probe-Hunter) repo  I want to send captured SSIDs to the WiGLE API in real time, I have two options for this.
 1) Use a NIC that supports Virtual Functions (VFs) (e.g., via iw and mac80211 with proper driver support)
 2) Use a dedicated second wireless card or USB dongle, one for monitoring, the other for staying connected to the internet.
 3) I was messing with this and manually filtering out the wildcard/blank SSIDs logged in our CSV adds too much overhead. I'm going add logic on capture.py so we don't log any of these in the csv file.  

##  Windows 
- (work in progress)
I created a capture.py file for Windows. After configuring the network interface to be in monitor mode, using `WlanHelper Wi-Fi mode monitor`  I'm still looking into if its possible to channel hop since we can't use `Airmon-ng`. I have to look into if other ways are possible or if there is a work around. Currently the capture.py will not pick up anything despite being in monitor mode. 



##  Probe Capturing Notes
- Sequential sniffing (one channel at a time) is slow. Background hopping + sniffing allows for higher capture rates.
- MAC randomization is a challenge—most modern devices (iOS 14+, Android 10+, Windows 10/11) implement it.
- You can attempt MAC de-randomization with deauth techniques, but they are out-of-scope for now.
- Windows does not offer channel hopping as easily through libraries like `Airmon-ng`
- Windows has to use [PNCAP](https://npcap.com/) with  802.11 packet capture enabled to be put in monitor mode.
- Using Scapy instead of tcpdump for packet capture and analysis because it simplifies parsing directly in Python.
- Scapy provides native access to packet fields, makes processing Wi-Fi probe requests simpler then tcpdump outputs
- Windows does not offer channel hopping as easily through libraries like `Airmon-ng`
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


