#!/usr/bin/env python3
import csv
import time
from scapy.all import sniff, Dot11, Dot11ProbeReq, RadioTap

CSV_FILENAME = "probe_requests_log.csv"
CSV_HEADERS = ["Timestamp", "Source MAC", "SSID", "Signal Strength (dBm)"]

def setup_csv_file():
    with open(CSV_FILENAME, 'w', newline='') as f:
        csv.writer(f).writerow(CSV_HEADERS)

def append_to_csv(row):
    with open(CSV_FILENAME, 'a', newline='') as f:
        csv.writer(f).writerow(row)

def packet_handler(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        ssid = pkt.info.decode(errors='ignore').strip() or "BROADCAST (WILDCARD)"
        mac = pkt.addr2 or "FF:FF:FF:FF:FF:FF"
        rssi = pkt[RadioTap].dBm_AntSignal if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], 'dBm_AntSignal') else "N/A"
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} | MAC: {mac} | SSID: '{ssid}' | RSSI: {rssi}")
        append_to_csv([timestamp, mac, ssid, rssi])

def main():
    print("[INFO] Starting probe request capture on Windows...")
    iface = "Wi-Fi 2" 
    setup_csv_file()

    try:
        sniff(iface=iface, prn=packet_handler, store=0)
    except PermissionError:
        print("[ERROR] You must run this script as administrator.")
    except Exception as e:
        print(f"[ERROR] Sniffing failed: {e}")

if __name__ == "__main__":
    main()
