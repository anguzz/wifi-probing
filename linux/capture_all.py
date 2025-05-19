import csv
import time
import subprocess
import os
import sys
import threading
import itertools
from scapy.all import sniff, Dot11, Dot11ProbeReq, RadioTap

IFACE = "wlan0mon" #for example, add your interface
CHANNELS_2_4GHZ = list(range(1, 15))
CHANNELS_5GHZ = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]
CHANNELS_TO_SCAN = CHANNELS_2_4GHZ  + CHANNELS_5GHZ
CSV_FILENAME = "probe_requests_log.csv"
CSV_HEADERS = ["Timestamp", "Source MAC", "Vendor", "SSID", "Signal Strength (dBm)"]
VENDOR_DICT = {}

channel_lock = threading.Lock()
current_channel_index = 0

def load_mac_vendors(filepath=None):
    if filepath is None:
        # Try to find mac-vendor.txt in the same directory as the script first
        script_dir = os.path.dirname(__file__)
        local_mac_vendor_path = os.path.join(script_dir, "mac-vendor.txt")
        utils_mac_vendor_path = os.path.join(script_dir, "..", "utils", "mac-vendor.txt")

        if os.path.exists(local_mac_vendor_path):
            filepath = local_mac_vendor_path
        elif os.path.exists(utils_mac_vendor_path):
            filepath = utils_mac_vendor_path
        else:
            print(f"[WARNING] mac-vendor.txt not found in default locations. Please ensure it's available.")
            return {} # Return empty dict if not found


def lookup_vendor(mac, vendors_dict):
    normalized_mac = mac.replace(":", "").replace("-", "").lower()
    for prefix, vendor in vendors_dict.items():
        if prefix.lower() in normalized_mac:
            return vendor
    return "Unknown/VirtualizedMAC"

def setup_csv_file():
    with open(CSV_FILENAME, 'w', newline='') as f:
        csv.writer(f).writerow(CSV_HEADERS)

def append_to_csv(row):
    with open(CSV_FILENAME, 'a', newline='') as f:
        csv.writer(f).writerow(row)

def print_channel_header(index, total):
    sys.stdout.write("\033[H")      
    sys.stdout.write("\033[2K")   
    print("-" * 40)
    print(f"Channel {index + 1} of {total}")
    print("-" * 40)


# --- Channel Hopping Thread ---
def hop_channels(run_event):
    global current_channel_index
    for channel in itertools.cycle(CHANNELS_TO_SCAN):
        if not run_event.is_set():
            break
        with channel_lock:
            current_channel_index = CHANNELS_TO_SCAN.index(channel)
        subprocess.run(['sudo', 'iw', 'dev', IFACE, 'set', 'channel', str(channel)],
                       capture_output=True, text=True)
        print_channel_header(current_channel_index, len(CHANNELS_TO_SCAN))
        time.sleep(3)

# --- Packet Handler ---
def packet_handler(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        ssid = pkt[Dot11ProbeReq].info.decode(errors='ignore').strip() or "BROADCAST (WILDCARD)"
        mac = pkt.addr2 or "FF:FF:FF:FF:FF:FF"
        vendor = lookup_vendor(mac, VENDOR_DICT)
        signal = pkt[RadioTap].dBm_AntSignal if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], 'dBm_AntSignal') else "N/A"
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} | MAC: {mac} | Vendor: {vendor} | SSID: '{ssid}' | RSSI: {signal}")
        append_to_csv([timestamp, mac, vendor, ssid, signal])

# --- Main ---
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[ERROR] Please run this script with sudo.")
        exit(1)

    os.system("clear")
    print("Wi-Fi Probe Sniffer (Threaded Hopping) — Running...\n")

    VENDOR_DICT = load_mac_vendors("mac-vendor.txt")
    setup_csv_file()

    run_event = threading.Event()
    run_event.set()

    channel_thread = threading.Thread(target=hop_channels, args=(run_event,))
    channel_thread.daemon = True
    channel_thread.start()

    try:
        sniff(iface=IFACE, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\n[INFO] Sniffing stopped by user.")
        run_event.clear()
        channel_thread.join()
    finally:
        print(f"\n[INFO] Data saved to: {CSV_FILENAME}")
