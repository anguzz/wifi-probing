
PING_TARGET="8.8.8.8" 
PING_COUNT=2


echoinfo() {
    echo "[INFO] $1"
}

echowarn() {
    echo "[WARN] $1"
}

echoerror() {
    echo "[ERROR] $1" >&2
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        echoerror "$1 could not be found. Please install it."
        return 1
    fi
    return 0
}

check_internet() {
    echoinfo "Checking internet connectivity (pinging $PING_TARGET)..."
    if ping -c "$PING_COUNT" "$PING_TARGET" &> /dev/null; then
        echoinfo "Internet connectivity confirmed."
        return 0
    else
        echowarn "Internet connectivity test failed. API calls might not work."
        return 1
    fi
}


if [ "$EUID" -ne 0 ]; then
    echoerror "This script must be run as root. Please use sudo."
    exit 1
fi

REQUIRED_TOOLS=("iw" "lspci" "lsusb" "airmon-ng" "ping" "nmcli" "ip") # Added nmcli and ip
MISSING_TOOLS=()
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! check_command "$tool"; then
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    echoerror "The following required tools are missing: ${MISSING_TOOLS[*]}. Please install them."
    echoerror "For example, on Debian/Ubuntu: sudo apt install iw pciutils usbutils aircrack-ng iputils-ping network-manager iproute2"
    exit 1
fi

echoinfo "Scanning for wireless interfaces..."

WIRELESS_INTERFACES=($(iw dev | awk '/Interface/{print $2}'))

if [ ${#WIRELESS_INTERFACES[@]} -eq 0 ]; then
    echoerror "No wireless interfaces found. Ensure your Wi-Fi adapter is enabled and drivers are loaded."
    exit 1
fi

echoinfo "Available wireless interfaces:"
select SELECTED_IFACE in "${WIRELESS_INTERFACES[@]}" "Quit"; do
    if [ "$SELECTED_IFACE" == "Quit" ]; then
        echoinfo "Exiting."
        exit 0
    elif [[ -n "$SELECTED_IFACE" ]]; then
        echoinfo "You selected: $SELECTED_IFACE"
        break
    else
        echowarn "Invalid selection. Please try again."
    fi
done

PHY_DEVICE=$(iw dev "$SELECTED_IFACE" info | awk '/wiphy/{print "phy"$2}')
if [ -z "$PHY_DEVICE" ]; then
    echoerror "Could not determine the phy device for $SELECTED_IFACE."
    exit 1
fi
echoinfo "Physical device for $SELECTED_IFACE is $PHY_DEVICE."

echoinfo "Attempting to identify chipset for $SELECTED_IFACE ($PHY_DEVICE)..."
PCI_INFO=$(lspci -vvv -s "$(iw dev "$SELECTED_IFACE" info | grep -oP 'phy#\K[0-9]+' | xargs -I{} ethtool -i wlan{} 2>/dev/null | grep bus-info | awk '{print $2}')" 2>/dev/null)
USB_INFO=$(lsusb -v -d "$(iw dev "$SELECTED_IFACE" info | grep -oP 'phy#\K[0-9]+' | xargs -I{} ethtool -i wlan{} 2>/dev/null | grep bus-info | awk '{print $2}')" 2>/dev/null) # This is a bit of a long shot, bus-info for USB is less direct

if [[ -n "$PCI_INFO" ]]; then
    CHIPSET_INFO=$(echo "$PCI_INFO" | grep -i -E 'network controller|wireless' | head -n1 | sed 's/.*: //')
    echoinfo "PCI Chipset (approximate): $CHIPSET_INFO"
elif [[ -n "$USB_INFO" ]]; then
    CHIPSET_INFO=$(echo "$USB_INFO" | grep -iE 'Product:|iProduct' | head -n1 | awk '{$1=""; print $0}' | xargs)
    echoinfo "USB Device (approximate): $CHIPSET_INFO"
else
    echowarn "Could not reliably determine chipset details via lspci or lsusb for $SELECTED_IFACE based on standard linking. Driver details below might be more helpful."
fi

echoinfo "Driver information for $SELECTED_IFACE:"
ethtool -i "$SELECTED_IFACE" 2>/dev/null || echowarn "Could not get driver info using ethtool for $SELECTED_IFACE."


echoinfo "--- Current Network Status ---"
PRIMARY_CONNECTION_INTERFACE=""
PRIMARY_CONNECTION_SSID=""
IP_ADDR_INFO=$(ip -4 addr show scope global | grep inet)
if [[ -n "$IP_ADDR_INFO" ]]; then
    echoinfo "Active global IP addresses found:"
    echo "$IP_ADDR_INFO"
    CURRENT_WIFI_CONNECTION=$(nmcli -t -f ACTIVE,DEVICE,SSID dev wifi list | grep '^yes' | head -n1)
    if [[ -n "$CURRENT_WIFI_CONNECTION" ]]; then
        PRIMARY_CONNECTION_INTERFACE=$(echo "$CURRENT_WIFI_CONNECTION" | cut -d':' -f2)
        PRIMARY_CONNECTION_SSID=$(echo "$CURRENT_WIFI_CONNECTION" | cut -d':' -f3)
        echoinfo "Currently connected to Wi-Fi SSID '$PRIMARY_CONNECTION_SSID' on interface '$PRIMARY_CONNECTION_INTERFACE'."
    fi
else
    echowarn "No active global IP addresses found. You may not be connected to the internet."
fi
check_internet 

echoinfo "--- Attempting to Start Monitor Mode on $SELECTED_IFACE ---"
echoinfo "This may disconnect you from your current Wi-Fi network temporarily or permanently depending on your adapter/driver."

echoinfo "Running 'airmon-ng check kill' to stop potentially interfering processes..."
airmon-ng check kill
sleep 2 

echoinfo "Starting monitor mode on $SELECTED_IFACE using airmon-ng..."
AIRMON_OUTPUT=$(airmon-ng start "$SELECTED_IFACE" 2>&1)
echo "$AIRMON_OUTPUT" 


MONITOR_IFACE=$(echo "$AIRMON_OUTPUT" | grep -oP 'monitor mode (vif )?enabled (for \[\w+\]\w+ )?on \[\w+\]\K\w+(mon|mon[0-9])' | head -n1)

if [ -z "$MONITOR_IFACE" ]; then
    MONITOR_IFACE=$(iw dev | awk '/Interface/{iface=$2} /type monitor/{print iface; exit}')
fi

if [ -z "$MONITOR_IFACE" ]; then
    echoerror "Failed to start monitor mode or could not identify the monitor interface."
    echoerror "Please check the output above. You might need to manually identify it using 'iw dev'."
    echoinfo "Attempting to restore original interface $SELECTED_IFACE to managed mode (best effort)..."
    airmon-ng stop "${SELECTED_IFACE}mon" >/dev/null 2>&1 
    airmon-ng stop "$SELECTED_IFACE" >/dev/null 2>&1

    ifconfig "$SELECTED_IFACE" down 2>/dev/null
    iw dev "$SELECTED_IFACE" set type managed 2>/dev/null
    ifconfig "$SELECTED_IFACE" up 2>/dev/null
    echoinfo "Consider restarting NetworkManager if network issues persist: sudo systemctl restart NetworkManager"
    exit 1
fi

echoinfo "Monitor mode appears to be enabled on: $MONITOR_IFACE"

if ! iw dev "$MONITOR_IFACE" info | grep -q "type monitor"; then
    echowarn "$MONITOR_IFACE does not appear to be in monitor mode according to 'iw dev'."
    ifconfig "$MONITOR_IFACE" down
    iw dev "$MONITOR_IFACE" set type monitor
    ifconfig "$MONITOR_IFACE" up
    sleep 1
    if ! iw dev "$MONITOR_IFACE" info | grep -q "type monitor"; then
      echoerror "Still unable to confirm monitor mode for $MONITOR_IFACE."
    else
      echoinfo "$MONITOR_IFACE successfully set to monitor mode."
    fi
fi

echoinfo "--- Post-Monitor Mode Network Status ---"
INTERNET_OK=false
if [[ -n "$PRIMARY_CONNECTION_INTERFACE" && "$PRIMARY_CONNECTION_INTERFACE" != "$MONITOR_IFACE" && "$PRIMARY_CONNECTION_INTERFACE" != "$SELECTED_IFACE" ]]; then
    echoinfo "Checking connectivity via original primary interface $PRIMARY_CONNECTION_INTERFACE..."
    if check_internet; then
        INTERNET_OK=true
    fi
elif [[ -n "$PRIMARY_CONNECTION_INTERFACE" && (-e "/sys/class/net/$PRIMARY_CONNECTION_INTERFACE") ]]; then
    echoinfo "The original Wi-Fi interface was $SELECTED_IFACE (which might now be $MONITOR_IFACE or down)."
    echoinfo "Checking if any *other* wireless interface is connected or if $SELECTED_IFACE (if it still exists and is not $MONITOR_IFACE) is connected."

    ORIG_IFACE_STILL_EXISTS_AND_MANAGED=false
    if [[ -e "/sys/class/net/$SELECTED_IFACE" && "$SELECTED_IFACE" != "$MONITOR_IFACE" ]]; then
        if iw dev "$SELECTED_IFACE" info | grep -q "type managed"; then
            echoinfo "Original interface $SELECTED_IFACE still exists and is in managed mode."
            if nmcli -t -f DEVICE,STATE dev | grep "^$SELECTED_IFACE:" | cut -d':' -f2 | grep -q "connected"; then
                 echoinfo "$SELECTED_IFACE is reported as connected by NetworkManager."
                 ORIG_IFACE_STILL_EXISTS_AND_MANAGED=true
            fi
        fi
    fi

    if [[ "$ORIG_IFACE_STILL_EXISTS_AND_MANAGED" = true ]]; then
        if check_internet; then
            INTERNET_OK=true
        fi
    else
        echowarn "Original interface $SELECTED_IFACE might have been converted to $MONITOR_IFACE or is no longer in managed mode / connected."
        echowarn "Attempting a general internet check..."
        if check_internet; then 
            INTERNET_OK=true
        fi
    fi
else
    echoinfo "No prior primary Wi-Fi connection was noted. Performing general internet check..."
    if check_internet; then
        INTERNET_OK=true
    fi
fi

echoinfo "--- Summary ---"
echoinfo "Monitor Mode Interface: $MONITOR_IFACE"
if $INTERNET_OK; then
    echoinfo "Internet Connectivity: Seems OK. Your Python script can likely make API calls."
    echoinfo "Your Python script should use '$MONITOR_IFACE' for sniffing."
else
    echowarn "Internet Connectivity: FAILED or UNCERTAIN."
    echowarn "Your Python script should use '$MONITOR_IFACE' for sniffing, but may need to operate in offline/batch mode for API calls."
    echowarn "You might need a separate network interface (e.g., Ethernet or another Wi-Fi adapter) for internet access."
fi

echoinfo "To stop monitor mode and attempt to restore $MONITOR_IFACE (or $SELECTED_IFACE):"
echoinfo "  sudo airmon-ng stop $MONITOR_IFACE"
echoinfo "  Then, if needed: sudo systemctl restart NetworkManager"
echoinfo "Script finished."
