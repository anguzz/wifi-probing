
PING_TARGET="8.8.8.8"
PING_COUNT=1
NMCLI_AVAILABLE=false

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
    if command -v "$1" &> /dev/null; then
        if [ "$1" == "nmcli" ]; then
            NMCLI_AVAILABLE=true
        fi
        return 0
    else
        echoerror "$1 could not be found. Please install it."
        return 1
    fi
}

check_internet() {
    echoinfo "Checking internet connectivity (pinging $PING_TARGET)..."
    if ping -c "$PING_COUNT" "$PING_TARGET" &> /dev/null; then
        echoinfo "Internet connectivity confirmed."
        return 0
    else
        echowarn "Internet connectivity test failed."
        return 1
    fi
}

if [ "$EUID" -ne 0 ]; then
    echoerror "This script must be run as root. Please use sudo."
    exit 1
fi

REQUIRED_TOOLS=("ip" "iw" "airmon-ng" "ping")
OPTIONAL_TOOLS=("nmcli" "lspci" "lsusb" "ethtool")
MISSING_REQUIRED_TOOLS=()
MISSING_OPTIONAL_TOOLS=()

for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! check_command "$tool"; then
        MISSING_REQUIRED_TOOLS+=("$tool")
    fi
done

for tool in "${OPTIONAL_TOOLS[@]}"; do
    if ! check_command "$tool"; then
        MISSING_OPTIONAL_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_REQUIRED_TOOLS[@]} -ne 0 ]; then
    echoerror "The following REQUIRED tools are missing: ${MISSING_REQUIRED_TOOLS[*]}. Please install them."
    echoerror "Debian/Ubuntu: sudo apt install iproute2 iw aircrack-ng iputils-ping"
    exit 1
fi

if [ ${#MISSING_OPTIONAL_TOOLS[@]} -ne 0 ]; then
    echowarn "The following OPTIONAL tools are missing: ${MISSING_OPTIONAL_TOOLS[*]}. Functionality might be limited."
    echowarn "Debian/Ubuntu: sudo apt install network-manager pciutils usbutils ethtool"
fi

select_interface() {
    echoinfo "Scanning for wireless interfaces..."
    mapfile -t ALL_INTERFACES < <(iw dev | awk '/Interface/{print $2}')

    if [ ${#ALL_INTERFACES[@]} -eq 0 ]; then
        echoerror "No wireless interfaces found. Ensure your Wi-Fi adapter is enabled and drivers are loaded."
        return 1
    fi

    echoinfo "Available wireless interfaces:"
    select iface in "${ALL_INTERFACES[@]}" "Quit"; do
        if [ "$iface" == "Quit" ]; then
            echoinfo "Exiting."
            exit 0
        elif [[ -n "$iface" ]]; then
            SELECTED_IFACE="$iface"
            echoinfo "You selected: $SELECTED_IFACE"
            return 0
        else
            echowarn "Invalid selection. Please try again."
        fi
    done
    return 1 # Should not reach here
}

get_phy_device() {
    local iface="$1"
    PHY_DEVICE=$(iw dev "$iface" info | awk '/wiphy/{print "phy"$2}')
    if [ -z "$PHY_DEVICE" ]; then
        echoerror "Could not determine the phy device for $iface."
        return 1
    fi
    echoinfo "Physical device for $iface is $PHY_DEVICE."
    return 0
}


enable_monitor_mode() {
    if ! select_interface; then return 1; fi
    local target_iface="$SELECTED_IFACE"

    if iw dev "$target_iface" info | grep -q "type monitor"; then
        echowarn "$target_iface is already in monitor mode."
        MONITOR_IFACE="$target_iface" 
        return 0
    fi

    if ! get_phy_device "$target_iface"; then return 1; fi

    echoinfo "Attempting to enable monitor mode on $target_iface..."

    if $NMCLI_AVAILABLE && nmcli -t dev show "$target_iface" 2>/dev/null | grep -q "GENERAL.MANAGED:yes"; then
        echoinfo "Device $target_iface is managed by NetworkManager. Attempting to set to unmanaged..."
        if ! nmcli dev set "$target_iface" managed no; then
            echowarn "Failed to set $target_iface to unmanaged via nmcli. Continuing, but this might cause issues."
        else
            echoinfo "$target_iface set to unmanaged."
            sleep 1 
        fi
    fi

    # 2. Try airmon-ng start first (it often handles driver quirks better for *creating* monitor interfaces)
    #    We avoid 'check kill'
    echoinfo "Using airmon-ng to start monitor mode on $target_iface (without 'check kill')..."
    AIRMON_OUTPUT=$(sudo airmon-ng start "$target_iface" 2>&1)
    echo "$AIRMON_OUTPUT"
    MONITOR_IFACE=$(echo "$AIRMON_OUTPUT" | grep -oP 'monitor mode (vif )?enabled (for \[\w+\]\w+ )?on \[\w+\]\K\w+(mon|mon[0-9]*)' | head -n1)

    if [ -z "$MONITOR_IFACE" ]; then
        MONITOR_IFACE=$(iw dev | grep -B 2 "phy#${PHY_DEVICE#phy}" | grep "Interface" | awk '{print $2}' | xargs -I{} iw dev {} info | grep -B 1 "type monitor" | awk '/Interface/{print $2}' | head -n1)
    fi
    
    if [ -z "$MONITOR_IFACE" ]; then
        if iw dev "$target_iface" info 2>/dev/null | grep -q "type monitor"; then
            echoinfo "Original interface $target_iface is now in monitor mode."
            MONITOR_IFACE="$target_iface"
        else
            echoerror "Failed to enable monitor mode or identify the monitor interface using airmon-ng."
            echoerror "You may need to check 'iw dev' manually."
            echoinfo "Attempting to restore $target_iface to managed mode (best effort)..."
            restore_managed_mode_internal "$target_iface" "$PHY_DEVICE"
            return 1
        fi
    fi

    echoinfo "Monitor mode interface: $MONITOR_IFACE"

    if ! ip link show "$MONITOR_IFACE" | grep -q "state UP"; then
        echoinfo "Bringing $MONITOR_IFACE up..."
        if ! ip link set "$MONITOR_IFACE" up; then
            echoerror "Failed to bring $MONITOR_IFACE up."
            return 1
        fi
    fi

    # Verify
    if iw dev "$MONITOR_IFACE" info | grep -q "type monitor"; then
        echoinfo "Successfully enabled monitor mode on $MONITOR_IFACE."
        if [ "$MONITOR_IFACE" != "$target_iface" ]; then
            echo "$target_iface" > "/tmp/.original_iface_for_${MONITOR_IFACE}"
        fi
        echo "$PHY_DEVICE" > "/tmp/.phy_for_${MONITOR_IFACE}"
    else
        echoerror "Verification failed: $MONITOR_IFACE is not in monitor mode according to 'iw dev'."
        return 1
    fi
    return 0
}

restore_managed_mode_internal() {
    local iface_to_stop="$1" 
    local original_phy_path="/tmp/.phy_for_${iface_to_stop}"
    local original_iface_path="/tmp/.original_iface_for_${iface_to_stop}"
    local original_iface_name=""
    local phy_dev=""

    if [ -f "$original_iface_path" ]; then
        original_iface_name=$(cat "$original_iface_path")
        rm -f "$original_iface_path"
    else
    
        if [ -f "$original_phy_path" ]; then
            phy_dev=$(cat "$original_phy_path")
            rm -f "$original_phy_path"
        elif [ -n "$2" ]; then 
            phy_dev="$2"
        else
             if ! get_phy_device "$iface_to_stop" && [[ "$iface_to_stop" == *mon ]]; then
                local base_iface="${iface_to_stop%mon}"
                if ! get_phy_device "$base_iface"; then
                     echoerror "Cannot determine physical device for $iface_to_stop or its base."
                fi
             elif ! get_phy_device "$iface_to_stop"; then
                 echoerror "Cannot determine physical device for $iface_to_stop."
             fi
        fi

        if [[ "$iface_to_stop" == *mon ]] && ! iw dev "${iface_to_stop%mon}" info &>/dev/null && [ -n "$phy_dev" ]; then
             original_iface_name="${iface_to_stop%mon}"
        elif iw dev "$iface_to_stop" info &>/dev/null ; then
             original_iface_name="$iface_to_stop" # Assume it was changed in place
        else
             echoerror "Cannot determine the original interface name for $iface_to_stop."
             echowarn "You might need to manually configure your interfaces."
             if [ -n "$phy_dev" ]; then
                original_iface_name=$(iw dev | grep -B 2 "phy#${phy_dev#phy}" | grep "Interface" | awk '{print $2}' | grep -v "$iface_to_stop" | head -n1)
                if [ -z "$original_iface_name" ]; then
                    echoerror "Could not find a likely original interface on $phy_dev."
                    return 1
                else
                    echoinfo "Guessed original interface as $original_iface_name on $phy_dev."
                fi
             else
                return 1
             fi
        fi
    fi

    echoinfo "Attempting to restore managed mode..."
    echoinfo "Interface to stop/modify: $iface_to_stop"
    echoinfo "Target original interface name (best guess): $original_iface_name"


    if [[ "$iface_to_stop" == *mon ]] || grep -q "type monitor" <(iw dev "$iface_to_stop" info 2>/dev/null); then
        echoinfo "Using 'airmon-ng stop $iface_to_stop'..."
        airmon-ng stop "$iface_to_stop"
        sleep 1 
    else
        echoinfo "Interface $iface_to_stop does not appear to be an active airmon-ng monitor interface."
        echoinfo "Attempting direct manipulation with 'iw' on $original_iface_name."
    fi

    if ! ip link show "$original_iface_name" &> /dev/null; then
        echoerror "Original interface $original_iface_name not found after airmon-ng stop or initial check."
        echowarn "You may need to manually bring it up or reconfigure."
        if [ -n "$phy_dev" ]; then
            local new_iface_on_phy=$(iw dev | grep -B 2 "phy#${phy_dev#phy}" | grep "Interface" | awk '{print $2}' | head -n1)
            if [ -n "$new_iface_on_phy" ]; then
                echowarn "Found interface $new_iface_on_phy on the original physical device $phy_dev. Will attempt to configure this one."
                original_iface_name="$new_iface_on_phy"
            else
                echoerror "Still no interface found on $phy_dev."
                return 1
            fi
        else
             return 1
        fi
    fi


    echoinfo "Configuring $original_iface_name to managed mode..."
    ip link set "$original_iface_name" down || echowarn "Failed to bring $original_iface_name down (it might already be)."
    iw dev "$original_iface_name" set type managed || { echoerror "Failed to set $original_iface_name to managed mode."; return 1; }
    ip link set "$original_iface_name" up || { echoerror "Failed to bring $original_iface_name up."; return 1; }

    echoinfo "$original_iface_name set to managed mode and brought up."

    # if netmanager is available, tell it to manage the device again
    if $NMCLI_AVAILABLE; then
        echoinfo "Attempting to set $original_iface_name to managed by NetworkManager..."
        if nmcli dev set "$original_iface_name" managed yes; then
            echoinfo "$original_iface_name is now managed by NetworkManager."
            echoinfo "You may need to manually connect to a Wi-Fi network if it doesn't reconnect automatically."
            echoinfo "Try: sudo nmcli dev wifi connect <SSID> password <PASSWORD> ifname $original_iface_name"
            echoinfo "Or check 'nmcli dev status' and 'nmcli con show'."
        else
            echowarn "Failed to set $original_iface_name to managed via nmcli. NetworkManager might not control it."
            echowarn "Consider restarting NetworkManager: sudo systemctl restart NetworkManager"
        fi
    else
        echowarn "nmcli not found. You might need to configure $original_iface_name manually (e.g., wpa_supplicant, dhclient)."
    fi

    check_internet
    return 0
}


disable_monitor_mode() {
    echoinfo "Select the INTERFACE CURRENTLY IN MONITOR MODE to restore to managed mode."
    if ! select_interface; then return 1; fi
    local monitor_iface_to_disable="$SELECTED_IFACE"

    if ! iw dev "$monitor_iface_to_disable" info | grep -q "type monitor"; then
        echowarn "$monitor_iface_to_disable is not currently in monitor mode. Attempting to ensure it's managed anyway."
        # fall through to restore_managed_mode_internal which will try to set it to managed.
    fi

    restore_managed_mode_internal "$monitor_iface_to_disable"
}


show_status() {
    echoinfo "--- Wireless Interface Status (iw dev) ---"
    iw dev
    echo 
    if $NMCLI_AVAILABLE; then
        echoinfo "--- NetworkManager Device Status (nmcli dev status) ---"
        nmcli dev status
        echo 
        echoinfo "--- NetworkManager Connection Status (nmcli con show --active) ---"
        nmcli con show --active
        echo 
    fi
    echoinfo "--- IP Address Information (ip addr) ---"
    ip addr | grep -A 3 "wl\|eth\|en\|mon" 
    echo 
    check_internet
}


# ---  main mennu ---
while true; do
    echo ""
    echoinfo "Wireless Interface Mode Manager"
    echo "---------------------------------"
    echo "1. Enable Monitor Mode on an interface"
    echo "2. Disable Monitor Mode (Return to Managed Mode)"
    echo "3. Show Network Status"
    echo "4. Identify Chipset/Driver for an interface"
    echo "Q. Quit"
    echo "---------------------------------"
    read -r -p "Choose an option: " choice

    case "$choice" in
        1)
            enable_monitor_mode
            MONITOR_IFACE_NAME_FOR_USER=${MONITOR_IFACE:-"N/A"} 
            echoinfo "Monitor mode setup finished. Monitor interface should be: $MONITOR_IFACE_NAME_FOR_USER"
            ;;
        2)
            disable_monitor_mode
            ;;
        3)
            show_status
            ;;
        4)
            if select_interface; then
                target_iface="$SELECTED_IFACE"
                echoinfo "--- Identifying details for $target_iface ---"
                if get_phy_device "$target_iface"; then
                    if $NMCLI_AVAILABLE && command -v lspci &>/dev/null; then
                        PCI_PATH=$(nmcli -g GENERAL.HWADDR dev show "$target_iface" | sed 's/://g' | xargs -I{} grep {} /sys/class/net/*/address 2>/dev/null | cut -d '/' -f 5 | xargs -I{} readlink -f /sys/class/net/{}/device 2>/dev/null | xargs -I{} basename {} 2>/dev/null)
                        if command -v ethtool &>/dev/null && BUS_INFO=$(ethtool -i "$target_iface" 2>/dev/null | grep "bus-info:" | awk '{print $2}'); then
                           echoinfo "Bus Info: $BUS_INFO"
                           if [[ "$BUS_INFO" == *:* ]]; then # pci
                                lspci -vvv -s "$BUS_INFO" | grep -i -E 'network|wireless|product|vendor'
                           elif command -v lsusb &>/dev/null; then 
                                lsusb -v -s "$BUS_INFO"  
                           fi
                        fi
                    fi
                    if command -v ethtool &>/dev/null; then
                        echoinfo "Driver information (ethtool -i $target_iface):"
                        ethtool -i "$target_iface"
                    else
                        echowarn "ethtool not found, cannot get driver info."
                    fi
                fi
            fi
            ;;
        [Qq])
            echoinfo "Exiting."
            break
            ;;
        *)
            echowarn "Invalid option. Please try again."
            ;;
    esac
    echo 
done

exit 0