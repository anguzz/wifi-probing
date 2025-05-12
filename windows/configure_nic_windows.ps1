function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-ErrorMsg {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

$npcapVersion = "1.82"
$npcapDownloadUrl = "https://npcap.com/dist/npcap-$($npcapVersion).exe"
$npcapInstallerName = "npcap-$($npcapVersion)-installer.exe"


Write-Info "Starting Wi-Fi Sniffing Environment Checker for Windows..."
Write-Info "This script requires Administrator privileges to run correctly."
Write-Host ""

function Check-NpcapStatus {
    $npcapIsInstalled = $false
    $npcapPath = "$env:ProgramFiles\Npcap" 
    $npcapDriverService = Get-Service -Name npf -ErrorAction SilentlyContinue 

    if (Test-Path $npcapPath) {
        Write-Info "Npcap installation directory found at: $npcapPath"
        
        if ($null -ne $npcapDriverService) {
            Write-Info "Npcap driver service ('npf') object found. Current Status: $($npcapDriverService.Status), StartType: $($npcapDriverService.StartType)"
            if (($npcapDriverService.Status -eq "Running") -and ($npcapDriverService.StartType -ne "Disabled")) {
                Write-Info "Npcap driver service ('npf') is running and enabled."
                $npcapIsInstalled = $true
            } else {
                Write-Warning "Npcap driver service ('npf') is present but is NOT running or is disabled."
                Write-Warning "Please ensure the 'Npcap Packet Driver (NPF)' service is started and its Start type is not 'Disabled' (e.g., set to Automatic or Manual)."
                Write-Warning "You can check this in the Services application (services.msc)."
            }
        } else {
            Write-Warning "Npcap driver service ('npf') was NOT detected."
            Write-Warning "This indicates the Npcap driver might not be installed correctly, or the service is missing."
            Write-Warning "Ensure Npcap was installed with administrator privileges and all components were installed."
            Write-Warning "If you just installed Npcap, a system restart might be required for the service to be properly registered and started."
        }
    } else {
        Write-ErrorMsg "Npcap installation directory NOT found at $npcapPath."
        Write-Warning "This suggests Npcap is not installed."
    }
    return $npcapIsInstalled
}


Write-Info "Step 1: Checking for Npcap installation..."
$npcapInstalled = Check-NpcapStatus

if (-not $npcapInstalled) {
    Write-ErrorMsg "Npcap does not appear to be installed or fully functional based on the checks above."
    Write-Warning "For raw 802.11 packet capture (like probe requests), Npcap is essential on Windows."
    
    $choiceDownload = Read-Host "[PROMPT] Npcap is not detected correctly. Would you like to download the Npcap $npcapVersion installer? (yes/no)"
    if ($choiceDownload -eq 'yes' -or $choiceDownload -eq 'y') {
        Write-Info "Attempting to download Npcap $npcapVersion from $npcapDownloadUrl..."
        $tempInstallerPath = Join-Path $env:TEMP $npcapInstallerName
        try {
            Invoke-WebRequest -Uri $npcapDownloadUrl -OutFile $tempInstallerPath -UseBasicParsing
            Write-Info "Npcap installer downloaded to: $tempInstallerPath"
            Write-Warning "Npcap installer has been downloaded."
            Write-Warning "IMPORTANT: You must now run this installer MANUALLY."
            Write-Warning "During the Npcap installation, ensure you select the following options:"
            Write-Warning "  1. CHECK 'Support raw 802.11 traffic (and monitor mode) for wireless adapters'."
            Write-Warning "  2. CHECK 'Install Npcap in WinPcap API-compatible Mode'."
            Write-Warning "  (Optional but recommended: CHECK 'Restrict Npcap driver access to Administrators only')."
            
            $choiceOpen = Read-Host "[PROMPT] Would you like to open the downloaded Npcap installer now? (yes/no)"
            if ($choiceOpen -eq 'yes' -or $choiceOpen -eq 'y') {
                Start-Process -FilePath $tempInstallerPath
                Write-Info "Npcap installer opened. Please complete the installation manually."
            } else {
                Write-Info "Please navigate to '$tempInstallerPath' and run the installer manually."
            }
            
            Write-Warning "After you have MANUALLY installed Npcap with the correct options (and potentially restarted your PC if prompted by the installer or if issues persist), you can re-run this script to verify."
            Read-Host "[PROMPT] Press Enter to continue this script after you have completed the Npcap installation (and any required restart)..."
            $npcapInstalled = Check-NpcapStatus 
            
        } catch {
            Write-ErrorMsg "An error occurred during Npcap download: $($_.Exception.Message)"
            Write-ErrorMsg "Please try downloading and installing Npcap manually from https://npcap.com"
        }
    } else {
        Write-Info "Npcap download skipped by user."
        Write-Warning "Please install Npcap manually from https://npcap.com, ensuring the correct options are selected as detailed above."
    }
}

if ($npcapInstalled) {
    Write-Info "Npcap appears to be installed and the NPF service is running."
    Write-Warning "CRITICAL REMINDER: For raw 802.11 capture, Npcap MUST have been installed with the following options selected:"
    Write-Warning "  1. 'Support raw 802.11 traffic (and monitor mode) for wireless adapters'."
    Write-Warning "  2. 'Install Npcap in WinPcap API-compatible Mode'."
    Write-Warning "If you encounter issues capturing raw 802.11 frames, ensure Npcap was installed with these options. Reinstall Npcap if unsure."
} else {
    Write-ErrorMsg "Npcap is still not detected as fully functional. Your sniffing script will likely fail."
    Write-ErrorMsg "Please ensure Npcap is installed correctly with the options mentioned above, and that the 'Npcap Packet Driver (NPF)' service is running."
    Write-Warning "A system RESTART may be required after Npcap installation or if the NPF service is not starting."
}
Write-Host ""

Write-Info "Step 2: Listing Wi-Fi adapters and checking for Monitor Mode support..."

$allPhysicalAdapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue
if ($allPhysicalAdapters) {
    Write-Info "All physical network adapters found on this system (for diagnostic purposes):"
    foreach ($physAdapter in $allPhysicalAdapters) {
        Write-Host "  - Name: $($physAdapter.Name), Description: $($physAdapter.InterfaceDescription), MediaType: $($physAdapter.MediaType), Status: $($physAdapter.Status), ifIndex: $($physAdapter.ifIndex)"
    }
} else {
    Write-Warning "Could not retrieve any physical network adapters using Get-NetAdapter. This is unusual."
}

$wifiAdapters = $allPhysicalAdapters | Where-Object {
    ($_.InterfaceDescription -like "*Wi-Fi*" -or $_.InterfaceDescription -like "*Wireless*" -or $_.Name -like "*Wi-Fi*" -or $_.Name -like "*Wireless*") -and 
    $_.MediaType -eq "Native 802.11"
}

if ($wifiAdapters) {
    Write-Info "Found the following potential Wi-Fi adapters for sniffing:"
    foreach ($adapter in $wifiAdapters) {
        Write-Host "--------------------------------------------------"
        Write-Info "Adapter Name: $($adapter.Name)"
        Write-Info "Description:  $($adapter.InterfaceDescription)"
        Write-Info "Status:       $($adapter.Status)"
        Write-Info "MAC Address:  $($adapter.MacAddress)"
        Write-Info "Interface GUID: $($adapter.InterfaceGuid)"
        Write-Info "Interface Index: $($adapter.ifIndex)"


        if ($adapter.Status -ne "Up") {
            Write-Warning "This Wi-Fi adapter is currently NOT 'Up' (Status: $($adapter.Status)). It may need to be enabled."
        }

        $netshOutput = netsh wlan show wirelesscapabilities interface="$($adapter.Name)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $netshOutput) {
            if ($netshOutput -match "Network Monitor Mode\s+:\s+Supported") {
                Write-Info "Monitor Mode: Supported (as reported by 'netsh wlan show wirelesscapabilities')"
            } elseif ($netshOutput -match "Network Monitor Mode\s+:\s+Not supported") {
                Write-Warning "Monitor Mode: Not Supported (as reported by 'netsh wlan show wirelesscapabilities')"
                Write-Warning "This adapter may not be able to capture raw 802.11 frames from unassociated devices."
            } else {
                Write-Warning "Monitor Mode: Could not determine support from 'netsh wlan show wirelesscapabilities' output for this adapter."
            }
        } else {
            Write-Warning "Monitor Mode: Could not retrieve wireless capabilities using 'netsh wlan show wirelesscapabilities' for this adapter (Interface: $($adapter.Name))."
            Write-Warning "This might happen if the WLAN AutoConfig service (WlanSvc) is not running or the adapter is in a strange state."
        }
    }
    Write-Host "--------------------------------------------------"
    Write-Info "Your Python sniffing script (using Scapy) will need to use one of these adapter names or GUIDs."
    Write-Info "The ability to capture raw 802.11 frames successfully depends on the adapter's driver, Npcap (correctly installed), and the 'Monitor Mode' support."
} else {
    Write-ErrorMsg "No Wi-Fi adapters suitable for sniffing were found after filtering."
    Write-Warning "Ensure your Wi-Fi adapter is enabled in 'Network Connections' (ncpa.cpl), drivers are installed,"
    Write-Warning "and its description or name contains 'Wi-Fi' or 'Wireless' and MediaType is 'Native 802.11'."
    Write-Warning "If you have a Wi-Fi adapter but it's not listed here, review the full list of physical adapters printed above for clues."
}
Write-Host ""

Write-Info "Step 3: Testing internet connectivity..."
$pingTarget = "8.8.8.8" 
$testConnectionResult = $false
try {
    $pingResult = Test-Connection -ComputerName $pingTarget -Count 2 -Quiet -ErrorAction SilentlyContinue
    if ($pingResult) {
        $testConnectionResult = $true
        Write-Info "Internet connectivity test to $pingTarget Succeeded (ICMP Echo Reply received)."
    }
} catch {} 

if (-not $testConnectionResult) {
    Write-Warning "Internet connectivity test to $pingTarget Failed."
    Write-Warning "If your sniffing tool needs to make API calls (e.g., to WiGLE), it may fail without internet."
}
Write-Host ""

Write-Info "Step 4: Summary and Advice"
Write-Info "--------------------------"
if ($npcapInstalled) {
    Write-Info "Npcap is detected, and the NPF service appears to be running. This is good."
} else {
    Write-ErrorMsg "Npcap is a critical prerequisite and is NOT detected as fully functional."
    Write-ErrorMsg "Please ensure Npcap is installed with the options mentioned earlier in this script, and the NPF service is running."
    Write-Warning "A system RESTART is often required after installing Npcap for the driver and service to function correctly."
}

Write-Info "When running your Python sniffing script (e.g., with Scapy):"
Write-Info " - Scapy will use Npcap to attempt to capture raw 802.11 frames."
Write-Info " - Success depends on your Wi-Fi adapter driver supporting this mode via Npcap."
Write-Info " - If an adapter showed 'Monitor Mode: Supported' via netsh, it has a higher chance of working, assuming Npcap is correctly installed."

Write-Info "Regarding internet connectivity while sniffing on Windows:"
Write-Info " - It *may* be possible to sniff raw 802.11 frames AND maintain internet on the SAME Wi-Fi adapter."
Write-Info " - This is highly dependent on the adapter, driver, and Npcap's interaction."
Write-Info " - If you lose internet when sniffing starts, you might need to:"
Write-Info "   a) Use a separate network interface for internet (e.g., Ethernet, a second Wi-Fi adapter)."
Write-Info "   b) Implement batch processing in your Python script (sniff offline, then connect to upload data)."
Write-Host ""
Write-Info "Script finished. Please review the messages above."
