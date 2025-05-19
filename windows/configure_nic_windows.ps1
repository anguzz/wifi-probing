windows/configure_nic_windows.ps1
# Function definitions for logging
function Write-Info { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-ErrorMsg { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

# Npcap configuration
$npcapVersion = "1.82" # Consider checking for the latest version if issues persist
$npcapUrl = "https://npcap.com/dist/npcap-$npcapVersion.exe"
$installerPath = Join-Path -Path $env:TEMP -ChildPath "npcap-$npcapVersion-installer.exe"
$wlanHelperPath = "C:\Windows\System32\Npcap\WlanHelper.exe" # Standard path

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script needs to be run as Administrator to function correctly, especially for enabling monitor mode."
    Write-Warning "Please re-run the script from an elevated PowerShell prompt."
    # Uncomment the next line to exit if not admin, or handle it as a strong suggestion.
    # Read-Host "Press Enter to exit..."; exit 1
}

Write-Info "Checking Npcap installation..."
$npcapInstalled = Test-Path (Join-Path -Path ${env:ProgramFiles} -ChildPath "Npcap")
$npfService = Get-Service -Name npf -ErrorAction SilentlyContinue

if (-not $npcapInstalled -or -not $npfService) {
    Write-Warning "Npcap not detected or 'npf' service missing."
    $response = Read-Host "[PROMPT] Download Npcap $npcapVersion now? (yes/no)"
    if ($response -match '^y(es)?$') {
        Write-Info "Downloading Npcap $npcapVersion..."
        try {
            Invoke-WebRequest -Uri $npcapUrl -OutFile $installerPath -UseBasicParsing -ErrorAction Stop
            Write-Info "Installer saved to $installerPath"
            Write-Warning "Please run the installer manually with the following options checked:"
            Write-Warning "- Support raw 802.11 traffic (and monitor mode) for wireless adapters"
            Write-Warning "- Install Npcap in WinPcap API-compatible Mode"
            Start-Process $installerPath
            Read-Host "After installing Npcap (and rebooting, if required by the installer), press Enter to continue this script..."
            # Re-check after installation attempt

            #TODO FIGURE OUT PATH 
            #TODO FIGURE OUT service name
            $npcapInstalled = Test-Path (Join-Path -Path ${env:ProgramFiles} -ChildPath "Npcap")
            $npfService = Get-Service -Name npf -ErrorAction SilentlyContinue
            if (-not $npcapInstalled -or -not $npfService) {
                Write-ErrorMsg "Npcap installation still not detected correctly. Please ensure it was installed with the recommended options. Exiting."
                exit 1
            }
            Write-Info "Npcap installation detected."
        }
        catch {
            Write-ErrorMsg "Failed to download Npcap installer. Error: $($_.Exception.Message)"
            Write-ErrorMsg "Please download and install Npcap manually from $npcapUrl with the options mentioned above."
            exit 1
        }
    } else {
        Write-ErrorMsg "Npcap is required for this script. Exiting."
        exit 1
    }
} else {
    Write-Info "Npcap is installed and 'npf' service is present."
}

Write-Info "Looking for active Wi-Fi adapters..."

# Method 1: Using InterfaceType (more reliable)
# InterfaceType 71 corresponds to IEEE 802.11 (Wi-Fi)
$wifiAdapter = Get-NetAdapter -Physical | Where-Object {
    $_.Status -eq 'Up' -and $_.InterfaceType -eq 71
} | Select-Object -First 1

# Method 2: Fallback to name/description matching if InterfaceType didn't find one
if (-not $wifiAdapter) {
    Write-Warning "No active Wi-Fi adapter found using InterfaceType 71. Trying name/description matching..."
    $wifiAdapter = Get-NetAdapter -Physical | Where-Object {
        $_.Status -eq 'Up' -and (
            $_.InterfaceDescription -like "*Wi-Fi*" -or
            $_.Name -like "*Wi-Fi*" -or
            $_.InterfaceDescription -like "*Wireless*" -or # Broader search
            $_.Name -like "*Wireless*"                     # Broader search
        )
    } | Select-Object -First 1
}

if (-not $wifiAdapter) {
    Write-ErrorMsg "No active Wi-Fi adapter found. Please ensure your Wi-Fi adapter is enabled and connected (Status 'Up')."
    Write-Info "You can list all physical adapters and their properties by running this command in PowerShell:"
    Write-Info 'Get-NetAdapter -Physical | Select-Object Name, InterfaceDescription, Status, InterfaceType | Format-Table -AutoSize'
    exit 1
}

Write-Info "Found adapter: $($wifiAdapter.Name) (Description: $($wifiAdapter.InterfaceDescription), Status: $($wifiAdapter.Status))"

if (-not (Test-Path $wlanHelperPath)) {
    Write-ErrorMsg "Npcap WlanHelper.exe not found at $wlanHelperPath. Npcap might not be installed correctly or the path is wrong."
    exit 1
}

Write-Info "Attempting to enable monitor mode on '$($wifiAdapter.Name)'..."
# Construct arguments carefully. The adapter name might contain spaces.
$arguments = """$($wifiAdapter.Name)"" mode monitor"
Write-Info "Executing: $wlanHelperPath $arguments"

try {
    # Start-Process will inherit admin rights if the script is run as admin.
    $process = Start-Process -FilePath $wlanHelperPath -ArgumentList $arguments -Wait -NoNewWindow -PassThru -ErrorAction Stop
    if ($process.ExitCode -ne 0) {
        Write-Warning "WlanHelper.exe exited with code $($process.ExitCode). This might indicate an issue enabling monitor mode."
        Write-Warning "Make sure you are running this script as Administrator and that your adapter supports monitor mode with Npcap."
    } else {
        Write-Info "WlanHelper.exe executed. Monitor mode *should* now be enabled on '$($wifiAdapter.Name)'."
        Write-Info "Note: Not all adapters/drivers successfully enter monitor mode even if WlanHelper reports success."
    }
}
catch {
    Write-ErrorMsg "Failed to execute WlanHelper.exe. Error: $($_.Exception.Message)"
    Write-Warning "Ensure Npcap is installed correctly and you are running the script as Administrator."
    exit 1
}

Write-Info "Verifying monitor mode status by checking internet connectivity..."
# This test is indicative, not definitive.
# Some setups might retain connectivity or lose it for other reasons.
if (Test-Connection -ComputerName 8.8.8.8 -Count 2 -Quiet -ErrorAction SilentlyContinue) {
    Write-Warning "Internet connection seems to be reachable. Monitor mode might *not* be fully enabled, or your setup allows connectivity in monitor mode."
    Write-Warning "True monitor mode often disrupts normal data traffic on the interface."
} else {
    Write-Info "Internet connection is not reachable. This suggests monitor mode is likely enabled."
}

Write-Info "Script finished. To disable monitor mode, you can try running:"
Write-Info "$wlanHelperPath ""$($wifiAdapter.Name)"" mode managed"
Write-Info "Or, often, disabling and re-enabling the Wi-Fi adapter in Network Connections resets it."