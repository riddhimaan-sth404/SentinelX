# Install Npcap for packet capture support
# Run as Administrator

Write-Host "Installing Npcap for packet capture..." -ForegroundColor Cyan

# Check if already installed
$npcapPath = "C:\Program Files\Npcap"
if (Test-Path $npcapPath) {
    Write-Host "Npcap already installed at $npcapPath" -ForegroundColor Green
    exit 0
}

# Download Npcap installer
$npcapUrl = "https://npcap.com/dist/npcap-1.75.exe"
$installerPath = "$env:TEMP\npcap-installer.exe"

Write-Host "Downloading Npcap installer..." -ForegroundColor Yellow
try {
    # Use TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $npcapUrl -OutFile $installerPath -UseBasicParsing
    
    if (-not (Test-Path $installerPath)) {
        Write-Host "Failed to download Npcap installer" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Running Npcap installer..." -ForegroundColor Yellow
    & $installerPath /S /loopback_support=yes /dlt_null=yes
    
    # Wait for installation
    Start-Sleep -Seconds 10
    
    # Verify installation
    if (Test-Path $npcapPath) {
        Write-Host "Npcap installed successfully!" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "Npcap installation may have failed or is pending restart" -ForegroundColor Yellow
        Write-Host "Please reboot and try again if Npcap is not available" -ForegroundColor Yellow
        exit 0
    }
} catch {
    Write-Host "Error downloading Npcap: $_" -ForegroundColor Red
    Write-Host "You can manually install from https://npcap.com/download.html" -ForegroundColor Yellow
    exit 1
}
