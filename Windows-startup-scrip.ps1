<#
GCP Windows VM Startup Script for Ransomware Detector
- Downloads script from GCS bucket
- Sets up scheduled task to run every 3 minutes as SYSTEM
- Configures Ops Agent to monitor log file
#>

# Configuration
$BucketName = "your-bucket-name"
$ZipFileName = "ransomware-detector.zip"
$InstallDir = "C:\RansomwareDetector"
$LogDir = "C:\ProgramData\Ransomware-Detector"
$LogFile = "$LogDir\enc-files.log"
$ScriptPath = "$InstallDir\ransomware_detector.py"

# Create directories
New-Item -ItemType Directory -Force -Path $InstallDir
New-Item -ItemType Directory -Force -Path $LogDir

# Download and extract script from GCS bucket
gsutil cp gs://$BucketName/$ZipFileName $env:TEMP\$ZipFileName
Expand-Archive -Path $env:TEMP\$ZipFileName -DestinationPath $InstallDir -Force
Remove-Item $env:TEMP\$ZipFileName -Force

# Install Python if not already installed (optional)
if (-not (Test-Path "C:\Python311\python.exe")) {
    $pythonUrl = "https://www.python.org/ftp/python/3.11.4/python-3.11.4-amd64.exe"
    $installerPath = "$env:TEMP\python-installer.exe"
    Invoke-WebRequest -Uri $pythonUrl -OutFile $installerPath
    Start-Process -FilePath $installerPath -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1" -Wait
    Remove-Item $installerPath -Force
}

# Create scheduled task to run every 3 minutes
$action = New-ScheduledTaskAction -Execute "python" -Argument "$ScriptPath"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 3) -RepetitionDuration ([TimeSpan]::MaxValue)
$principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName "RansomwareDetector" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force

# Configure Ops Agent for log monitoring
$opsAgentConfigPath = "C:\Program Files\Google\Cloud Operations\Ops Agent\config\config.yaml"

# Backup existing config
if (Test-Path $opsAgentConfigPath) {
    Copy-Item -Path $opsAgentConfigPath -Destination "$opsAgentConfigPath.bak" -Force
}

# Create new config with ransomware log monitoring
$opsConfig = @"
logging:
  receivers:
    ransomware_logs:
      type: files
      include_paths:
        - $LogFile
  service:
    pipelines:
      ransomware_pipeline:
        receivers: [ransomware_logs]
"@

# Append to config if it exists, otherwise create new
if (Test-Path $opsAgentConfigPath) {
    $existingConfig = Get-Content -Path $opsAgentConfigPath -Raw
    if (-not ($existingConfig -match "ransomware_logs")) {
        $opsConfig | Out-File -Append -FilePath $opsAgentConfigPath
    }
} else {
    $opsConfig | Out-File -FilePath $opsAgentConfigPath
}

# Restart Ops Agent to apply configuration
Restart-Service -Name google-cloud-ops-agent -Force
