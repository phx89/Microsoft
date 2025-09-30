#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Install and configure Grafana Alloy and Windows Exporter for monitoring
.DESCRIPTION
    This script installs Grafana Alloy and Windows Exporter on Windows machines,
    configures them with appropriate settings, and sets up Windows services.
.PARAMETER DataSourceUrl
    The Prometheus endpoint for metrics (without protocol)
.PARAMETER DataSourceUrl
    The Prometheus endpoint username (Basic-Auth)
.PARAMETER DataSourceUrl
    The Prometheus endpoint password (Basic-Auth)
.PARAMETER AlloyVersion
    Version of Grafana Alloy to install (default: latest)
.PARAMETER WindowsExporterVersion
    Version of Windows Exporter to install (default: latest)
.PARAMETER InstallPath
    Base installation path (default: C:\monitoring)
.EXAMPLE
    .\Install-MonitoringAgents.ps1 -DataSourceUrl "prometheus.monitoring.local" -DataSourceUser "admin" -DataSourceSecret "password"
#>

param(
    [string]$ClusterName = "",
    [string]$DataSourceUrl = "prometheus.monitoring.local",
    [string]$DataSourceUser = "admin",
    [string]$DataSourceSecret = "password",
    [string]$AlloyVersion = "latest",
    [string]$WindowsExporterVersion = "latest",
    [string]$InstallPath = "C:\Program Files\GrafanaLabs",
    [string]$LogLevel = "info",
    [string]$Collectors = "cpu,memory,logical_disk,net,os,process,service,system,textfile,memory,terminal_services,netframework"
)

# Global variables
$ErrorActionPreference = "Stop"
$LogFile = "$env:TEMP\monitoring-install.log"
$AlloyServiceName = "Alloy"
$WindowsExporterServiceName = "WindowsExporter"

# Logging function
function Write-Log {
    param(
        [string]$Message, 
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
    Add-Content -Path $LogFile -Value $logMessage
}

# Download function with improved error handling
function Get-File {
    param(
        [string]$Url, 
        [string]$OutputPath
    )
    
    Write-Log "Downloading from: $Url"
    try {
        # Ensure TLS 1.2 is enabled (required for GitHub downloads)
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        
        # Method 1: Try with Invoke-WebRequest (PowerShell 3.0+)
        try {
            Write-Log "Attempting download with Invoke-WebRequest..."
            $progressPreference = 'SilentlyContinue'  # Disable progress bar for speed
            Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing -UserAgent "PowerShell/MonitoringInstaller"
            Write-Log "Downloaded successfully to: $OutputPath"
            return
        }
        catch {
            Write-Log "Invoke-WebRequest failed: $($_.Exception.Message)" "WARN"
        }
        
        # Method 2: Try with WebClient with proper headers
        try {
            Write-Log "Attempting download with WebClient..."
            $webClient = New-Object System.Net.WebClient
            
            # Set user agent to avoid GitHub blocking
            $webClient.Headers.Add('User-Agent', 'PowerShell/MonitoringInstaller')
            
            # Handle GitHub redirects
            $webClient.Headers.Add('Accept', 'application/octet-stream')
            
            # Set timeout (30 seconds)
            $webClient.Timeout = 30000
            
            $webClient.DownloadFile($Url, $OutputPath)
            $webClient.Dispose()
            Write-Log "Downloaded successfully to: $OutputPath"
            return
        }
        catch {
            Write-Log "WebClient failed: $($_.Exception.Message)" "WARN"
            if ($webClient) { $webClient.Dispose() }
        }
        
        # Method 3: Try with System.Net.Http.HttpClient (PowerShell 5.0+)
        try {
            Write-Log "Attempting download with HttpClient..."
            Add-Type -AssemblyName System.Net.Http
            
            $httpClient = New-Object System.Net.Http.HttpClient
            $httpClient.DefaultRequestHeaders.Add('User-Agent', 'PowerShell/MonitoringInstaller')
            $httpClient.Timeout = [TimeSpan]::FromSeconds(30)
            
            $response = $httpClient.GetAsync($Url).Result
            $response.EnsureSuccessStatusCode()
            
            $fileStream = [System.IO.File]::Create($OutputPath)
            $response.Content.CopyToAsync($fileStream).Wait()
            $fileStream.Close()
            $httpClient.Dispose()
            
            Write-Log "Downloaded successfully to: $OutputPath"
            return
        }
        catch {
            Write-Log "HttpClient failed: $($_.Exception.Message)" "WARN"
            if ($httpClient) { $httpClient.Dispose() }
            if ($fileStream) { $fileStream.Close() }
        }
        
        # If all methods fail, throw an error
        throw "All download methods failed. Please check your internet connection and try again."
    }
    catch {
        Write-Log "Failed to download: $_" "ERROR"
        
        # Clean up partial download
        if (Test-Path $OutputPath) {
            Remove-Item $OutputPath -Force -ErrorAction SilentlyContinue
        }
        
        throw
    }
}

# Test if URL is accessible
function Test-DownloadUrl {
    param([string]$Url)
    
    try {
        Write-Log "Testing URL accessibility: $Url"
        $response = Invoke-WebRequest -Uri $Url -Method Head -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            Write-Log "URL is accessible"
            return $true
        }
    }
    catch {
        Write-Log "URL test failed: $($_.Exception.Message)" "WARN"
    }
    return $false
}

# Get latest release from GitHub
function Get-LatestRelease {
    param([string]$Repository)
    
    try {
        # Ensure TLS 1.2 is enabled
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        
        $apiUrl = "https://api.github.com/repos/$Repository/releases/latest"
        $headers = @{
            "User-Agent" = "PowerShell/MonitoringInstaller"
            "Accept" = "application/vnd.github.v3+json"
        }
        
        Write-Log "Fetching latest release for $Repository"
        $response = Invoke-RestMethod -Uri $apiUrl -Headers $headers -TimeoutSec 30
        $version = $response.tag_name.TrimStart('v')
        Write-Log "Latest version found: $version"
        return $version
    }
    catch {
        Write-Log "Failed to get latest release for $Repository" "ERROR"
        
        # Fallback versions if GitHub API fails
        switch ($Repository) {
            "grafana/alloy" { return "1.0.0" }
            "prometheus-community/windows_exporter" { return "0.25.1" }
            default { throw "No fallback version available for $Repository" }
        }
    }
}

# Service management functions
function Remove-ServiceCompletely {
    param([string]$ServiceName)
    
    try {
        # Check if service exists using WMI (more reliable than Get-Service)
        $service = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
        
        if ($service) {
            Write-Log "Found existing service: $ServiceName (State: $($service.State))"
            
            # Stop the service if it's running
            if ($service.State -eq "Running") {
                Write-Log "Stopping service: $ServiceName"
                Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                
                # Wait for service to stop
                $timeout = 30
                $count = 0
                do {
                    Start-Sleep -Seconds 1
                    $count++
                    $currentService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                } while ($currentService.Status -eq "Running" -and $count -lt $timeout)
                
                if ($currentService.Status -eq "Running") {
                    Write-Log "Force stopping service using taskkill..." "WARN"
                    # Try to force kill any related processes
                    $processName = [System.IO.Path]::GetFileNameWithoutExtension($service.PathName.Split('"')[1])
                    taskkill /F /IM "$processName.exe" /T 2>$null | Out-Null
                }
            }
            
            # Delete the service
            Write-Log "Deleting service: $ServiceName"
            $result = sc.exe delete $ServiceName 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Service deletion initiated successfully"
            } else {
                Write-Log "Service deletion may have issues: $result" "WARN"
            }
        }
        else {
            Write-Log "Service $ServiceName does not exist, skipping removal"
        }
    }
    catch {
        Write-Log "Error during service removal: $_" "WARN"
    }
}

function Wait-ForServiceDeletion {
    param([string]$ServiceName)
    
    Write-Log "Waiting for service deletion to complete..."
    
    $maxWaitTime = 60 # Maximum wait time in seconds
    $waitInterval = 2 # Check every 2 seconds
    $totalWaited = 0
    
    do {
        Start-Sleep -Seconds $waitInterval
        $totalWaited += $waitInterval
        
        # Check using multiple methods to ensure service is truly gone
        $serviceExists = $false
        
        # Method 1: Get-Service
        try {
            $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($svc) { $serviceExists = $true }
        } catch { }
        
        # Method 2: WMI
        try {
            $wmiSvc = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
            if ($wmiSvc) { $serviceExists = $true }
        } catch { }
        
        # Method 3: Registry check
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
            if (Test-Path $regPath) { $serviceExists = $true }
        } catch { }
        
        if ($serviceExists) {
            Write-Log "Service still exists, waiting... ($totalWaited/$maxWaitTime seconds)"
        }
        
    } while ($serviceExists -and $totalWaited -lt $maxWaitTime)
    
    if ($serviceExists) {
        Write-Log "Service deletion did not complete within $maxWaitTime seconds. Attempting to proceed anyway..." "WARN"
        Write-Log "You may need to reboot the system to fully remove the service." "WARN"
    } else {
        Write-Log "Service deletion completed successfully"
    }
}

function Install-WindowsService {
    param(
        [string]$ServiceName,
        [string]$BinaryPath,
        [string]$DisplayName,
        [string]$Description,
        [string]$StartupType = "Automatic"
    )
    
    try {
        # Stop and remove existing service if it exists
        Remove-ServiceCompletely -ServiceName $ServiceName
        
        # Wait for service deletion to complete and verify it's gone
        Wait-ForServiceDeletion -ServiceName $ServiceName
        
        Write-Log "Creating service: $ServiceName"
        
        # Try to create service with retry logic
        $maxRetries = 3
        $retry = 0
        $serviceCreated = $false
        
        while (-not $serviceCreated -and $retry -lt $maxRetries) {
            try {
                $retry++
                Write-Log "Attempt $retry to create service..."
                
                # Method 1: Use New-Service cmdlet
                New-Service -Name $ServiceName -BinaryPathName $BinaryPath -DisplayName $DisplayName -Description $Description -StartupType $StartupType -ErrorAction Stop
                $serviceCreated = $true
                Write-Log "Service created successfully using New-Service"
                
            } catch {
                Write-Log "New-Service failed (attempt $retry): $($_.Exception.Message)" "WARN"
                
                if ($retry -eq $maxRetries) {
                    # Final attempt: Use sc.exe directly
                    Write-Log "Final attempt using sc.exe..."
                    try {
                        $scResult = sc.exe create $ServiceName binPath= $BinaryPath displayName= $DisplayName start= auto 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            Write-Log "Service created successfully using sc.exe"
                            $serviceCreated = $true
                            
                            # Set description separately
                            sc.exe description $ServiceName $Description | Out-Null
                        } else {
                            throw "sc.exe create failed: $scResult"
                        }
                    } catch {
                        Write-Log "Both New-Service and sc.exe failed: $_" "ERROR"
                        throw "Could not create service after $maxRetries attempts. Last error: $_"
                    }
                } else {
                    Write-Log "Waiting 5 seconds before retry..."
                    Start-Sleep -Seconds 5
                }
            }
        }
        
        Write-Log "Starting service: $ServiceName"
        Start-Service -Name $ServiceName
        
        Write-Log "Service $ServiceName installed and started successfully"
    }
    catch {
        Write-Log "Failed to install service ${ServiceName}: $_" "ERROR"
        throw
    }
}

# Validate service status
function Test-ServiceHealth {
    param(
        [string]$ServiceName, 
        [int]$Port = 0
    )
    
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Log "Service $ServiceName not found" "ERROR"
        return $false
    }
    
    if ($service.Status -ne "Running") {
        Write-Log "Service $ServiceName is not running (Status: $($service.Status))" "ERROR"
        return $false
    }
    
    if ($Port -gt 0) {
        try {
            # PowerShell 5.1 compatible network test
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connection = $tcpClient.BeginConnect("localhost", $Port, $null, $null)
            $wait = $connection.AsyncWaitHandle.WaitOne(3000, $false)
            if ($wait) {
                $tcpClient.EndConnect($connection)
                $tcpClient.Close()
            } else {
                $tcpClient.Close()
                Write-Log "Service $ServiceName port $Port is not responding" "ERROR"
                return $false
            }
        }
        catch {
            Write-Log "Failed to test port $Port for service $ServiceName" "ERROR"
            return $false
        }
    }
    
    Write-Log "Service $ServiceName is healthy"
    return $true
}

function Install-GrafanaAlloy {
    Write-Log "Installing Grafana Alloy..."
    
    $alloyPath = "C:\Program Files\GrafanaLabs\alloy"
    $alloyBinary = "$alloyPath\alloy-installer-windows-amd64.exe"
    $alloyConfig = "$alloyPath\config.alloy"
    
    # Create directory
    New-Item -Path $alloyPath -ItemType Directory -Force | Out-Null
    
    # Get version
    if ($AlloyVersion -eq "latest") {
        $AlloyVersion = Get-LatestRelease "grafana/alloy"
    }
    
    # Download URL (zip file)
    $downloadUrl = "https://github.com/grafana/alloy/releases/download/v$AlloyVersion/alloy-installer-windows-amd64.exe.zip"
    $zipPath = "$alloyPath\alloy.zip"
    
    Write-Log "Downloading Grafana Alloy version $AlloyVersion"
    
    # Test URL before downloading
    if (-not (Test-DownloadUrl -Url $downloadUrl)) {
        throw "Download URL is not accessible: $downloadUrl"
    }
    
    Get-File -Url $downloadUrl -OutputPath $zipPath
    
    # Extract the zip file
    Write-Log "Extracting Grafana Alloy..."
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $alloyPath)
        
        # Clean up zip file
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

        Write-Log "Alloy extracted successfully"
    }
    catch {
        Write-Log "Failed to extract Alloy: $_" "ERROR"
        throw
        }

    # Run Installer in Silent-mode
    Write-Log "Run alloy installer $alloyBinary"
    Start-Process -FilePath "$alloyBinary" -ArgumentList "/S" -Wait
    Write-Log "Alloy installed"
    # Clean up installer file
    Remove-Item $alloyBinary -Force -ErrorAction SilentlyContinue
    
    # Create configuration
    Write-Log "Creating Grafana Alloy configuration"
    Update-AlloyConfig -ConfigPath $alloyConfig -AlloyPath $alloyPath
    
    # Restart service required after config creation
    Write-Log "Restarting Alloy service"
    Restart-Service -Name $AlloyServiceName -ErrorAction SilentlyContinue
    
    Write-Log "Grafana Alloy installation completed"
}

# Install Grafana Alloy (Deprecated, Issue with service run)
# function Install-GrafanaAlloyBinary {
#     Write-Log "Installing Grafana Alloy..."
    
#     $alloyPath = "$InstallPath\alloy"
#     $alloyBinary = "$alloyPath\alloy.exe"
#     $alloyConfig = "$alloyPath\config.alloy"
    
#     # Create directory
#     New-Item -Path $alloyPath -ItemType Directory -Force | Out-Null
    
#     # Get version
#     if ($AlloyVersion -eq "latest") {
#         $AlloyVersion = Get-LatestRelease "grafana/alloy"
#     }
    
#     # Download URL (zip file)
#     $downloadUrl = "https://github.com/grafana/alloy/releases/download/v$AlloyVersion/alloy-windows-amd64.exe.zip"
#     $zipPath = "$alloyPath\alloy.zip"
    
#     Write-Log "Downloading Grafana Alloy version $AlloyVersion"
    
#     # Test URL before downloading
#     if (-not (Test-DownloadUrl -Url $downloadUrl)) {
#         throw "Download URL is not accessible: $downloadUrl"
#     }
    
#     Get-File -Url $downloadUrl -OutputPath $zipPath
    
#     # Extract the zip file
#     Write-Log "Extracting Grafana Alloy..."
#     try {
#         Add-Type -AssemblyName System.IO.Compression.FileSystem
#         [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $alloyPath)
        
#         # Find and rename the extracted executable
#         $extractedExe = Get-ChildItem -Path $alloyPath -Name "*.exe" | Select-Object -First 1
#         if ($extractedExe) {
#             Move-Item -Path "$alloyPath\$extractedExe" -Destination $alloyBinary -Force
#         }
        
#         # Clean up zip file
#         Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        
#         Write-Log "Alloy extracted successfully"
#     }
#     catch {
#         Write-Log "Failed to extract Alloy: $_" "ERROR"
#         throw
#     }
    
#     # Create configuration
#     Write-Log "Creating Grafana Alloy configuration"
#     Update-AlloyConfig -ConfigPath $alloyConfig -AlloyPath $alloyPath
    
#     # Install as Windows service
#     $serviceBinary = "$alloyBinary run $alloyConfig"
#     Install-WindowsService -ServiceName $AlloyServiceName -BinaryPath $serviceBinary -DisplayName "Grafana Alloy" -Description "Grafana Alloy telemetry collector"
    
#     Write-Log "Grafana Alloy installation completed"
# }

# Install Windows Exporter
function Install-WindowsExporter {
    Write-Log "Installing Windows Exporter..."
    
    $exporterPath = "$InstallPath\windows_exporter"
    $exporterBinary = "$exporterPath\windows_exporter.exe"
    $exporterConfigFile = "$exporterPath\config.yaml"
    
    # Create directory
    New-Item -Path $exporterPath -ItemType Directory -Force | Out-Null
    
    # Get version
    if ($WindowsExporterVersion -eq "latest") {
        $WindowsExporterVersion = Get-LatestRelease "prometheus-community/windows_exporter"
    }
    
    # Download URL
    $downloadUrl = "https://github.com/prometheus-community/windows_exporter/releases/download/v$WindowsExporterVersion/windows_exporter-$WindowsExporterVersion-amd64.exe"
    
    Write-Log "Downloading Windows Exporter version $WindowsExporterVersion"
    
    # Test URL before downloading
    if (-not (Test-DownloadUrl -Url $downloadUrl)) {
        throw "Download URL is not accessible: $downloadUrl"
    }
    
    Get-File -Url $downloadUrl -OutputPath $exporterBinary

    # Create Config file

    Update-ExporterConfig $exporterConfigFile
    
    # Install as Windows service
    $serviceBinary = "`"$exporterBinary`" --config.file=`"$exporterConfigFile`""
    Install-WindowsService -ServiceName $WindowsExporterServiceName -BinaryPath $serviceBinary -DisplayName 'Windows Exporter' -Description 'Prometheus Windows Exporter'

    
    Write-Log "Windows Exporter installation completed"
}

# Create Windows Exporter configuration
function Update-ExporterConfig {
    param([string]$ConfigPath)
    
    $config = @"
# config.yaml - Minimal working configuration
collectors:
  enabled: "$Collectors"
web:
  listen-address: ":9182"
log:
  level: "$LogLevel"
"@

    Set-Content -Path $ConfigPath -Value $config -Encoding UTF8
    Write-Log "Windows Exporter configuration created at: $ConfigPath"
}


# Create Alloy configuration
function Update-AlloyConfig {
    param(
        [string]$ConfigPath,
        [string]$AlloyPath
    )
    
    $hostname = $env:COMPUTERNAME
    $AlloyPathEscaped = $AlloyPath -replace "\\", "\\"
    if ([string]::IsNullOrEmpty($ClusterName)) {
        $ClusterName = $hostname -replace '\d+', ''
        Write-Log "Variable Cluster is not provided, will use $ClusterName instead"
    }
    $config = @"
logging {
  level  = "$LogLevel"
  format = "logfmt"
}
// Scrape external Windows exporter
prometheus.scrape "external_windows_exporter" {
  targets = [
    {
      __address__ = "127.0.0.1:9182",  // Replace with actual Windows machine IP and port
    instance  = "$hostname",
    },
  ]
  // Scrape configuration
  scrape_interval = "15s"
  scrape_timeout  = "10s"
  metrics_path    = "/metrics"
  scheme          = "http"
  forward_to = [prometheus.remote_write.metrics_service.receiver]
}
// Configure remote write endpoint
prometheus.remote_write "metrics_service" {
  endpoint {
    url = "https://$DataSourceUrl/api/v1/write"
    // Basic authentication
    basic_auth {
      username = "$DataSourceUser"
      password = "$DataSourceSecret"
    }
  }
    external_labels = {
      cluster     = "$ClusterName",
    }
}
local.file_match "textfiles" {
  path_targets = [
    {
      __path__ = "$AlloyPathEscaped\\textfiles\\*.prom",
    },
  ]
}
"@

    Set-Content -Path $ConfigPath -Value $config -Encoding UTF8
    Write-Log "Alloy configuration created at: $ConfigPath"
}

# Validate installations
function Test-Installation {
    Write-Log "Validating installation..."
    
    $alloyHealthy = Test-ServiceHealth -ServiceName $AlloyServiceName -Port 12345
    $exporterHealthy = Test-ServiceHealth -ServiceName $WindowsExporterServiceName -Port 9182
    
    if ($alloyHealthy -and $exporterHealthy) {
        Write-Log "All services are healthy and running" "SUCCESS"
        
        Write-Log "=== Installation Summary ===" "SUCCESS"
        Write-Log "Grafana Alloy: Running on port 12345" "SUCCESS"
        Write-Log "Windows Exporter: Running on port 9182" "SUCCESS"
        Write-Log "Prometheus URL: https://$DataSourceUrl" "SUCCESS"
        Write-Log "Log file: $LogFile" "SUCCESS"
        
        return $true
    }
    else {
        Write-Log "Installation validation failed" "ERROR"
        return $false
    }
}

# Main execution
function Main {
    Write-Log "Starting monitoring agents installation..."
    Write-Log "Datasource URL: https://$DataSourceUrl"
    Write-Log "Installation Path: $InstallPath"
    
    try {
        # Create base installation directory
        New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
        
        # Install components
        Install-WindowsExporter
        Install-GrafanaAlloy
        
        # Wait for services to stabilize
        Start-Sleep -Seconds 10
        
        # Validate installation
        if (Test-Installation) {
            Write-Log "Installation completed successfully!" "SUCCESS"
            return 0
        }
        else {
            Write-Log "Installation completed with errors" "ERROR"
            return 1
        }
    }
    catch {
        Write-Log "Installation failed: $_" "ERROR"
        Write-Log "Check the log file for details: $LogFile" "ERROR"
        return 1
    }
}

# Run main function if script is executed directly
if ($MyInvocation.InvocationName -ne '.') {
    exit (Main)
}
