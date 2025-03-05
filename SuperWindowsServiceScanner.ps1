Write-Host "---------------------------------------"
Write-Host "
Super
__        ___           _                                                 
\ \      / (_)_ __   __| | _____      _____                               
 \ \ /\ / /| | '_ \ / _` |/ _ \ \ /\ / / __|                              
  \ V  V / | | | | | (_| | (_) \ V  V /\__ \                              
   \_/\_/  |_|_| |_|\__,_|\___/ \_/\_/ |___/                              
 ____                  _            ____                                  
/ ___|  ___ _ ____   _(_) ___ ___  / ___|  ___ __ _ _ __  _ __   ___ _ __ 
\___ \ / _ \ '__\ \ / / |/ __/ _ \ \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 ___) |  __/ |   \ V /| | (_|  __/  ___) | (_| (_| | | | | | | |  __/ |   
|____/ \___|_|    \_/ |_|\___\___| |____/ \___\__,_|_| |_|_| |_|\___|_|   "

Write-Host "---------------------------------------`n"
Write-Host "Developed by: myp" -ForegroundColor Green
Write-Host "Version: 1.0" -ForegroundColor Red
Write-Host "---------------------------------------`n"


# Admin privilege check with user confirmation
$adminCheck = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $adminCheck) {
    Write-Host "⚠ This script is not running with administrator privileges." -ForegroundColor Yellow
    $adminApproval = Read-Host "Do you want to restart as Administrator? (Yes/No)"

    if ($adminApproval -eq "Yes") {
        Write-Host "🔄 Restarting script as Administrator..." -ForegroundColor Cyan
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit
    } else {
        Write-Host "⚠ Running without administrator privileges. Some operations may fail." -ForegroundColor Red
        LogMessage "Warning: Script is running without administrator privileges."
    }
} else {
    Write-Host "✅ Running with administrator privileges." -ForegroundColor Green
}

# Define log file
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = "$PSScriptRoot\Service_Check_Log.txt"

# Function to write logs
function LogMessage {
    param ($message)
    $timestampNow = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestampNow - $message" | Out-File -Append -FilePath $logFile
}

LogMessage "Scanning started."

# -- VirusTotal Fonksiyonları --
# VirusTotal API anahtarını doğrulamak için fonksiyon
function Validate-VirusTotal {
    param (
        [string]$apiKey
    )

    $testUrl = "https://www.virustotal.com/api/v3/users/me"
    $headers = @{ "x-apikey" = "$apiKey" }

    try {
        $response = Invoke-RestMethod -Uri $testUrl -Headers $headers -Method Get -ErrorAction Stop
        return $true
    } catch {
        Write-Host "❌ Invalid VirusTotal API key! Please enter a valid API key." -ForegroundColor Red
        return $false
    }
}

# VirusTotal taraması yapmak için fonksiyon (SHA256 hash kullanılarak)
function Check-VirusTotal {
    param (
        [string]$filePath,
        [string]$apiKey
    )

    if (-Not (Test-Path $filePath -PathType Leaf)) {
        Write-Host "⚠ File not found: $filePath, skipping VirusTotal scan." -ForegroundColor Yellow
        LogMessage "⚠ File not found: $filePath, skipping VirusTotal scan."
        return
    }

    # Dosyanın SHA256 hash'ini hesapla
    $fileHash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash

    # VirusTotal API isteği (hash ile sorgulama)
    $vtUrl = "https://www.virustotal.com/api/v3/files/$fileHash"
    $headers = @{ "x-apikey" = "$apiKey" }

    try {
        # VirusTotal API'ye istek gönder
        $response = Invoke-RestMethod -Uri $vtUrl -Headers $headers -Method Get -ErrorAction Stop

        # Beklenen alanlar varsa sonuçları değerlendir
        if ($response -and $response.data -and $response.data.attributes -and $response.data.attributes.last_analysis_stats) {
            $maliciousCount = $response.data.attributes.last_analysis_stats.malicious
            if ($maliciousCount -gt 0) {
                Write-Host "🔍 VirusTotal result: $filePath is suspicious! ($maliciousCount detections)" -ForegroundColor Magenta
                LogMessage "VirusTotal result: $filePath is suspicious! ($maliciousCount detections)"
            } else {
                Write-Host "✅ VirusTotal clean: $filePath" -ForegroundColor Green
                LogMessage "VirusTotal clean: $filePath"
            }
        } else {
            Write-Host "⚠ No result found in VirusTotal for: $filePath" -ForegroundColor Yellow
            LogMessage "⚠ No result found in VirusTotal for: $filePath"
        }
    } catch {
        Write-Host "⚠ VirusTotal API error: $_" -ForegroundColor Red
        LogMessage "VirusTotal API error: $_"
    }
}

# -------------------------------
# Kullanıcıya devam etmek isteyip istemediğini sor
$confirmation = Read-Host "This script will check Windows services and Security Logs. Do you want to proceed? (Yes/No)"
if ($confirmation -ne "Yes") {
    Write-Host "Operation canceled." -ForegroundColor Yellow
    exit
}

# Kullanıcıdan default servis listesi dosyasının yolunu al (örn: C:\servis_listesi.txt, csv, json)
$defaultServicesFile = Read-Host "Please enter the full path of the default service list (Example: C:\servis_listesi.txt, csv, json)"
$defaultServicesFile = $defaultServicesFile.Trim('"').Trim()

# Dosyanın varlığını kontrol et
if (-Not (Test-Path -Path $defaultServicesFile -PathType Leaf)) {
    Write-Host "Error: File not found! Please enter a valid file path." -ForegroundColor Red
    LogMessage "ERROR: File not found! Path: $defaultServicesFile"
    exit
}

# Kullanıcının sağladığı servis listesini oku
Write-Host "`n📄 User-Provided Service List:" -ForegroundColor Cyan
$defaultServices = @()
try {
    switch ([System.IO.Path]::GetExtension($defaultServicesFile).ToLower()) {
        ".txt" {
            $defaultServices = Get-Content -Path $defaultServicesFile | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.ToLower().Trim() }
        }
        ".csv" {
            $csvData = Import-Csv -Path $defaultServicesFile
            if ($csvData -and $csvData.Name) {
                $defaultServices = $csvData | Select-Object -ExpandProperty Name | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.ToLower().Trim() }
            } else {
                throw "Missing 'Name' column in CSV file!"
            }
        }
        ".json" {
            $jsonData = Get-Content -Path $defaultServicesFile | ConvertFrom-Json
            if ($jsonData -and $jsonData.Name) {
                $defaultServices = $jsonData | Select-Object -ExpandProperty Name | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.ToLower().Trim() }
            } else {
                throw "Missing 'Name' property in JSON file!"
            }
        }
        default {
            throw "Error: Unsupported file format! Please use TXT, CSV, or JSON files."
        }
    }
} catch {
    Write-Host "❌ Error: An error occurred while reading the file: $_" -ForegroundColor Red
    LogMessage "ERROR: Failed to read the user's service list: $_"
    exit
}

# Servis listesini göster
$defaultServices | ForEach-Object { Write-Host "✔ $($_)" -ForegroundColor Green }

# Mevcut sistem servislerini al
$currentServices = Get-CimInstance -ClassName Win32_Service | Select-Object Name, StartMode, StartName, PathName

$suspiciousServices = @()
foreach ($service in $currentServices) {
    $normalizedServiceName = $service.Name.ToLower().Trim()
    if ($normalizedServiceName -notin $defaultServices) {
        Write-Host "❌ Suspicious Service: $($service.Name)" -ForegroundColor Red
        LogMessage "Suspicious Service Found: $($service.Name)"

        $suspiciousServices += [PSCustomObject]@{
            Name        = $service.Name
            StartupType = $service.StartMode
            LogOnAs     = $service.StartName
            Path        = if ($service.PathName) { $service.PathName -replace '"', '' } else { "Bilinmiyor" }
        }
    }
}

# Toplam şüpheli servis sayısını göster
Write-Host "`n🔎 Total Suspicious Services Found: $($suspiciousServices.Count)" -ForegroundColor Yellow
LogMessage "Total Suspicious Services Found: $($suspiciousServices.Count)"

# Event Log sorgulaması isteyip istemediğini sor
$logPermission = Read-Host "Would you like to query specific Event IDs (4697, 7030, 7031, 7045)? (Yes/No)"
$eventLogReport = "$PSScriptRoot\Supheli_Servis_Event_Log.csv"

if ($logPermission -eq "Yes") {
    $eventIDs = @(4697, 7030, 7031, 7045)

    # Tüm security logları al
    Write-Host "Reading security logs, please wait..." -ForegroundColor Green
    $allSecurityLogs = Get-WinEvent -LogName Security -ErrorAction SilentlyContinue

    # Event ID'ye göre filtrele
    $suspiciousLogEntries = $allSecurityLogs | Where-Object { $_.Id -in $eventIDs }

    if ($suspiciousLogEntries.Count -gt 0) {
        $suspiciousLogData = $suspiciousLogEntries | ForEach-Object {
            [PSCustomObject]@{
                ServiceName = if ($_.Properties.Count -gt 0) { $_.Properties[0].Value } else { "Bilinmeyen Servis" }
                EventID     = $_.Id
                Timestamp   = $_.TimeCreated
            }
        }

        $suspiciousLogData | Export-Csv -Path $eventLogReport -NoTypeInformation -Encoding UTF8
        Write-Host "Suspicious service log report generated: $eventLogReport" -ForegroundColor Cyan
    } else {
        Write-Host "No relevant Event IDs found to report." -ForegroundColor Yellow
    }
}

# Google & VirusTotal sorgulaması
$searchMethod = Read-Host "How would you like to search for suspicious services? (Google/VirusTotal/None)"
if ($searchMethod -eq "Google") {
    foreach ($service in $suspiciousServices) {
        $url = "https://www.google.com/search?q=What+is+$($service.Name)"
        Start-Process $url
        Start-Sleep -Milliseconds 500
    }
    Write-Host "`n🔍 Suspicious services have been searched on Google." -ForegroundColor Green
} elseif ($searchMethod -eq "VirusTotal") {
    # VirusTotal API anahtarını kullanıcıdan al ve doğrula
    do {
        $virusTotalAPIKey = Read-Host "🔑 Please enter your VirusTotal API key"
        if ([string]::IsNullOrEmpty($virusTotalAPIKey)) {
            Write-Host "⚠ API key cannot be empty. Please enter a valid key." -ForegroundColor Red
        }
    } until ($virusTotalAPIKey -and (Validate-VirusTotal -apiKey $virusTotalAPIKey))
    
    foreach ($service in $suspiciousServices) {
        if ($service.Path -and $service.Path -ne "Bilinmiyor" -and (Test-Path $service.Path -PathType Leaf)) {
            Check-VirusTotal -filePath $service.Path -apiKey $virusTotalAPIKey
        } else {
            Write-Host "⚠ No valid EXE path found for $($service.Name), skipping scan." -ForegroundColor Yellow
            LogMessage "⚠ No valid EXE path found for $($service.Name), skipping scan."
        }
    }
}

Write-Host "`n✅ Scan Completed!" -ForegroundColor Green
LogMessage "Scan Completed."
Write-Host "Do NOT rely 100% on the results, this is NOT a VIRUS SCAN!!!" -ForegroundColor Red