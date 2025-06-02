#Requires -Version 5.1
<#
.SYNOPSIS
    Windows servislerini ve belirli güvenlik olay günlüklerini analiz eden, şüpheli servisleri belirleyen
    ve isteğe bağlı olarak VirusTotal veya Google üzerinden araştırma yapan bir PowerShell script'i.
.DESCRIPTION
    Bu script, kullanıcı tarafından sağlanan bir varsayılan servis listesiyle mevcut sistem servislerini karşılaştırır.
    Listede olmayan servisleri "şüpheli" olarak işaretler. Ayrıca, belirli olay kimliklerini (4697, 7030, 7031, 7045)
    güvenlik günlüklerinde arar. Şüpheli servislerin çalıştırılabilir dosyaları için VirusTotal taraması yapabilir
    veya Google'da arama yapabilir. Script, yönetici ayrıcalıklarıyla çalışmayı tercih eder ve bunun için
    kullanıcıdan onay ister. Kullanıcı girdileri için gelişmiş doğrulama mekanizmaları içerir.
.NOTES
    Version: 1.2.3
    Author: myp (ve Gemini tarafından yapılan eklemelerle)
    Developed by: myp
.LINK
    Bu script'in orijinal veya ilham alınan kaynağına bir link (varsa).
.EXAMPLE
    .\Scanner.ps1
    Script'i çalıştırır ve kullanıcıya adımları sorar.
#>

Write-Host "---------------------------------------"
Write-Host "
Super
__    ___          _
\ \  / / (_) _ __  __| | _____   _____
 \ \/\ / /| | '_ \ / _` |/ _ \ \ /\ / / __|
  \ V  V / | | | | | (_| | (_) \ V  V /\__ \
   \_/\_/  |_|_| |_|\__,_|\___/ \_/\_/ |___/
 ____              _        ____
/ ___| ___ _ ____  _(_) ___ ___  / ___| ___ __ _ _ __  _ __   ___ _ __
\___ \ / _ \ '__\ \ / / |/ __/ _ \ \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 ___) |  __/ |   \ V /| | (_|  __/  ___) | (_| (_| | | | | | | |  __/ |
|____/ \___|_|    \_/ |_|\___\___| |____/ \___\__,_|_| |_|_| |_|\___|_|
" -ForegroundColor Cyan
Write-Host "---------------------------------------`n"
Write-Host "Developed by: myp" -ForegroundColor Green
Write-Host "Version: 1.2.3 (Log mesajı düzeltmesi)" -ForegroundColor Red
Write-Host "---------------------------------------`n"

# --- Fonksiyon Tanımlamaları ---

# 1) Log mesajlarını dosyaya yazmak için fonksiyon
function LogMessage {
    param (
        [string]$message
    )
    # Global $logFile kullanımına dikkat
    $timestampNow = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestampNow - $message" | Out-File -Append -FilePath $logFile -Encoding UTF8
}

# 2) Gelişmiş kullanıcı girişi ve komut çalıştırma seçeneği için fonksiyon
function Get-ScriptInput {
    param(
        [string]$Prompt,
        [scriptblock]$ValidationLogic = { param($v) return $true }, # Varsayılan: her giriş geçerli
        [string]$ValidationErrorMessage = "Geçersiz giriş."
    )

    while ($true) {
        $userInput = Read-Host -Prompt $Prompt
        if ($null -eq $userInput) { # Kullanıcı Ctrl+C ile çıkmış olabilir veya bazı nadir durumlar
            Write-Warning "Girdi alınamadı. Lütfen geçerli bir değer girin."
            continue
        }

        $userInput = $userInput.Trim()

        if ([string]::IsNullOrWhiteSpace($userInput)) {
            Write-Warning "Giriş boş bırakılamaz. Lütfen geçerli bir değer girin."
            continue
        }

        # ValidationLogic için doğrudan çağrı
        try {
            $isValid = & $ValidationLogic $userInput # Scriptblock'u kullanıcı girdisiyle çağır
        } catch {
            $isValid = $false # Doğrulama script bloğunda hata olursa geçersiz say
            Write-Warning "Doğrulama mantığında hata oluştu: $($_.Exception.Message)"
        }

        if ($isValid) {
            return $userInput # Doğrulama başarılı, kullanıcı girdisini döndür
        }

        # Eğer doğrulama başarısızsa, bunun bir komut olup olmadığını kontrol edelim
        $commandInfo = Get-Command $userInput -ErrorAction SilentlyContinue
        if ($commandInfo) {
            Write-Host "⚠️ Girdiğiniz '$userInput' bir Windows komutu olarak algılandı." -ForegroundColor Yellow
            Write-Host "    Komut Adı: $($commandInfo.Name)" -ForegroundColor Gray
            Write-Host "    Komut Tipi: $($commandInfo.CommandType)" -ForegroundColor Gray

            $runCommandChoice = Read-Host "❓ Bu komutu işletim sisteminde çalıştırmak ister misiniz? (Evet/Hayır)"
            $runCommandChoice = $runCommandChoice.Trim()

            if ($runCommandChoice -ieq "Evet") {
                Write-Host "⚙️ Komut çalıştırılıyor: $userInput ..." -ForegroundColor Cyan
                Write-Warning "Invoke-Expression ile komut çalıştırılmaya çalışılıyor. Lütfen komutun güvenli olduğundan emin olun!"
                try {
                    Invoke-Expression $userInput
                    Write-Host "✅ Komut çalıştırılması tamamlandı." -ForegroundColor Green
                } catch {
                    Write-Error "❌ Komut çalıştırılırken hata oluştu: $($_.Exception.Message)"
                }
                Write-Host "`n🔁 Script'in sorusuna geri dönülüyor..." -ForegroundColor Yellow
            } else {
                Write-Warning "🟡 Komut çalıştırma iptal edildi. Lütfen script için geçerli bir giriş yapın."
            }
        } else {
            # Ne geçerli bir script girdisi ne de tanınan bir komut
            Write-Warning "❌ $ValidationErrorMessage"
        }
    }
}

# 3) Servisin çalıştırılabilir dosya yolunu çözümlemek için yardımcı fonksiyon
function Resolve-ServicePath {
    param (
        [string]$pathNameStr
    )

    if ([string]::IsNullOrWhiteSpace($pathNameStr)) {
        return $null
    }

    # Tırnaklı veya tırnaksız ilk .exe/.dll/.sys kısmını yakalayan regex
    $regex = '^(?:"(?<QuotedPath>[^"]+\.(?:exe|dll|sys))"|(?<UnquotedPath>\S+\.(?:exe|dll|sys)))'
    $matches = [regex]::Match($pathNameStr, $regex)
    $executablePath = $null

    if ($matches.Success) {
        if ($matches.Groups["QuotedPath"].Success) {
            $executablePath = $matches.Groups["QuotedPath"].Value
        } else {
            $executablePath = $matches.Groups["UnquotedPath"].Value
        }
    } else {
        # Regex ile yakalanamadıysa, tırnaklı ilk bölümü veya boşluktan ilk parçayı al
        if ($pathNameStr.StartsWith('"')) {
            $endQuoteIndex = $pathNameStr.IndexOf('"', 1)
            if ($endQuoteIndex -gt 1) { # Sadece açılış tırnağı olmamalı
                $executablePath = $pathNameStr.Substring(1, $endQuoteIndex - 1)
            } else { # Hatalı tırnak yapısı, sadece ilk tırnağı kaldır ve ilk kelimeyi al
                $executablePath = $pathNameStr.TrimStart('"').Split(' ')[0]
            }
        } else { # Tırnaksızsa ilk kelimeyi al
            $executablePath = $pathNameStr.Split(' ')[0]
        }
    }
    
    if ([string]::IsNullOrWhiteSpace($executablePath)) { # Eğer bir şekilde boş bir path elde edildiyse
        return $null
    }

    # Çevresel değişkenleri genişlet
    $expandedPath = [System.Environment]::ExpandEnvironmentVariables($executablePath)

    # Eğer tam sürücü veya UNC yolu yoksa, SystemRoot altında bulunup bulunmadığını kontrol et
    if ($expandedPath -notmatch '^[a-zA-Z]:\\' -and $expandedPath -notmatch '^\\\\') {
        $systemRoot = [System.Environment]::ExpandEnvironmentVariables('%SystemRoot%')
        $potentialPath = Join-Path -Path $systemRoot -ChildPath $expandedPath
        if (Test-Path $potentialPath -PathType Leaf) {
            return $potentialPath
        }
    }

    return $expandedPath
}

# 4) VirusTotal API anahtarını doğrulamak için fonksiyon
function Validate-VirusTotal {
    param (
        [string]$apiKey
    )
    if ([string]::IsNullOrWhiteSpace($apiKey)) { return $false }

    $testUrl = "https://www.virustotal.com/api/v3/users/me"
    $headers = @{ "x-apikey" = $apiKey }

    try {
        $response = Invoke-RestMethod -Uri $testUrl -Headers $headers -Method Get -ErrorAction Stop -TimeoutSec 10
        return $true
    } catch {
        Write-Host "❌ Geçersiz veya zaman aşımına uğrayan VirusTotal API anahtarı! Lütfen geçerli bir API anahtarı girin." -ForegroundColor Red
        LogMessage "ERROR: VirusTotal API key validation failed. Message: $($_.Exception.Message)"
        return $false
    }
}

# 5) VirusTotal taraması yapmak için fonksiyon (SHA256 hash kullanılarak)
function Check-VirusTotal {
    param (
        [string]$filePath,
        [string]$apiKey
    )

    if (-Not (Test-Path $filePath -PathType Leaf)) {
        Write-Host "⚠ Dosya bulunamadı: $filePath, VirusTotal taraması atlanıyor." -ForegroundColor Yellow
        LogMessage "WARN: File not found: $filePath, skipping VirusTotal scan."
        return
    }

    try {
        $fileHash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
    } catch {
        Write-Host "❌ Dosya hash'i hesaplanırken hata: $filePath. $($_.Exception.Message)" -ForegroundColor Red
        LogMessage "ERROR: Failed to calculate hash for ${filePath}. Message: $($_.Exception.Message)"
        return
    }

    $vtUrl   = "https://www.virustotal.com/api/v3/files/$fileHash"
    $headers = @{ "x-apikey" = $apiKey }

    try {
        $response = Invoke-RestMethod -Uri $vtUrl -Headers $headers -Method Get -ErrorAction Stop -TimeoutSec 20

        if ($response -and $response.data -and $response.data.attributes -and $response.data.attributes.last_analysis_stats) {
            $maliciousCount = $response.data.attributes.last_analysis_stats.malicious
            if ($maliciousCount -gt 0) {
                Write-Host "🔍 VirusTotal sonucu: $filePath şüpheli! ($maliciousCount tespit)" -ForegroundColor Magenta
                LogMessage "VirusTotal result: ${filePath} is suspicious! ($maliciousCount detections)"
            } else {
                Write-Host "✅ VirusTotal temiz: $filePath" -ForegroundColor Green
                LogMessage "VirusTotal clean: ${filePath}"
            }
        }
        elseif ($response -and $response.error -and $response.error.code -eq "NotFoundError") {
            Write-Host "ℹ️ VirusTotal'da $filePath ($fileHash) için sonuç bulunamadı (daha önce taranmamış olabilir)." -ForegroundColor Cyan
            LogMessage "INFO: No result found in VirusTotal for ${filePath} (hash: $fileHash)."
        }
        else {
            Write-Host "⚠ VirusTotal'dan $filePath için beklenmedik yanıt veya eksik veri." -ForegroundColor Yellow
            LogMessage "WARN: Unexpected or incomplete data from VirusTotal for: ${filePath}. Response: $($response | ConvertTo-Json -Depth 3)"
        }
    } catch {
        Write-Host "❌ VirusTotal API hatası (${filePath}): $($_.Exception.Message)" -ForegroundColor Red
        LogMessage "ERROR: VirusTotal API error for ${filePath}: $($_.Exception.Message)" # DÜZELTİLDİ
    }
}

# --- Ana Script Mantığı Başlangıcı ---

# 1) Log dosyasını oluştur
$PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$timeStamp    = Get-Date -Format 'yyyyMMdd-HHmmss'
$logFile      = Join-Path -Path $PSScriptRoot -ChildPath "Service_Check_Log_$timeStamp.txt"
LogMessage "INFO: Script başlatıldı. Log dosyası: $logFile"

# 2) Yönetici kontrolü
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator") # DÜZELTİLDİ (Tek satır)

if (-not $isAdmin) {
    Write-Host "⚠️ Bu script yönetici ayrıcalıklarıyla çalışmıyor." -ForegroundColor Yellow
    $adminApproval = Get-ScriptInput -Prompt "Yönetici olarak yeniden başlatmak ister misiniz? (Evet/Hayır)" `
                                     -ValidationLogic { param($a); ($a -ieq "Evet" -or $a -ieq "Hayır") } `
                                     -ValidationErrorMessage "Lütfen 'Evet' veya 'Hayır' girin."

    if ($adminApproval -ieq "Evet") {
        Write-Host "🔄 Script Yönetici olarak yeniden başlatılıyor..." -ForegroundColor Cyan
        LogMessage "INFO: Script is restarting as Administrator."
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit
    } else {
        Write-Warning "⚠️ Yönetici ayrıcalıkları olmadan devam ediliyor. Bazı işlemler başarısız olabilir."
        LogMessage "WARN: Running without administrator privileges. Some operations may fail."
    }
} else {
    Write-Host "✅ Script yönetici ayrıcalıklarıyla çalışıyor." -ForegroundColor Green
    LogMessage "INFO: Running with administrator privileges."
}

# 3) Başlangıç onayı
$confirmation = Get-ScriptInput -Prompt "Bu script Windows servislerini ve Güvenlik Günlüklerini kontrol edecektir. Devam etmek istiyor musunuz? (Evet/Hayır)" `
                                -ValidationLogic { param($a); ($a -ieq "Evet" -or $a -ieq "Hayır") } `
                                -ValidationErrorMessage "Lütfen 'Evet' veya 'Hayır' girin."

if ($confirmation -ine "Evet") {
    Write-Host "İşlem iptal edildi." -ForegroundColor Yellow
    LogMessage "INFO: Operation cancelled by user at initial prompt."
    Read-Host "`n🔴 Çıkmak için Enter tuşuna basın..."
    exit
}

# 4) Varsayılan servis listesi dosya yolu
$defaultServicesFile = ""
while ($true) {
    $defaultServicesFileUserInput = Get-ScriptInput -Prompt "Lütfen varsayılan servis listesinin tam yolunu girin (Örnek: C:\servis_listesi.txt, .csv, .json)" `
                                                   -ValidationLogic { param($p); (-not [string]::IsNullOrWhiteSpace($p)) } `
                                                   -ValidationErrorMessage "Dosya yolu boş bırakılamaz."
    $defaultServicesFile = $defaultServicesFileUserInput.Trim('"') # Tırnakları ayrıca temizle

    if (Test-Path -Path $defaultServicesFile -PathType Leaf) {
        LogMessage "INFO: User provided service list path: $defaultServicesFile"
        break
    } else {
        Write-Error "HATA: Dosya bulunamadı! Lütfen geçerli bir dosya yolu girin: $defaultServicesFile"
        LogMessage "ERROR: Default service list file not found at: $defaultServicesFile"
    }
}

# 5) Varsayılan servis listesini oku
Write-Host "`n📄 Kullanıcı Tarafından Sağlanan Servis Listesi:" -ForegroundColor Cyan
$defaultServices = @()

try {
    $fileExtension = [System.IO.Path]::GetExtension($defaultServicesFile).ToLower()
    switch ($fileExtension) {
        ".txt" {
            $defaultServices = Get-Content -Path $defaultServicesFile -Encoding UTF8 |
                                Where-Object { $_.Trim() -ne "" } |
                                ForEach-Object { $_.ToLower().Trim() }
        }
        ".csv" {
            $csvData = Import-Csv -Path $defaultServicesFile -Encoding UTF8
            $nameProperty = $csvData |
                            Get-Member -MemberType NoteProperty |
                            Where-Object { $_.Name -ieq "Name" -or $_.Name -ieq "ServiceName" } |
                            Select-Object -First 1 -ExpandProperty Name

            if ($nameProperty) {
                $defaultServices = $csvData |
                                    Select-Object -ExpandProperty $nameProperty |
                                    Where-Object { $_.Trim() -ne "" } |
                                    ForEach-Object { $_.ToLower().Trim() }
            } else {
                throw "CSV dosyasında 'Name' veya 'ServiceName' sütunu bulunamadı!"
            }
        }
        ".json" {
            $jsonData = Get-Content -Path $defaultServicesFile -Encoding UTF8 | ConvertFrom-Json

            if ($jsonData -is [System.Array]) {
                # Dizi içindeki objelerden Name veya ServiceName çekelim
                if ($jsonData.Count -gt 0 -and $jsonData[0].PSObject.Properties.Name -contains "Name") {
                    $defaultServices = $jsonData | ForEach-Object { $_.Name }
                } elseif ($jsonData.Count -gt 0 -and $jsonData[0].PSObject.Properties.Name -contains "ServiceName") {
                    $defaultServices = $jsonData | ForEach-Object { $_.ServiceName }
                } elseif ($jsonData -is [string[]]) {
                    $defaultServices = $jsonData
                } else { # Dizi ama beklenen yapıda değil veya boş
                     $defaultServices = @() # Boş dizi ata, hata vermesin ama uyarı verilsin
                     Write-Warning "JSON dizisi servis adlarını beklenen formatta içermiyor (objelerde 'Name'/'ServiceName' veya doğrudan string dizisi)."
                }
                # Ortak filtreleme ve küçük harfe çevirme
                $defaultServices = $defaultServices | Where-Object { $_ -is [string] -and $_.Trim() -ne "" } | ForEach-Object { $_.ToLower().Trim() }

            } elseif ($jsonData -is [System.Object]) { # JSON tek bir obje ise
                if ($jsonData.PSObject.Properties.Name -contains "Name") {
                    $defaultServices = $jsonData.Name | Where-Object { $_ -is [string] -and $_.Trim() -ne "" } | ForEach-Object { $_.ToLower().Trim() }
                } elseif ($jsonData.PSObject.Properties.Name -contains "ServiceName") {
                    $defaultServices = $jsonData.ServiceName | Where-Object { $_ -is [string] -and $_.Trim() -ne "" } | ForEach-Object { $_.ToLower().Trim() }
                } else {
                    throw "JSON objesi 'Name' veya 'ServiceName' özelliği içermiyor!"
                }
            } else {
                 throw "JSON formatı anlaşılamadı (ne dizi ne de obje)."
            }
        }
        default {
            throw "HATA: Desteklenmeyen dosya formatı! Lütfen TXT, CSV veya JSON dosyaları kullanın."
        }
    }

    if ($defaultServices.Count -eq 0) {
        Write-Warning "Sağlanan servis listesi boş veya okunamadı. Karşılaştırma yapılamayacak."
        LogMessage "WARN: Provided service list is empty or could not be parsed."
    }
} catch {
    Write-Error "❌ HATA: Dosya okunurken bir hata oluştu: $($_.Exception.Message)"
    LogMessage "ERROR: Failed to read the user's service list: $($_.Exception.Message)"
    Read-Host "`n🔴 Çıkmak için Enter tuşuna basın..."
    exit
}

# Ekrana yazdır
$defaultServices | ForEach-Object { Write-Host "  ✔ $($_)" -ForegroundColor Green }

# 6) Mevcut sistem servislerini al
Write-Host "`n🔄 Mevcut sistem servisleri alınıyor..." -ForegroundColor Cyan
$currentServices = Get-CimInstance -ClassName Win32_Service |
                   Select-Object Name, StartMode, StartName, PathName, State, Status, ProcessId
LogMessage "INFO: Fetched current system services."

# 7) Şüpheli servisleri bul
$suspiciousServices = @()
Write-Host "`n🔍 Şüpheli servisler taranıyor..." -ForegroundColor Cyan

foreach ($service in $currentServices) {
    $normalizedServiceName = $service.Name.ToLower().Trim()
    if ($normalizedServiceName -notin $defaultServices) {
        Write-Host "  ❌ Şüpheli Servis: $($service.Name) (Durum: $($service.State), Başlangıç: $($service.StartMode))" -ForegroundColor Red
        LogMessage "Suspicious Service Found: Name: $($service.Name), State: $($service.State), StartMode: $($service.StartMode), PathName: $($service.PathName), StartName: $($service.StartName)"

        $resolvedPathValue = Resolve-ServicePath -pathNameStr $service.PathName

        $suspiciousServices += [PSCustomObject]@{
            Name        = $service.Name
            State       = $service.State
            Status      = $service.Status
            ProcessId   = $service.ProcessId
            StartupType = $service.StartMode
            LogOnAs     = $service.StartName
            Path        = if (-not [string]::IsNullOrWhiteSpace($resolvedPathValue)) { $resolvedPathValue } else { "Bilinmiyor/Çözümlenemedi" }
            RawPathName = $service.PathName
        }
    }
}

Write-Host "`n📊 Toplam Şüpheli Servis Bulundu: $($suspiciousServices.Count)" -ForegroundColor Yellow
LogMessage "INFO: Total Suspicious Services Found: $($suspiciousServices.Count)"

if ($suspiciousServices.Count -gt 0) {
    Write-Host "Detaylar:" -ForegroundColor Yellow
    $suspiciousServices |
        Format-Table -AutoSize -Wrap |
        Out-String |
        Write-Host
}

# 8) Olay günlüklerini sorgulamak isteyip istemediğini sor
$eventLogReport = Join-Path -Path $PSScriptRoot -ChildPath "Supheli_Servis_Olay_Gunlugu_$timeStamp.csv"
$logPermission    = Get-ScriptInput -Prompt "Belirli Olay Kimliklerini (4697, 7030, 7031, 7045) sorgulamak ister misiniz? (Evet/Hayır)" `
                                  -ValidationLogic { param($a); ($a -ieq "Evet" -or $a -ieq "Hayır") } `
                                  -ValidationErrorMessage "Lütfen 'Evet' veya 'Hayır' girin."

if ($logPermission -ieq "Evet") {
    $eventIDs = @(4697, 7030, 7031, 7045)
    Write-Host "`n🔄 Güvenlik ve Sistem olay günlükleri okunuyor, lütfen bekleyin..." -ForegroundColor Green
    LogMessage "INFO: Querying Event Logs for IDs: $($eventIDs -join ', ')."

    $allRelevantLogs = @()
    try {
        $allRelevantLogs += Get-WinEvent -LogName Security -FilterHashtable @{ ID = $eventIDs } -ErrorAction SilentlyContinue
        $allRelevantLogs += Get-WinEvent -LogName System -FilterHashtable @{ ProviderName = 'Service Control Manager'; ID = $eventIDs } -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Olay günlükleri okunurken bir hata oluştu: $($_.Exception.Message)"
        LogMessage "WARN: Error reading event logs: $($_.Exception.Message)"
    }

    if ($allRelevantLogs.Count -gt 0) {
        $suspiciousLogData = $allRelevantLogs | ForEach-Object {
            $serviceName = "Bilinmiyor"

            switch ($_.Id) {
                4697 { # Security Log: A new service was installed
                    if ($_.Properties.Count -ge 1) { $serviceName = $_.Properties[0].Value } # Service Name
                }
                7045 { # System Log: A service was installed
                    if ($_.Properties.Count -ge 1) { $serviceName = $_.Properties[0].Value } # Service Name
                }
                7030 { # System Log: Service marked as interactive (often an error)
                    if ($_.Message -match "The (.*?) service is marked as an interactive service.") { $serviceName = $Matches[1].Trim() }
                }
                7031 { # System Log: Service terminated unexpectedly
                     if ($_.Message -match "The (.*?) service terminated unexpectedly.") { $serviceName = $Matches[1].Trim() }
                }
            }

            # Genel mesajlardan yakalama (yukarıdakiler eşleşmezse)
            if ($serviceName -eq "Bilinmiyor") {
                if ($_.Message -match "The (.*?) service entered the") { $serviceName = $Matches[1].Trim() }
                elseif ($_.Message -match "service named (.*?) failed to start") { $serviceName = $Matches[1].Trim() }
                elseif ($_.Message -match "Service (.*?) was installed") { $serviceName = $Matches[1].Trim() } # Daha genel bir yakalama
            }

            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                EventID     = $_.Id
                Level       = $_.LevelDisplayName
                Provider    = $_.ProviderName
                ServiceName = $serviceName
                Message     = $_.Message -replace "`r`n|`n", " " # Mesajı tek satıra indirge
            }
        }

        $suspiciousLogData |
            Export-Csv -Path $eventLogReport -NoTypeInformation -Encoding UTF8 -Delimiter ";"

        Write-Host "`n📄 Şüpheli servis olay günlüğü raporu oluşturuldu: $eventLogReport" -ForegroundColor Cyan
        LogMessage "INFO: Suspicious service event log report generated: $eventLogReport"
    } else {
        Write-Host "`nℹ️ Raporlanacak ilgili Olay Kimliği bulunamadı." -ForegroundColor Yellow
        LogMessage "INFO: No relevant Event IDs found to report."
    }
}

# 9) Şüpheli servisleri online aratmak isteyip istemediğini sor
if ($suspiciousServices.Count -gt 0) {
    $searchMethod = Get-ScriptInput -Prompt "Şüpheli servisleri nasıl aramak istersiniz? (Google/VirusTotal/Hiçbiri)" `
                                     -ValidationLogic { param($a); @("Google","VirusTotal","Hiçbiri") -icontains $a } `
                                     -ValidationErrorMessage "Lütfen 'Google', 'VirusTotal' veya 'Hiçbiri' seçeneklerinden birini girin."

    if ($searchMethod -ieq "Google") {
        LogMessage "INFO: User chose to search suspicious services on Google."
        foreach ($service in $suspiciousServices) {
            $url = "https://www.google.com/search?q=What+is+$([uri]::EscapeDataString($service.Name))+service"
            Write-Host "  🔍 Google'da aranıyor: $($service.Name)"
            Start-Process $url
            Start-Sleep -Milliseconds 500
        }
        Write-Host "`n✅ Şüpheli servisler Google'da aratıldı." -ForegroundColor Green
    }
    elseif ($searchMethod -ieq "VirusTotal") {
        LogMessage "INFO: User chose to search suspicious services on VirusTotal."
        $apiKeyIsValid = $false
        $virusTotalAPIKey = ""

        do {
            $virusTotalAPIKey = Get-ScriptInput -Prompt "🔑 Lütfen VirusTotal API anahtarınızı girin" `
                                                 -ValidationLogic { param($k); (-not [string]::IsNullOrWhiteSpace($k)) } `
                                                 -ValidationErrorMessage "API anahtarı boş bırakılamaz."

            if (Validate-VirusTotal -apiKey $virusTotalAPIKey) {
                $apiKeyIsValid = $true
                LogMessage "INFO: VirusTotal API key validated successfully."
            } else {
                LogMessage "WARN: User provided an invalid VirusTotal API key."
            }
        } until ($apiKeyIsValid)

        Write-Host "`n🔬 VirusTotal taramaları başlatılıyor..." -ForegroundColor Cyan
        foreach ($service in $suspiciousServices) {
            if ($service.Path -and $service.Path -ne "Bilinmiyor/Çözümlenemedi") {
                if (Test-Path $service.Path -PathType Leaf) {
                    Write-Host "  SCANNING: $($service.Name) - $($service.Path)"
                    Check-VirusTotal -filePath $service.Path -apiKey $virusTotalAPIKey
                } else {
                    Write-Warning "  UYARI: $($service.Name) için çözümlenen yol ('$($service.Path)') geçerli bir dosya değil veya erişilemiyor. Tarama atlanıyor."
                    LogMessage "WARN: Resolved path for $($service.Name) ('$($service.Path)') is not a valid file or cannot be accessed. Skipping scan."
                }
            } else {
                Write-Warning "  UYARI: $($service.Name) için geçerli bir EXE yolu bulunamadı veya çözümlenemedi, VirusTotal taraması atlanıyor."
                LogMessage "WARN: No valid EXE path found or resolved for $($service.Name), skipping VirusTotal scan."
            }
        }
    }
    else { # Hiçbiri seçeneği
        LogMessage "INFO: User chose not to search suspicious services online."
    }
}

# 10) Son mesajlar ve kapanış
Write-Host "`n✅ Tarama Tamamlandı!" -ForegroundColor Green
LogMessage "INFO: Scan Completed."
Write-Host "‼️  SONUÇLARA %100 GÜVENMEYİN, BU BİR VİRÜS TARAMASI DEĞİL!" -ForegroundColor Red -BackgroundColor Black
Write-Host "📜 Detaylı loglar için '$logFile' dosyasını kontrol edin." -ForegroundColor Cyan

Read-Host "`n🟢 Taramayı sonlandırmak ve pencereyi kapatmak için Enter tuşuna basın..."
