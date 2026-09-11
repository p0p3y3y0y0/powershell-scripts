#Developed by popeye
# Run PowerShell as Administrator

# --- Hostname ---
$Hostname = $env:COMPUTERNAME
Write-Output "Hostname ======= $Hostname"

# --- Sense ID ---
try {
    $path = "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\"
    if (Test-Path $path) {
        $SenseID = Get-ItemPropertyValue -Path $path -Name senseID
        Write-Output "SenseID: $SenseID"
    } else {
        Write-Output "SenseID not found"
    }
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
}

Write-Output "==============="

# --- OS Version ---
$ver = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
$ver | Format-List

Write-Output "==============="

# --- Defender Services ---
Write-Output "Defender Services"
$services = Get-Service Sense, WinDefend | Select Name, Status, StartType
$services | Format-Table -AutoSize

Write-Output "==============="

# --- Onboarding and EDR Status ---
Write-Output "Checking Onboarding and EDR status"
try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"
    if (Test-Path $regPath) {
        $EDR = Get-ItemProperty -Path $regPath | Select-Object MsSenseDllVersion, ConfigurationVersion, OnboardingState
        $EDR | Format-List
    } else {
        Write-Output "MDE Configuration registry path not found"
    }
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
}

Write-Output "==============="

# --- TLS/SSL Settings ---
try {
    $regtls = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
    $regssl = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"

    if (Test-Path $regtls) {
        $TLS = Get-ItemProperty -Path $regtls | Select-Object DisabledByDefault
        $TLS | Format-List
    } elseif (Test-Path $regssl) {
        $SSL = Get-ItemProperty -Path $regssl | Select-Object DisabledByDefault
        $SSL | Format-List
    } else {
        Write-Output "No TLS/SSL registry paths found"
    }
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
}

Write-Output "==============="

# --- Defender Settings ---
$defenderStatus = Get-MpComputerStatus

# Real-Time Protection
if ($defenderStatus.RealTimeProtectionEnabled) {
    Write-Output "Real-Time Protection is ENABLED"
} else {
    Write-Output "Real-Time Protection is DISABLED"
    $choiceRTP = Read-Host "Do you want to enable Real-Time Protection? (Y/N)"
    if ($choiceRTP -eq "Y") {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Write-Output "Real-Time Protection has been ENABLED"
    }
}

# Tamper Protection
if ($defenderStatus.IsTamperProtected) {
    Write-Output "Tamper Protection is ENABLED"
} else {
    Write-Output "Tamper Protection is DISABLED"
    $choiceTP = Read-Host "Do you want to enable Tamper Protection? (Y/N)"
    if ($choiceTP -eq "Y") {
        try {
            Set-MpPreference -EnableTamperProtection $true
            Write-Output "Tamper Protection has been ENABLED"
        } catch {
            Write-Output "Could not enable Tamper Protection via script. Please enable it manually in Windows Security settings."
        }
    }
}

# Antivirus Mode
if ($defenderStatus.AMServiceEnabled) {
    Write-Output "Antivirus Mode: ACTIVE"
} else {
    Write-Output "Antivirus Mode: PASSIVE"
    $choiceAV = Read-Host "Do you want to switch Antivirus Mode to ACTIVE? (Y/N)"
    if ($choiceAV -eq "Y") {
        try {
            Set-MpPreference -DisableRealtimeMonitoring $false
            Write-Output "Antivirus Mode switched to ACTIVE"
        } catch {
            Write-Output "Could not change Antivirus Mode. It may be controlled by Group Policy or another AV solution."
        }
    }
}

Write-Output "==============="

# --- Defender & Sense Events (last 24h) ---
$startTime = (Get-Date).AddDays(-1)

Write-Output "===== Microsoft Defender Antivirus (last 24h) ====="
$defenderLog = "Microsoft-Windows-Windows Defender/Operational"
$defenderEvents = Get-WinEvent -LogName $defenderLog -ErrorAction SilentlyContinue |
                  Where-Object { ($_.LevelDisplayName -in @("Error","Warning")) -and $_.TimeCreated -ge $startTime }

foreach ($event in $defenderEvents) {
    Write-Output "----------------------------------------"
    Write-Output "Event ID: $($event.Id)"
    Write-Output "Level: $($event.LevelDisplayName)"
    Write-Output "Time Created: $($event.TimeCreated)"
    Write-Output "Description: $($event.Message)"
}

Write-Output "`n===== Microsoft Defender for Endpoint (Sense) (last 24h) ====="
$senseLog = "Microsoft-Windows-SENSE/Operational"
$senseEvents = Get-WinEvent -LogName $senseLog -ErrorAction SilentlyContinue |
               Where-Object { ($_.LevelDisplayName -in @("Error","Warning")) -and $_.TimeCreated -ge $startTime }

foreach ($event in $senseEvents) {
    Write-Output "----------------------------------------"
    Write-Output "Event ID: $($event.Id)"
    Write-Output "Level: $($event.LevelDisplayName)"
    Write-Output "Time Created: $($event.TimeCreated)"
    Write-Output "Description: $($event.Message)"
}

Write-Output "==============="

# --- AV Update ---
Write-Output "===== Starting Microsoft Defender AV Update (MMPC) ====="
try {
    Update-MpSignature -UpdateSource MMPC
    Write-Output "Microsoft Defender signatures have been updated from MMPC."
} catch {
    Write-Output "Failed to update signatures. Error details:"
    Write-Output $_.Exception.Message
}

Write-Output "==============="

# --- MDE Re-Onboarding --- Place the script in the same folder as the MDE script
Write-Output "===== MDE Server Re-Onboarding ====="
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$offboardFile = Join-Path $scriptDir "WindowsDefenderATPOffboarding.cmd"
$onboardFile  = Join-Path $scriptDir "WindowsDefenderATPOnboarding.cmd"

if (Test-Path $offboardFile) {
    $choiceOff = Read-Host "Do you want to OFFBOARD this server from MDE? (Y/N)"
    if ($choiceOff -eq "Y") {
        Write-Output "Running offboarding package..."
        & $offboardFile
        Write-Output "Server has been offboarded from MDE."
    }
} else {
    Write-Output "Offboarding package not found in: $scriptDir"
}

if (Test-Path $onboardFile) {
    $choiceOn = Read-Host "Do you want to ONBOARD this server to MDE again? (Y/N)"
    if ($choiceOn -eq "Y") {
        Write-Output "Running onboarding package..."
        & $onboardFile
        Write-Output "Server has been onboarded to MDE."
    }
} else {
    Write-Output "Onboarding package not found in: $scriptDir"
}

Write-Output "===== Script Completed ====="
