# CYBER-ROR HEADLESS v3.58 - Oppsettscript
# Kjoer som Administrator

Write-Host "=== CYBER-ROR HEADLESS v3.58 Oppsett ===" -ForegroundColor Cyan

# 1. Opprett mapper
$dirs = @("C:\cyber", "C:\cyber\logs", "C:\cyber\data")
foreach ($dir in $dirs) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "Opprettet: $dir" -ForegroundColor Green
    }
}

# 2. Kopier filer
Write-Host "`nKopier disse filer til C:\cyber\:" -ForegroundColor Yellow
Write-Host "  - CYBER_ROR_HEADLESS_v358.py" -ForegroundColor White
Write-Host "  - config.json" -ForegroundColor White
Write-Host "`nRediger config.json og legg inn dine API-noekler." -ForegroundColor Yellow

# 3. Slett gammel oppgave (hvis finnes)
try {
    Unregister-ScheduledTask -TaskName "CYBER-ROR-v358" -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "`nSlettet gammel oppgave (hvis den fantes)" -ForegroundColor Green
} catch {
    Write-Host "Ingen gammel oppgave funnet" -ForegroundColor Gray
}

# 4. Lag ny oppgave (SYSTEM, ved oppstart)
$action = New-ScheduledTaskAction `
    -Execute "C:\Users\ander\AppData\Local\Python\bin\pythonw.exe" `
    -Argument "C:\cyber\CYBER_ROR_HEADLESS_v358.py" `
    -WorkingDirectory "C:\cyber"

$trigger = New-ScheduledTaskTrigger -AtStartup

$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable

Register-ScheduledTask `
    -TaskName "CYBER-ROR-v358" `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings

Write-Host "`nOppgave opprettet!" -ForegroundColor Green

# 5. Start oppgaven for testing
Write-Host "`nStarter CYBER-ROR for testing..." -ForegroundColor Cyan
Start-ScheduledTask -TaskName "CYBER-ROR-v358"
Start-Sleep -Seconds 3

# 6. Sjekk status
$info = Get-ScheduledTask -TaskName "CYBER-ROR-v358" | Get-ScheduledTaskInfo
Write-Host "`nStatus:" -ForegroundColor Cyan
Write-Host "  LastRunTime: $($info.LastRunTime)" -ForegroundColor White
Write-Host "  LastTaskResult: $($info.LastTaskResult)" -ForegroundColor $(if ($info.LastTaskResult -eq 0) { "Green" } else { "Red" })

# 7. Sjekk logg
$logFile = "C:\cyber\logs\cyber_ror.log"
if (Test-Path $logFile) {
    Write-Host "`nSiste logglinjer:" -ForegroundColor Cyan
    Get-Content $logFile -Tail 5 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
}

Write-Host "`n=== Oppsett fullfoert ===" -ForegroundColor Green
Write-Host "Loggfil: C:\cyber\logs\cyber_ror.log" -ForegroundColor White
Write-Host "Blokkerte IP-er: C:\cyber\data\blocked_ips.json" -ForegroundColor White
Write-Host "VirusTotal resultater: C:\cyber\data\vt_results.json" -ForegroundColor White
Write-Host "AbuseIPDB resultater: C:\cyber\data\abuseipdb_results.json" -ForegroundColor White
