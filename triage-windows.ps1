<# 
Windows Incident Response Triage Script
Collects key system, process, network, registry, and log info
#>

$OutDir = "C:\IR_Triage"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Write-Output "[*] Collecting triage data into $OutDir ..."

# --- 1. System Info ---
systeminfo > "$OutDir\systeminfo.txt"
hostname > "$OutDir\hostname.txt"
whoami /all > "$OutDir\whoami.txt"
ipconfig /all > "$OutDir\network_info.txt"
net accounts > "$OutDir\password_policy.txt"

# --- 2. Processes & Services ---
tasklist /v > "$OutDir\tasklist.txt"
Get-Process | Sort-Object CPU -Descending | Out-File "$OutDir\get-process.txt"
Get-Service | Where-Object {$_.Status -eq "Running"} | Out-File "$OutDir\running_services.txt"

# --- 3. Network Connections ---
netstat -ano > "$OutDir\netstat.txt"
Get-NetTCPConnection | Select-Object LocalAddress,RemoteAddress,State,OwningProcess |
    Out-File "$OutDir\net_connections.txt"

# --- 4. Scheduled Tasks & Persistence ---
schtasks /query /fo LIST /v > "$OutDir\schtasks.txt"
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run > "$OutDir\run_hkcu.txt"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run > "$OutDir\run_hklm.txt"
Get-WmiObject -Namespace root\subscription -Class __EventConsumer > "$OutDir\wmi_persistence.txt"

# --- 5. Autoruns (if Sysinternals is available) ---
if (Test-Path ".\autorunsc.exe") {
    .\autorunsc.exe -accepteula -a * -c > "$OutDir\autoruns.csv"
}

# --- 6. Event Logs (last 200 events per log) ---
Get-WinEvent -LogName Security -MaxEvents 200 | Export-Clixml "$OutDir\security_log.xml"
Get-WinEvent -LogName System -MaxEvents 200 | Export-Clixml "$OutDir\system_log.xml"
Get-WinEvent -LogName Application -MaxEvents 200 | Export-Clixml "$OutDir\application_log.xml"

# --- 7. File System Anomalies ---
Get-ChildItem -Path C:\Users\Public\ -Recurse -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object FullName,Length,LastWriteTime -First 50 |
    Out-File "$OutDir\public_recent_files.txt"

Get-ChildItem -Path $env:TEMP -Recurse -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object FullName,Length,LastWriteTime -First 50 |
    Out-File "$OutDir\temp_recent_files.txt"

# --- 8. User Accounts & Groups ---
net user > "$OutDir\users.txt"
net localgroup administrators > "$OutDir\admins.txt"

# --- 9. Defender / Security Status ---
Get-MpThreat > "$OutDir\defender_threats.txt"
Get-MpComputerStatus | Out-File "$OutDir\defender_status.txt"

# --- 10. Suspected Data Staging ---
Get-ChildItem -Path C:\ -Include *.zip,*.rar,*.7z -Recurse -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object FullName,Length,LastWriteTime -First 20 |
    Out-File "$OutDir\archives.txt"

Write-Output "[+] Collection complete. Review output in $OutDir"
