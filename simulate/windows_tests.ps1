# Harmless actions that trigger the Windows rules. Run as Administrator on a test VM
# with Sysmon and the Wazuh agent installed. Each step cleans up after itself.

# 100100 - encoded PowerShell (the payload is just "whoami")
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("whoami"))
powershell.exe -NoProfile -enc $enc

# 100103 - scheduled task created, then deleted
schtasks /create /tn "SoarTest" /tr "cmd.exe /c echo test" /sc once /st 23:59 /f
schtasks /delete /tn "SoarTest" /f

# 100104 - certutil download of a harmless page
certutil.exe -urlcache -split -f "https://example.com" "$env:TEMP\soar-test.html"
Remove-Item "$env:TEMP\soar-test.html" -ErrorAction SilentlyContinue
certutil.exe -urlcache -f "https://example.com" delete

# 100102 - test user added to Administrators, then removed
net user soar_test P@ssw0rd-Test-Only-123 /add
net localgroup Administrators soar_test /add
net user soar_test /delete

# 100101 (LSASS access) is not simulated here: it needs a dumping tool.
# To test it, run Sysinternals procdump on the test VM:  procdump64.exe -ma lsass.exe
Write-Host "Done. Check the Wazuh dashboard for rules 100100-100104."
