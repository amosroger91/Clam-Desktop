$ErrorActionPreference = 'Stop'
Stop-Service SentinelMonitor -ErrorAction Stop
& sc.exe delete SentinelMonitor
if ($LASTEXITCODE -ne 0) { throw 'Could not remove SentinelMonitor.' }
Write-Output 'Service removed. Settings, pending work, and detections have been preserved.'
