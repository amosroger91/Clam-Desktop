$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$compiler = Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw '.NET Framework 4 C# compiler is required to build the Windows service host.' }
$output = Join-Path $repo 'service/SentinelMonitor.exe'
& $compiler /nologo /target:exe "/out:$output" /reference:System.ServiceProcess.dll (Join-Path $repo 'service/SentinelMonitor.cs')
if ($LASTEXITCODE -ne 0) { throw 'Service host compilation failed.' }
Write-Output $output
