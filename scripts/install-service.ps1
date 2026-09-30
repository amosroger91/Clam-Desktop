param(
    [Parameter(Mandatory=$true)][string]$Runtime,
    [Parameter(Mandatory=$true)][string]$Agent,
    [Parameter(Mandatory=$true)][string]$Profile,
    [Parameter(Mandatory=$true)][string]$HostExecutable,
    [Parameter(Mandatory=$true)][PSCredential]$Credential
)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run service installation from an elevated PowerShell window.'
}
$account = New-Object Security.Principal.NTAccount($Credential.UserName)
$sid = $account.Translate([Security.Principal.SecurityIdentifier]).Value
# Use the desktop user's identity, never LocalSystem: the service consumes that user's writable config.
if ($sid -ne $identity.User.Value) { throw 'Use the same Windows account as this desktop session, elevated with UAC.' }
foreach ($item in @($Runtime, $Agent, $HostExecutable)) {
    if (-not (Test-Path -LiteralPath $item -PathType Leaf)) { throw "Required file missing: $item" }
}
$profilePath = (Resolve-Path -LiteralPath $Profile).Path.TrimEnd('\')
if (-not (Test-Path -LiteralPath (Join-Path $profilePath 'monitor/control.key'))) { throw 'Enable monitoring in Sentinel first.' }
if (Get-Service SentinelMonitor -ErrorAction SilentlyContinue) { throw 'SentinelMonitor already exists. Stop and remove it before reinstalling.' }
$paths = @((Resolve-Path -LiteralPath $HostExecutable).Path, (Resolve-Path -LiteralPath $Runtime).Path, (Resolve-Path -LiteralPath $Agent).Path, $profilePath)
if ($paths | Where-Object { $_ -match '["\r\n]' }) { throw 'Invalid service path.' }
$binary = ($paths | ForEach-Object { '"' + $_ + '"' }) -join ' '
# Close the desktop and stop its background agent before transferring ownership to SCM.
$previousRunMode = $env:ELECTRON_RUN_AS_NODE
try { $env:ELECTRON_RUN_AS_NODE = '1'; & $Runtime $Agent $profilePath --stop }
finally { $env:ELECTRON_RUN_AS_NODE = $previousRunMode }
if ($LASTEXITCODE -ne 0) { throw 'Could not stop the desktop background agent.' }
New-Service -Name SentinelMonitor -DisplayName 'Sentinel continuous scanner' -BinaryPathName $binary -StartupType Automatic -Credential $Credential
& sc.exe failure SentinelMonitor reset= 86400 actions= restart/30000/restart/60000/restart/300000
Start-Service SentinelMonitor
Get-Service SentinelMonitor
