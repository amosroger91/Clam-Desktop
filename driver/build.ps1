param(
  [Parameter(Mandatory=$true)][string]$WdkRoot,
  [string]$SdkRoot = "${env:ProgramFiles(x86)}\Windows Kits\10"
)
$ErrorActionPreference = 'Stop'
$wdkTree = (Resolve-Path -LiteralPath $WdkRoot).Path
if (Test-Path -LiteralPath (Join-Path $wdkTree 'c')) { $wdkTree = Join-Path $wdkTree 'c' }
$kitVersion = (Get-ChildItem -LiteralPath (Join-Path $wdkTree 'Include') -Directory | Sort-Object Name -Descending | Select-Object -First 1).Name
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsInstall = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$vsInstall) { throw 'MSVC x64 compiler is required' }
$vcVersion = (Get-Content -LiteralPath (Join-Path $vsInstall 'VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt')).Trim()
$vcRoot = Join-Path $vsInstall "VC\Tools\MSVC\$vcVersion"
$include = Join-Path $wdkTree "Include\$kitVersion"
$lib = Join-Path $wdkTree "Lib\$kitVersion\km\x64"
if (!(Test-Path -LiteralPath (Join-Path $lib 'FltMgr.lib'))) { throw 'Complete x64 WDK libraries are required' }
$output = Join-Path $PSScriptRoot '..\test-output\driver'
New-Item -ItemType Directory -Path $output -Force | Out-Null
& "$vcRoot\bin\Hostx64\x64\cl.exe" /nologo /c /kernel /Zl /GS /W4 /D_AMD64_ /D_WIN64 /DWINVER=0x0A00 /D_WIN32_WINNT=0x0A00 "/I$include\km" "/I$include\shared" "/I$SdkRoot\Include\$kitVersion\shared" "/I$include\km\crt" "/I$vcRoot\include" "/Fo$output\SentinelFilter.obj" "$PSScriptRoot\SentinelFilter.c"
if ($LASTEXITCODE -ne 0) { throw 'Driver compilation failed' }
& "$vcRoot\bin\Hostx64\x64\link.exe" /nologo /DRIVER:WDM /SUBSYSTEM:NATIVE /ENTRY:GsDriverEntry /NODEFAULTLIB /INTEGRITYCHECK /MANIFEST:NO "/LIBPATH:$lib" "/OUT:$output\SentinelFilter.sys" "$output\SentinelFilter.obj" FltMgr.lib ntoskrnl.lib hal.lib BufferOverflowK.lib
if ($LASTEXITCODE -ne 0) { throw 'Driver link failed' }
Write-Output "Built unsigned experimental source only: $output\SentinelFilter.sys"
Write-Output 'No driver was installed, signed, loaded or added to the desktop package.'
