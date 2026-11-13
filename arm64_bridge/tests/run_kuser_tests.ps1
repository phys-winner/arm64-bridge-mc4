$ErrorActionPreference = 'Stop'
$mc4BridgeRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$mc4TestOutput = Join-Path $mc4BridgeRoot 'build_kuser_tests'
New-Item -ItemType Directory -Path $mc4TestOutput -Force | Out-Null
$mc4VsWhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$mc4VsRoot = & $mc4VsWhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $mc4VsRoot) { throw 'Local MSVC C++ toolchain not found.' }
$mc4VcVars = Join-Path $mc4VsRoot 'VC\Auxiliary\Build\vcvars64.bat'
$mc4TestSource = Join-Path $PSScriptRoot 'test_arm32_guest_atomic.cpp'
$mc4TestBinary = Join-Path $mc4TestOutput 'test_arm32_guest_atomic.exe'
$mc4Include = Join-Path $mc4BridgeRoot 'src'
$mc4Command = 'call "{0}" >nul && cl.exe /nologo /std:c++20 /EHsc /W4 /O2 /I"{1}" "{2}" /Fe:"{3}" && "{3}"' -f $mc4VcVars, $mc4Include, $mc4TestSource, $mc4TestBinary
Push-Location -LiteralPath $mc4TestOutput
try {
    & $env:ComSpec /d /s /c $mc4Command
    if ($LASTEXITCODE -ne 0) { throw "guest atomic regression failed: $LASTEXITCODE" }
} finally { Pop-Location }
