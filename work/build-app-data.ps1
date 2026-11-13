param(
    [string]$JdkBin = (Join-Path $env:JAVA_HOME 'bin'),
    [string]$AndroidJar = (Join-Path $env:ANDROID_SDK_ROOT 'platforms\android-32\android.jar'),
    [string]$ToolRoot,
    [switch]$IncludeDeviceCheck
)
$ErrorActionPreference = 'Stop'
# Git Bash may inherit PowerShell 7 module paths while launching Windows PowerShell.
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -Force
$taskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskToolRoot = if ($ToolRoot) { $ToolRoot } elseif ($env:MC4_TOOL_ROOT) { $env:MC4_TOOL_ROOT } else { Join-Path $taskRoot 'tools\android' }
$taskOutput = Join-Path $PSScriptRoot 'appdata-build'
$taskRun = Join-Path $taskOutput ([IO.Path]::GetRandomFileName())
$taskClasses = Join-Path $taskRun 'classes'
$taskDex = Join-Path $taskRun 'dex'
$taskSmali = Join-Path $taskRun 'smali'
$taskPackage = 'com\gameloft\android\ANMP\GloftM4HM'
$taskDestination = Join-Path $taskRoot ('app\smali\' + $taskPackage)
$taskManifest = Join-Path $taskOutput 'provenance.json'
$taskSource = Join-Path $PSScriptRoot 'AppData.java'
$taskSources = @($taskSource)
$taskRegistered = [IO.File]::ReadAllText((Join-Path $taskRoot 'app\AndroidManifest.xml')).Contains('android:name=".AppDataDeviceCheck"')
if ([bool]$IncludeDeviceCheck -ne $taskRegistered) { throw 'Diagnostic instrumentation source/manifest mismatch.' }
if ($IncludeDeviceCheck) { $taskSources += Join-Path $PSScriptRoot 'AppDataDeviceCheck.java' }
New-Item -ItemType Directory -Path $taskClasses,$taskDex,$taskSmali -Force | Out-Null
try {
    & (Join-Path $JdkBin 'javac.exe') --release 8 -encoding UTF-8 -classpath $AndroidJar -d $taskClasses $taskSources
    if ($LASTEXITCODE -ne 0) { throw 'AppData javac failed.' }
    $taskClassFiles = @(Get-ChildItem -LiteralPath $taskClasses -Recurse -File -Filter '*.class')
    & (Join-Path $JdkBin 'java.exe') -cp (Join-Path $env:ANDROID_SDK_ROOT 'build-tools\37.0.0\lib\d8.jar') com.android.tools.r8.D8 --release --lib $AndroidJar --min-api 24 --output $taskDex $taskClassFiles.FullName
    if ($LASTEXITCODE -ne 0) { throw 'AppData D8 failed.' }
    & (Join-Path $JdkBin 'java.exe') -jar (Join-Path $taskToolRoot 'baksmali.jar') disassemble --api 24 --debug-info false -o $taskSmali (Join-Path $taskDex 'classes.dex')
    if ($LASTEXITCODE -ne 0) { throw 'AppData baksmali failed.' }
    $taskFiles = @(Get-ChildItem -LiteralPath (Join-Path $taskSmali $taskPackage) -File)
    if (!$taskFiles.Count -or @($taskFiles | Where-Object { $_.Name -notmatch '^AppData(?:DeviceCheck)?(?:\$.*)?\.smali$' }).Count) { throw 'Unexpected AppData generated class.' }
    $taskOld = if (Test-Path -LiteralPath $taskManifest) { Get-Content -LiteralPath $taskManifest -Raw | ConvertFrom-Json } else { $null }
    $taskCurrent = @(Get-ChildItem -LiteralPath $taskDestination -File -Filter 'AppData*.smali')
    foreach ($taskFile in $taskCurrent) {
        $taskRecord = @($taskOld.files | Where-Object { $_.name -eq $taskFile.Name })
        if ($taskRecord.Count -ne 1 -or (Get-FileHash -LiteralPath $taskFile.FullName).Hash -ne $taskRecord[0].sha256) { throw ('Unowned/modified generated class: ' + $taskFile.FullName) }
    }
    foreach ($taskFile in $taskFiles) { Copy-Item -LiteralPath $taskFile.FullName -Destination (Join-Path $taskDestination $taskFile.Name) }
    foreach ($taskFile in $taskCurrent) {
        if ($taskFile.Name -notin $taskFiles.Name) { Remove-Item -LiteralPath $taskFile.FullName }
    }
    $taskRecords = @($taskFiles | ForEach-Object { @{name=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash} })
    @{source_sha256=(Get-FileHash -LiteralPath $taskSource).Hash;devicecheck_sha256=$(if ($IncludeDeviceCheck) { (Get-FileHash -LiteralPath $taskSources[1]).Hash } else { $null });android_jar=$AndroidJar;files=$taskRecords} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $taskManifest -Encoding UTF8
    Write-Output ('AppData source/dex/smali generated: ' + $taskFiles.Count + ' classes')
} finally {
    $taskResolved = [IO.Path]::GetFullPath($taskRun)
    $taskBoundary = [IO.Path]::GetFullPath($taskOutput) + [IO.Path]::DirectorySeparatorChar
    if (!$taskResolved.StartsWith($taskBoundary,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe AppData scratch cleanup path.' }
    Remove-Item -LiteralPath $taskResolved -Recurse -Force
}
