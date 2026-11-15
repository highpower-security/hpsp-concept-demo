# Make the release zips: self-contained, single-file .exe files for x64 and Arm64 Windows.
# Usage (from the demo folder, in PowerShell):   .\build\publish.ps1 -Build 3
# The zips are named HPSP-Demo-<version>-build<n>-<win-x64|win-arm64>.zip, so every build
# can be told apart. Raise the build number for each new set you hand out.
# Needs the .NET 8 SDK.
param([Parameter(Mandatory = $true)][int]$Build)
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$version = ([xml](Get-Content src\HpspAcuSimulator\HpspAcuSimulator.csproj)).Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
$name = "HPSP-Demo-$version-build$Build"
$out = Join-Path (Get-Location) 'artifacts'
New-Item -ItemType Directory -Force $out | Out-Null
foreach ($rid in 'win-x64', 'win-arm64') {
    $dir = Join-Path $out "$name-$rid"
    New-Item -ItemType Directory -Force $dir | Out-Null
    foreach ($app in 'HpspAcuSimulator', 'HpspReaderSimulator') {
        dotnet publish "src/$app" -c Release -r $rid --self-contained true -p:PublishSingleFile=true -o $dir
        if ($LASTEXITCODE -ne 0) { throw "publish failed: $app $rid" }
    }
    Get-ChildItem $dir -Filter *.pdb | Remove-Item
    Copy-Item ..\RUNNING.md, ..\RUNNING.fr.md $dir
    Copy-Item ..\LICENSE (Join-Path $dir 'LICENSE.txt')
    $zip = Join-Path $out "$name-$rid.zip"
    if (Test-Path $zip) { Remove-Item $zip }
    Compress-Archive -Path $dir -DestinationPath $zip
}
Write-Host "Made: $out\$name-win-x64.zip and $out\$name-win-arm64.zip"
