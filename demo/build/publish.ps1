# Make the release zips: self-contained, single-file .exe files for x64 and Arm64 Windows.
# Usage (from the demo folder, in PowerShell):   .\build\publish.ps1
# Needs the .NET 8 SDK.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$out = Join-Path (Get-Location) 'artifacts'
New-Item -ItemType Directory -Force $out | Out-Null
foreach ($rid in 'win-x64', 'win-arm64') {
    $dir = Join-Path $out "HPSP-Demo-$rid"
    New-Item -ItemType Directory -Force $dir | Out-Null
    foreach ($app in 'HpspAcuSimulator', 'HpspReaderSimulator') {
        dotnet publish "src/$app" -c Release -r $rid --self-contained true -p:PublishSingleFile=true -o $dir
        if ($LASTEXITCODE -ne 0) { throw "publish failed: $app $rid" }
    }
    Get-ChildItem $dir -Filter *.pdb | Remove-Item
    Copy-Item ..\RUNNING.md, ..\RUNNING.fr.md $dir
    Copy-Item ..\LICENSE (Join-Path $dir 'LICENSE.txt')
    $zip = Join-Path $out "HPSP-Demo-$rid.zip"
    if (Test-Path $zip) { Remove-Item $zip }
    Compress-Archive -Path $dir -DestinationPath $zip
}
Write-Host "Made: $out\HPSP-Demo-win-x64.zip and $out\HPSP-Demo-win-arm64.zip"
