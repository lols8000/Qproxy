param(
    [string]$TargetDir = "$PSScriptRoot\..\data\windivert"
)

$ErrorActionPreference = "Stop"
$url = "https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip"
$expectedSha256 = "63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15"

$tmpZip = Join-Path $env:TEMP "WinDivert-2.2.2-A.zip"
Write-Host "[Qproxy] Baixando WinDivert 2.2.2 oficial..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $url -OutFile $tmpZip -UseBasicParsing

$hash = (Get-FileHash -Path $tmpZip -Algorithm SHA256).Hash.ToUpperInvariant()
if ($hash -ne $expectedSha256) {
    Remove-Item -Force $tmpZip -ErrorAction SilentlyContinue
    throw "SHA-256 invalido! Esperado: $expectedSha256 | Obtido: $hash"
}
Write-Host "[Qproxy] SHA-256 verificado com sucesso." -ForegroundColor Green

$tmpExtract = Join-Path $env:TEMP ("windivert_extract_" + [guid]::NewGuid().ToString("N"))
Expand-Archive -Path $tmpZip -DestinationPath $tmpExtract -Force

$arch = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
$sysName = if ($arch -eq "x64") { "WinDivert64.sys" } else { "WinDivert32.sys" }

$dllSource = Get-ChildItem -Path $tmpExtract -Recurse -Filter "WinDivert.dll" | Where-Object { $_.Directory.Name -eq $arch } | Select-Object -First 1
$sysSource = Get-ChildItem -Path $tmpExtract -Recurse -Filter $sysName | Where-Object { $_.Directory.Name -eq $arch } | Select-Object -First 1

if (-not $dllSource -or -not $sysSource) {
    throw "Arquivos $arch/WinDivert.dll ou $arch/$sysName nao encontrados no ZIP."
}

New-Item -ItemType Directory -Force -Path $TargetDir | Out-Null
Copy-Item -Path $dllSource.FullName -Destination (Join-Path $TargetDir "WinDivert.dll") -Force
Copy-Item -Path $sysSource.FullName -Destination (Join-Path $TargetDir $sysName) -Force

Remove-Item -Force $tmpZip -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $tmpExtract -ErrorAction SilentlyContinue

Write-Host "[Qproxy] WinDivert ($arch) instalado em: $((Resolve-Path $TargetDir).Path)" -ForegroundColor Green
