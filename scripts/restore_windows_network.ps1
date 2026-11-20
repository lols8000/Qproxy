$ErrorActionPreference = "SilentlyContinue"

Write-Host "[Qproxy] Restaurando configuracoes de rede do Windows..." -ForegroundColor Cyan

# 1. Desativa proxy do Windows
$path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $path -Name ProxyEnable -Type DWord -Value 0

# 2. Restaura DNS dos adaptadores fisicos ativos para automatico (DHCP)
$adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq "Up" }
foreach ($adapter in $adapters) {
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses
}

# 3. Limpa cache DNS do Windows
ipconfig /flushdns | Out-Null

Write-Host "[Qproxy] Proxy desativado, DNS restaurado e cache DNS limpo." -ForegroundColor Green
