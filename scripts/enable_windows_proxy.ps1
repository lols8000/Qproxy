param(
    [string]$Proxy = "127.0.0.1:8899"
)

$path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $path -Name ProxyEnable -Type DWord -Value 1
Set-ItemProperty -Path $path -Name ProxyServer -Value $Proxy
Set-ItemProperty -Path $path -Name ProxyOverride -Value "<local>"

Write-Host "Qproxy ativado no Windows em $Proxy" -ForegroundColor Green
Write-Host "Mantenha o processo qproxy em execução. Alguns aplicativos ignoram o proxy do Windows."
