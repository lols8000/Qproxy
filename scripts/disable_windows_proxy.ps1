$path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $path -Name ProxyEnable -Type DWord -Value 0
Write-Host "Proxy do Windows desativado." -ForegroundColor Yellow
