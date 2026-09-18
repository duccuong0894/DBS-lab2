# Fix-Docker.ps1 — chay SAU KHI da bat Intel Virtualization (VT-x) trong BIOS va reboot.
# Cach chay: chuot phai PowerShell -> Run as administrator -> E:\DBS\Lab4\Fix-Docker.ps1
#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

Write-Output "[1/5] Bat Windows features can thiet..."
dism /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
dism /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart

Write-Output "[2/5] Cap nhat + dat mac dinh WSL2..."
wsl --update
wsl --set-default-version 2

Write-Output "[3/5] Khoi dong lai Docker Desktop..."
Get-Process "Docker Desktop", "com.docker.backend" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 3
Start-Process "$env:LOCALAPPDATA\Programs\DockerDesktop\Docker Desktop.exe"
Write-Output "Cho Docker khoi dong ~60s..."
Start-Sleep -Seconds 60

Write-Output "[4/5] Kiem tra..."
docker context use desktop-linux
docker version
docker ps

Write-Output "[5/5] XONG neu 'docker ps' khong bao loi. Neu van loi, reboot may roi chay lai script."
