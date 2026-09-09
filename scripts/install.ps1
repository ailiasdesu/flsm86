<#
  FLSm86 开机自启注册（需要管理员）
#>
param([string]$ExePath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'bin\flsm86_svc.exe'))
$ErrorActionPreference = 'Stop'
$log = Join-Path $env:LOCALAPPDATA 'FlSm86\svc.log'
New-Item -ItemType Directory -Force -Path (Split-Path $log -Parent) | Out-Null
$action = "\"$ExePath\" --run --log \"$log\""
schtasks /Create /TN "FLSm86" /TR $action /SC ONLOGON /RL HIGHEST /F | Out-Null
Write-Host "已注册计划任务 FLSm86（登录时以最高权限启动）"
Write-Host "查看日志: $log"
