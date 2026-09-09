<#
  FLSm86 卸载：移除计划任务与常驻进程（不删除载荷）
#>
$ErrorActionPreference = 'Continue'
schtasks /Delete /TN "FLSm86" /F 2>$null | Out-Null
Get-Process flsm86_svc -ErrorAction SilentlyContinue | Stop-Process -Force
Write-Host "已移除计划任务 FLSm86 并结束常驻进程"
Write-Host "（载荷仍在 %LOCALAPPDATA%\FlSm86\proxy\payload.enc，如需彻底清除请手动删除该目录）"
