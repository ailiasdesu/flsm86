<#
  verify_ingame.ps1 — 游戏运行中检查：加载的 nvngx_dlssg.dll 是不是我们部署的版本、ACE 是否在场
  用法： .\verify_ingame.ps1            （默认找 HTGame）
         .\verify_ingame.ps1 -Name HTGame
#>
param([string]$Name = "HTGame")
$ErrorActionPreference = 'SilentlyContinue'
$p = Get-Process $Name | Select-Object -First 1
if (-not $p) { Write-Host "没有找到进程 $Name（游戏未运行？）"; exit 1 }
Write-Host "进程: $($p.ProcessName) pid=$($p.Id) 内存=$([math]::Round($p.WorkingSet64/1MB,0)) MB"
Write-Host ""
Write-Host "=== 反作弊模块（在场说明 ACE 已挂上）==="
$ace = $p.Modules | Where-Object { $_.ModuleName -match "ACE|SGuard|AntiCheat" }
if ($ace) { $ace | ForEach-Object { Write-Host ("  " + $_.ModuleName) } } else { Write-Host "  (无)" }
Write-Host ""
Write-Host "=== DLSS 相关模块 ==="
$dlss = $p.Modules | Where-Object { $_.ModuleName -match "nvngx|dlssg|sl\.|streamline" }
if ($dlss) {
  foreach ($m in $dlss) {
    $ver = ""
    try { $ver = (Get-Item $m.FileName).VersionInfo.FileVersion } catch {}
    Write-Host ("  {0,-24} base=0x{1:X}  版本={2}" -f $m.ModuleName, [int64]$m.BaseAddress, $ver)
    Write-Host ("      " + $m.FileName)
  }
} else { Write-Host "  (游戏还没加载 DLSS 模块 —— 需要进入渲染流程/画面)" }
Write-Host ""
Write-Host "=== 判定 ==="
$g = $dlss | Where-Object { $_.ModuleName -eq "nvngx_dlssg.dll" } | Select-Object -First 1
if ($g) {
  $v = (Get-Item $g.FileName).VersionInfo.FileVersion
  Write-Host "  已加载 nvngx_dlssg.dll，版本 = $v"
  if ($v -eq "310,5,2,0") { Write-Host "  -> 与游戏期望版本一致（可能是我们部署的版本或原版，看下方路径）" }
} else {
  Write-Host "  尚未加载 nvngx_dlssg.dll —— 请进入游戏画面后重跑本脚本"
}
