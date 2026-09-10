<#
  deploy_dlssg.ps1 — 把 SM86 版 nvngx_dlssg.dll 部署到游戏目录（带备份/还原）

  为什么需要它：带内核反作弊（如 ACE）的游戏会终止一切运行时注入，
  但实测「把游戏目录里的 nvngx_dlssg.dll 换成版本补丁后的 SM86 版」不会被拦截
  （加载过程是正常的 LoadImage + 正常模块）。

  用法：
    .\deploy_dlssg.ps1 -GameDir "E:\...\StreamlineCore\Binaries\ThirdParty\Win64" -Sm86Dll "C:\...\nvngx_dlssg.dll"
    .\deploy_dlssg.ps1 -GameDir "E:\...\Win64" -Restore
#>
param(
  [Parameter(Mandatory=$true)][string]$GameDir,
  [string]$Sm86Dll,
  [switch]$Restore,
  [string]$VersionOverride
)
$ErrorActionPreference = 'Stop'
$target = Join-Path $GameDir 'nvngx_dlssg.dll'
$bak    = Join-Path $GameDir 'nvngx_dlssg.dll.flbak'

if ($Restore) {
  if (Test-Path $bak) { Move-Item $bak $target -Force; Write-Host "已还原原版: $target" }
  else { Write-Host "没有找到备份 $bak" }
  exit 0
}
if (-not $Sm86Dll) { throw "需要 -Sm86Dll 指定 SM86 版 nvngx_dlssg.dll" }
if (-not (Test-Path $target)) { throw "找不到游戏目录里的 $target" }

if (-not (Test-Path $bak)) { Copy-Item $target $bak -Force }
$gameVer = (Get-Item $target).VersionInfo.FileVersion
$sm86Ver = (Get-Item $Sm86Dll).VersionInfo.FileVersion
Write-Host "游戏原版版本: $gameVer / SM86 版版本: $sm86Ver"
if (-not $VersionOverride) { $VersionOverride = $gameVer }

$patched = Join-Path $env:TEMP ('nvngx_patched_' + [guid]::NewGuid().ToString('N') + '.dll')
$py = Join-Path $PSScriptRoot '..\tools\patch_ver.py'
python $py $Sm86Dll $patched $VersionOverride
if ($LASTEXITCODE -ne 0) { throw "版本补丁失败" }
Write-Host ("补丁后版本: " + (Get-Item $patched).VersionInfo.FileVersion)

Copy-Item $patched $target -Force
Remove-Item $patched -Force -ErrorAction SilentlyContinue
Write-Host "已部署到: $target"
Write-Host "还原: .\deploy_dlssg.ps1 -GameDir $GameDir -Restore"
