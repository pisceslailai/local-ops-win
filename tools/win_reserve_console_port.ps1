# 为总控台「先占用」本地端口窗口，避免被 Hyper-V / WSL2 的保留段吞掉。
#
# 症状：总控台报「端口 9600-9609 均被占用，无法启动」，其实 netstat 什么都没有，
# 真正的 bind 错误是 WinError 10013（WSAEACCES）——端口落在 Hyper-V/WSL 动态
# 预留的连续大段里（每次开机重新划分，所以时好时坏）。
#
# 「管理的端口排除」是管理员显式加的排除段：Hyper-V/WSL 会绕开它，而普通程序
# 依然可以显式 bind（本机 50000-50059 实测可绑）。把总控台窗口加进去，端口就
# 固定在 9600，书签/前端不再漂移。
#
# 用法（会自动提权，UAC 确认一次）：
#   powershell -ExecutionPolicy Bypass -File tools\win_reserve_console_port.ps1
# 可选：连动态端口范围一起恢复成 Windows 11 默认值（把 Hyper-V 的预留段整体
# 赶到高位，9600 段更彻底地不受影响）：
#   ... -RestoreDynamicRange

[CmdletBinding()]
param(
    [int]$StartPort = 9600,
    [int]$Count = 20,
    [switch]$RestoreDynamicRange
)

$ErrorActionPreference = 'Continue'
$EndPort = $StartPort + $Count - 1

function Test-Admin {
    $identity = [Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    return $identity.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "需要管理员权限，正在请求提权（UAC）..."
    $argumentList = @('-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', "`"$PSCommandPath`"",
        '-StartPort', $StartPort, '-Count', $Count)
    if ($RestoreDynamicRange) { $argumentList += '-RestoreDynamicRange' }
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs `
            -ArgumentList $argumentList
    } catch {
        Write-Host "提权被取消或失败：$($_.Exception.Message)"
        exit 2
    }
    exit 0
}

function Test-Bind([int]$Port) {
    $listener = $null
    try {
        $listener = New-Object System.Net.Sockets.TcpListener(
            [System.Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        $listener.Stop()
        return $true
    } catch {
        if ($listener) { try { $listener.Stop() } catch { } }
        return $false
    } finally {
        if ($listener) { $listener = $null }
    }
}

function Show-PortState([string]$Title) {
    Write-Host ""
    Write-Host "== $Title =="
    netsh int ipv4 show dynamicport tcp
    netsh int ipv4 show excludedportrange protocol=tcp
}

Show-PortState "当前系统端口状态"
$bindableBefore = Test-Bind $StartPort
Write-Host ("端口 {0} 当前{1}" -f $StartPort,
    $(if ($bindableBefore) { "可绑定（暂时没被抢）" } else { "不可绑定（被保留段覆盖）" }))

# 现有 Hyper-V/WSL 的保留段会与目标窗口重叠，导致 netsh 拒绝新增；
# 先停掉 WinNAT/HNS 释放本会话的保留，加完再恢复。
Write-Host ""
Write-Host "== 暂停 WinNAT / HNS（会中断 WSL 与 Docker 的网络数秒，稍后自动恢复）=="
& wsl.exe --shutdown 2>$null | Out-Null
foreach ($service in @('winnat', 'hns')) {
    $null = net stop $service 2>&1
}
Start-Sleep -Seconds 2

if ($RestoreDynamicRange) {
    Write-Host ""
    Write-Host "== 恢复动态端口范围为 Windows 11 默认 49152+16384 =="
    $null = net stop winnat 2>&1
    netsh int ipv4 set dynamicport tcp start=49152 num=16384
    netsh int ipv6 set dynamicport tcp start=49152 num=16384
}

Write-Host ""
Write-Host ("== 预留 {0}-{1}（持久生效，重启后仍然有效）==" -f $StartPort, $EndPort)
$addResult = (netsh int ipv4 add excludedportrange protocol=tcp `
        startport=$StartPort numberofports=$Count store=persistent 2>&1) -join "`n"
Write-Host $addResult.Trim()
$overlapped = $addResult -match '重叠|overlap|already|已存在'

foreach ($service in @('hns', 'winnat')) {
    $null = net start $service 2>&1
}
Start-Sleep -Seconds 2

Show-PortState "执行后的端口状态"
$bindableAfter = Test-Bind $StartPort

if ($bindableAfter) {
    Write-Host ""
    Write-Host ("完成：端口 {0} 现在可以绑定，总控台会稳定停在 9600。" -f $StartPort)
    Write-Host "被抢的旧保留段会在下次开机重新划分时让位（现在也已被排除段保护）。"
    exit 0
}

Write-Host ""
Write-Host ("端口 {0} 现在仍不可绑定。" -f $StartPort)
if ($overlapped) {
    Write-Host "原因：已经有保留段覆盖该窗口，且本次没能释放（可能被其他服务持有）。"
}
Write-Host "排除段已持久写入，重启一次后 Hyper-V/WSL 会绕开这段端口。"
Write-Host "重启后如仍不可用，请把上面的 netsh 输出发给维护者。"
exit 3
