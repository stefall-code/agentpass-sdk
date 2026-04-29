<#
.SYNOPSIS
    AgentPass 一键重置 — 重置信任评分 + 解除封禁，恢复初始状态
#>

$ErrorActionPreference = "SilentlyContinue"
$PORT = 8000

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║         AgentPass — 一键重置信任评分                   ║" -ForegroundColor Magenta
Write-Host "  ╚══════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""

$base = "http://localhost:$PORT"

try {
    Invoke-WebRequest -Uri "$base/api/feishu/status" -TimeoutSec 3 -UseBasicParsing | Out-Null
} catch {
    Write-Host "  服务器未运行! 请先执行 .\start_feishu.ps1" -ForegroundColor Red
    Read-Host "按回车退出"
    exit 1
}

Write-Host "[1/3] 查询当前状态..." -ForegroundColor Yellow
try {
    $trust = Invoke-RestMethod -Uri "$base/api/delegate/trust" -TimeoutSec 5
    foreach ($name in $trust.agents.PSObject.Properties.Name) {
        $score = $trust.agents.$name.trust_score
        $revoked = $trust.agents.$name.auto_revoked
        $icon = if ($revoked) { "🔥" } elseif ($score -lt 0.5) { "⚠️" } else { "✅" }
        $color = if ($revoked) { "Red" } elseif ($score -lt 0.5) { "Yellow" } else { "Green" }
        Write-Host "      $icon $name : $score" -ForegroundColor $color
        if ($revoked) { Write-Host "         (已封禁)" -ForegroundColor Red }
    }
} catch {}

Write-Host ""
Write-Host "[2/3] 重置信任评分 + 解除封禁..." -ForegroundColor Yellow
try {
    $r = Invoke-RestMethod -Uri "$base/api/governance/reset-all" -Method POST -TimeoutSec 5 -ContentType "application/json"
    Write-Host "      重置成功" -ForegroundColor Green
} catch {
    try {
        Invoke-RestMethod -Uri "$base/api/delegate/trust/reset" -Method POST -TimeoutSec 5 -ContentType "application/json" -Body "{}" | Out-Null
        Write-Host "      信任评分已重置" -ForegroundColor Green
    } catch {
        Write-Host "      重置失败，请手动重启服务器" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "[3/3] 验证重置结果..." -ForegroundColor Yellow
try {
    $trust = Invoke-RestMethod -Uri "$base/api/delegate/trust" -TimeoutSec 5
    foreach ($name in $trust.agents.PSObject.Properties.Name) {
        $score = $trust.agents.$name.trust_score
        Write-Host "      ✅ $name : $score" -ForegroundColor Green
    }
} catch {}

Write-Host ""
Write-Host "  所有 Agent 已恢复初始状态，可以重新开始演示!" -ForegroundColor Green
Write-Host "  执行 .\demo_4step.ps1 开始四步渐进式演示" -ForegroundColor DarkGray
Write-Host ""
