# 从样本文件计算 p50 / p95 / p99 百分位。
# 用法: powershell -File scripts\bench_percentiles.ps1 -Path <样本文件>
# 样本文件: 每行一个数字（耗时，秒或纳秒均可，单位一致即可）。
param(
    [Parameter(Mandatory = $true)][string]$Path
)

$lines = Get-Content $Path -ErrorAction Stop | Where-Object { $_ -match '^\d+(\.\d+)?$' }
if ($lines.Count -eq 0) {
    Write-Error "no numeric samples in $Path"
    exit 1
}
$samples = $lines | ForEach-Object { [double]$_ } | Sort-Object

function Get-Percentile($arr, $p) {
    $n = $arr.Count
    $rank = ($p / 100.0) * ($n - 1)
    $lo = [math]::Floor($rank)
    $hi = [math]::Ceiling($rank)
    if ($lo -eq $hi) { return $arr[$lo] }
    $frac = $rank - $lo
    return $arr[$lo] * (1 - $frac) + $arr[$hi] * $frac
}

Write-Output "samples: $($samples.Count)"
Write-Output ("p50: {0}" -f (Get-Percentile $samples 50))
Write-Output ("p95: {0}" -f (Get-Percentile $samples 95))
Write-Output ("p99: {0}" -f (Get-Percentile $samples 99))
