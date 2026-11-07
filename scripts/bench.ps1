#Requires -Version 7.0
<#
.SYNOPSIS
    Runs the chipsrc SLA benchmark matrix (7 iterations per operation), records median
    wall-clock latencies to `output/bench/<git-sha>.json`, and prints a summary table.
#>
param(
    [int]$Iterations = 7,
    [string]$Binary = "target/release/chipsrc.exe",
    [string]$BundleDir = "output/chipsrc"
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path $Binary)) {
    Write-Host "==> Building release binary..."
    cargo build --release
}

$gitSha = (git rev-parse --short HEAD).Trim()
$benchDir = Join-Path "output" "bench"
New-Item -ItemType Directory -Force -Path $benchDir | Out-Null

function Measure-MedianMs {
    param(
        [string]$Name,
        [scriptblock]$Action,
        [int]$Runs = $Iterations
    )
    $samples = [System.Collections.Generic.List[double]]::new()
    for ($i = 0; $i -lt $Runs; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        & $Action | Out-Null
        $sw.Stop()
        $samples.Add($sw.Elapsed.TotalMilliseconds)
    }
    $sorted = $samples | Sort-Object
    $mid = [int][Math]::Floor($sorted.Count / 2)
    $median = [Math]::Round($sorted[$mid], 2)
    $min = [Math]::Round($sorted[0], 2)
    $max = [Math]::Round($sorted[$sorted.Count - 1], 2)
    return [PSCustomObject]@{
        Operation = $Name
        MedianMs  = $median
        MinMs     = $min
        MaxMs     = $max
    }
}

$results = [System.Collections.Generic.List[object]]::new()

$results.Add((Measure-MedianMs "inspect ." { & $Binary inspect . }))
$results.Add((Measure-MedianMs "convert . --force (cold)" { & $Binary convert . -o $BundleDir --force } -Runs 3))
$results.Add((Measure-MedianMs "convert . (warm hit)" { & $Binary convert . -o $BundleDir }))
$results.Add((Measure-MedianMs "ensure . (warm hit)" { & $Binary ensure . -o output }))
$results.Add((Measure-MedianMs "sym convert_repo --no-sync" { & $Binary sym convert_repo --no-sync }))
$results.Add((Measure-MedianMs "sym convert_repo (auto-sync)" { & $Binary sym convert_repo }))
$results.Add((Measure-MedianMs "type ConvertConfig --no-sync" { & $Binary type ConvertConfig --no-sync }))
$results.Add((Measure-MedianMs "callers resolve_and_link --no-sync" { & $Binary callers resolve_and_link --no-sync }))
$results.Add((Measure-MedianMs "callees convert_repo --no-sync" { & $Binary callees convert_repo --no-sync }))
$results.Add((Measure-MedianMs "xref ConvertConfig --no-sync" { & $Binary xref ConvertConfig --no-sync }))
$results.Add((Measure-MedianMs "xref ConvertConfig (auto-sync)" { & $Binary xref ConvertConfig }))
$results.Add((Measure-MedianMs "path convert_repo resolve_and_link --no-sync" { & $Binary path convert_repo resolve_and_link --no-sync }))
$results.Add((Measure-MedianMs "impact resolve_and_link --no-sync" { & $Binary impact resolve_and_link --no-sync }))
$results.Add((Measure-MedianMs "search ConvertConfig --no-sync" { & $Binary search ConvertConfig --no-sync }))
$results.Add((Measure-MedianMs "hook session-start (native)" { & $Binary hook session-start }))

$outPath = Join-Path $benchDir "$gitSha.json"
$payload = @{
    git_sha    = $gitSha
    timestamp  = (Get-Date).ToString("o")
    iterations = $Iterations
    results    = $results
}
$payload | ConvertTo-Json -Depth 5 | Set-Content -Path $outPath -Encoding UTF8

Write-Host "`n=== chipsrc SLA Benchmark Results ($gitSha) ==="
$results | Format-Table -AutoSize
Write-Host "Saved benchmark report to $outPath"
