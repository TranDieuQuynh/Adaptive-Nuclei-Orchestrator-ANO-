param(
    [string]$PythonPath = ".\\.venv\\Scripts\\python.exe",
    [string]$NucleiPath = "D:\\Nuclei\\nuclei_3.7.1_windows_amd64\\nuclei.exe",
    [string]$SignaturePath = ".\\demo_runs\\signatures_thesis_demo.yaml",
    [string]$SeedPath = ".\\demo_runs\\facts_seed_thesis.json",
    [int]$MaxDepth = 3,
    [int]$MaxTemplatesPerDepth = 3,
    [int]$MaxParallelWorkers = 3
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-FactKey {
    param([object]$Fact)
    return "{0}|{1}" -f [string]$Fact.type, [string]$Fact.value
}

function Convert-FactToDemoLabel {
    param([object]$Fact)

    $t = [string]$Fact.type
    $v = [string]$Fact.value

    switch ($t) {
        "software_product" { return "tech:$v" }
        "framework" { return "tech:$v" }
        "path" { return "endpoint:$v" }
        "panel" { return "page:$v" }
        "feature" { return "feature:$v" }
        default { return "${t}:$v" }
    }
}

function Safe-NodeId {
    param([string]$Text)
    if (-not $Text) { return "N_empty" }
    return ("N_" + ($Text -replace "[^A-Za-z0-9_]", "_"))
}

function Read-JsonFile {
    param([string]$Path)
    return (Get-Content $Path -Raw | ConvertFrom-Json)
}

Write-Host "=== THESIS DEMO: Dynamic Orchestration + Blackboard + Attack Graph ===" -ForegroundColor Cyan
Write-Host "Workspace: $PWD"

if (-not (Test-Path $PythonPath)) {
    throw "Python not found at $PythonPath"
}
if (-not (Test-Path $NucleiPath)) {
    throw "Nuclei not found at $NucleiPath"
}
if (-not (Test-Path $SignaturePath)) {
    throw "Signature profile not found at $SignaturePath"
}
if (-not (Test-Path $SeedPath)) {
    throw "Seed file not found at $SeedPath"
}

$seedFacts = @(Read-JsonFile -Path $SeedPath)
$targetFact = $seedFacts | Where-Object { $_.type -eq "url" } | Select-Object -First 1
$targetUrl = if ($targetFact) { [string]$targetFact.value } else { "unknown-target" }

Write-Host ""
Write-Host "=== PHAN 1: TRANG THAI BAN DAU CUA MUC TIEU ===" -ForegroundColor Yellow
$seedView = [ordered]@{
    target = $targetUrl
    facts = @($seedFacts | ForEach-Object { Convert-FactToDemoLabel -Fact $_ })
}
$seedView | ConvertTo-Json -Depth 6
Write-Host "Luu y: Day la facts ban dau, chua phai ket luan lo hong." -ForegroundColor DarkYellow

Write-Host ""
Write-Host "=== PHAN 2: MO HINH SIGNATURE (DESCRIPTOR) ===" -ForegroundColor Yellow
Write-Host "Profile: $SignaturePath"
Write-Host "Moi template gom precondition + requirements + matching_features + output + cost/confidence."
Write-Host "Vi du template ids: login-check, xss-search-check, api-fuzz, idor-check, sensitive-data-check"

Write-Host ""
Write-Host "Running orchestrator..." -ForegroundColor Cyan
$engineArgs = @(
    ".\\engine.py",
    "--signatures", $SignaturePath,
    "--facts", $SeedPath,
    "--max-depth", "$MaxDepth",
    "--max-templates-per-depth", "$MaxTemplatesPerDepth",
    "--max-parallel-workers", "$MaxParallelWorkers",
    "--partial-coverage-threshold", "1.0",
    "--relaxed-fallback-coverage-threshold", "1.0",
    "--partial-score-penalty", "1.0",
    "--relaxed-fallback-score-penalty", "1.0",
    "--disable-validation-loop",
    "--disable-baseline-scan",
    "--nuclei-binary", $NucleiPath
)
& $PythonPath @engineArgs

if (-not (Test-Path ".\\facts_result.json")) {
    throw "facts_result.json not found after run"
}
if (-not (Test-Path ".\\facts_latest.json")) {
    throw "facts_latest.json not found after run"
}
if (-not (Test-Path ".\\attack_graph.json")) {
    throw "attack_graph.json not found after run"
}
if (-not (Test-Path ".\\facts_history.json")) {
    throw "facts_history.json not found after run"
}

$result = Read-JsonFile -Path ".\\facts_result.json"
$latestFacts = @(Read-JsonFile -Path ".\\facts_latest.json")
$attackGraph = @(Read-JsonFile -Path ".\\attack_graph.json")
$history = @(Read-JsonFile -Path ".\\facts_history.json")

$seedKeys = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($f in $seedFacts) {
    $null = $seedKeys.Add((Get-FactKey -Fact $f))
}
$newFacts = @($latestFacts | Where-Object { -not $seedKeys.Contains((Get-FactKey -Fact $_)) })

Write-Host ""
Write-Host "=== PHAN 3: BLACKBOARD LA TRUNG TAM DIEU PHOI ===" -ForegroundColor Yellow
Write-Host "Initial facts in blackboard: $(@($seedFacts).Count)"
Write-Host "Final facts in blackboard:   $(@($latestFacts).Count)"
Write-Host "New facts generated:         $(@($newFacts).Count)" -ForegroundColor Green
Write-Host "Snapshots recorded:          $(@($history).Count)"

Write-Host ""
Write-Host "=== PHAN 4: CO CHE MATCHING DONG ===" -ForegroundColor Yellow
$queryHistory = @($result.scheduling.template_query_history)
if ($queryHistory.Count -gt 0) {
    $q0 = $queryHistory[0]
    Write-Host "Depth $($q0.depth) Iteration $($q0.iteration): matched_templates=$($q0.templates_matched)"
    if ($q0.top_templates) {
        Write-Host "Top matched templates: $($q0.top_templates -join ', ')"
    }
}

Write-Host ""
Write-Host "=== PHAN 5: FAN-OUT TU CUNG FACTS ===" -ForegroundColor Yellow
$decisions = @($result.scheduling.scheduler_decisions)
$depth1Decisions = @($decisions | Where-Object { $_.depth -eq 1 })
$depth1Templates = @($depth1Decisions | Select-Object -ExpandProperty template -Unique)
Write-Host "Depth 1 matched/executed templates: $($depth1Templates.Count)"
if ($depth1Templates.Count -gt 0) {
    Write-Host "[Matcher] matched templates:" -ForegroundColor Cyan
    $depth1Templates | Select-Object -First 8 | ForEach-Object { Write-Host "  - $_" }
}
$launching = [Math]::Min($MaxParallelWorkers, [Math]::Max($depth1Templates.Count, 1))
Write-Host "[Scheduler] launching $launching tasks in parallel" -ForegroundColor Cyan

Write-Host ""
Write-Host "=== PHAN 6: DYNAMIC CHAINING NHIEU TANG ===" -ForegroundColor Yellow
$executionHistory = @($result.execution_history)
$successRuns = @($executionHistory | Where-Object { $_.new_facts_count -gt 0 })
if ($successRuns.Count -eq 0) {
    Write-Host "Chua co run nao sinh fact moi." -ForegroundColor DarkYellow
} else {
    foreach ($run in $successRuns | Select-Object -First 8) {
        $tid = [string]$run.template_id
        $trigger = $attackGraph | Where-Object { $_.to -eq $tid } | Select-Object -ExpandProperty trigger -First 1
        if ($trigger) {
            Write-Host "[Match] $trigger -> $tid"
        } else {
            Write-Host "[Match] runtime-state -> $tid"
        }
        Write-Host "[Execute] $tid"
        $outFacts = @($latestFacts | Where-Object { [string]$_.source -eq ("template-output:" + $tid) })
        foreach ($of in $outFacts | Select-Object -First 4) {
            Write-Host "[Output] $($of.type):$($of.value)"
        }
        Write-Host ""
    }
}

Write-Host "=== PHAN 7: KIEM SOAT VONG LAP VA CHI PHI ===" -ForegroundColor Yellow
$loopSkips = @($result.loop_prevention_history).Count
Write-Host "Loop-prevention events: $loopSkips"
Write-Host "Depth execution counts: $((($result.scheduling.depth_execution_counts | ConvertTo-Json -Compress)))"
if ($result.scheduling.budget_stop_reason) {
    Write-Host "Stop reason: $($result.scheduling.budget_stop_reason)"
}

Write-Host ""
Write-Host "=== PHAN 8: ATTACK GRAPH (RUNTIME) ===" -ForegroundColor Yellow
Write-Host "Edges in attack graph: $(@($attackGraph).Count)"

if ($result.risk_summary) {
    Write-Host ""
    Write-Host "=== PHAN BO SUNG: RISK SCORING ===" -ForegroundColor Yellow
    Write-Host "Risk level: $($result.risk_summary.risk_level)" -ForegroundColor Green
    Write-Host "Risk score: $($result.risk_summary.risk_score)"
    Write-Host "Vulnerability count: $($result.risk_summary.vulnerability_count)"
    Write-Host "Impact count: $($result.risk_summary.impact_count)"
}

$mermaidLines = @("flowchart TD")
foreach ($edge in $attackGraph) {
    $factLabel = [string]$edge.trigger
    $templateId = [string]$edge.to
    $factNode = Safe-NodeId -Text ("fact_" + $edge.from + "_" + $factLabel)
    $tplNode = Safe-NodeId -Text ("tpl_" + $templateId)
    $mermaidLines += "    $factNode((`"$factLabel`")) --> $tplNode[`"$templateId`"]"
}
foreach ($fact in $latestFacts) {
    $source = [string]$fact.source
    if (-not $source.StartsWith("template-output:")) { continue }
    $templateId = $source.Substring("template-output:".Length)
    $tplNode = Safe-NodeId -Text ("tpl_" + $templateId)
    $factLabel = "{0}:{1}" -f [string]$fact.type, [string]$fact.value
    $factNode = Safe-NodeId -Text ("out_" + $templateId + "_" + $factLabel)
    $mermaidLines += "    $tplNode[`"$templateId`"] --> $factNode((`"$factLabel`"))"
}
$mermaidPath = ".\\demo_runs\\attack_graph_thesis.mmd"
$mermaidLines | Set-Content $mermaidPath -Encoding UTF8

Write-Host ""
Write-Host "=== DEMO RESULT SUMMARY ===" -ForegroundColor Green
Write-Host "Seed facts:   $(@($seedFacts).Count)"
Write-Host "Latest facts: $(@($latestFacts).Count)"
Write-Host "New facts:    $(@($newFacts).Count)" -ForegroundColor Green
Write-Host ""
Write-Host "Top new facts:" -ForegroundColor Cyan
$newFacts | Select-Object -First 12 type, value, source, confidence | Format-Table -AutoSize

Write-Host "Artifacts:" -ForegroundColor Cyan
Write-Host " - facts_result.json"
Write-Host " - facts_latest.json"
Write-Host " - attack_graph.json"
Write-Host " - facts_history.json"
Write-Host " - $mermaidPath"
