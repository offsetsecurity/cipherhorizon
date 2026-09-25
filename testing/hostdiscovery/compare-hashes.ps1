<#
.SYNOPSIS
  Independent check of the SHA-256 values in a host CBOM: recomputes each file's hash with
  Get-FileHash and compares.

.DESCRIPTION
  For every library/application component that carries a hash, finds the file (the component's
  evidence location, relative to the system drive) and compares the collector's SHA-256 with
  Windows' own. Reads only files the CBOM already names; nothing else is opened.

.PARAMETER Cbom
  A CBOM produced by `cipherhorizon-collector run -o`.
#>
param([Parameter(Mandatory)][string]$Cbom)

$ErrorActionPreference = 'SilentlyContinue'
$doc = Get-Content $Cbom -Raw | ConvertFrom-Json
$agree = 0; $bad = @(); $noHash = 0; $missing = @()
foreach ($c in $doc.components) {
  if ($c.type -eq 'cryptographic-asset') { continue }
  if (-not $c.hashes) { $noHash++; continue }
  $rel = $c.evidence.occurrences[0].location
  $path = Join-Path "$env:SystemDrive\" ($rel -replace '/', '\')
  if (-not (Test-Path -LiteralPath $path)) { $missing += $rel; continue }
  $ours = ($c.hashes | Where-Object { $_.alg -eq 'SHA-256' } | Select-Object -First 1).content
  $theirs = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower()
  if ($ours -eq $theirs) { $agree++ } else { $bad += "$rel : cbom=$ours windows=$theirs" }
}
"components with a hash that AGREE with Get-FileHash: $agree"
"components WITHOUT a hash (not hashed by the collector): $noHash"
"components whose file could not be found now: $(@($missing).Count)"; $missing | ForEach-Object { "  $_" }
"MISMATCHES: $(@($bad).Count)"; $bad | ForEach-Object { "  $_" }
if (@($bad).Count -gt 0) { exit 1 }
