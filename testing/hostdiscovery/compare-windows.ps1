<#
.SYNOPSIS
  Ground-truth check of `cipherhorizon run` on a Windows host, against an independent oracle.

.DESCRIPTION
  Runs (or reads) a host CBOM, then finds crypto-library candidates a *different, broader* way
  (any .dll/.exe under the same roots whose file name OR embedded product/description says
  crypto) and compares:  EXPECTED (oracle)  vs  DETECTED (CBOM)  ->  MISSING / FALSE POSITIVE /
  VERSION MISMATCH.  The oracle deliberately does not use the collector's name patterns.

  It only READS files' version resources (Get-Item .VersionInfo); it never opens keys or secrets.

.PARAMETER Cbom
  Path of a CBOM produced by `cipherhorizon run -o`. If omitted, the binary is run first.
.PARAMETER Binary
  Path of the collector, cipherhorizon-collector.exe (default: dist\cipherhorizon-collector.exe). The full cipherhorizon.exe also works.

.EXAMPLE
  .\testing\hostdiscovery\compare-windows.ps1
  # then, from an elevated PowerShell, again, to see what elevation reveals:
  .\testing\hostdiscovery\compare-windows.ps1
#>
param([string]$Cbom, [string]$Binary = 'dist\cipherhorizon-collector.exe')

$ErrorActionPreference = 'SilentlyContinue'
if (-not $Cbom) {
  $Cbom = Join-Path $env:TEMP 'cipherhorizon-host.cbom.json'
  & $Binary run -o $Cbom 2>&1 | ForEach-Object { "  collector: $_" }
}
$isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
"privilege of this comparison run: " + $(if ($isAdmin) { 'ADMIN' } else { 'standard user' })

$doc = Get-Content $Cbom -Raw | ConvertFrom-Json
$ours = @{}
foreach ($c in $doc.components) {
  if ($c.type -ne 'cryptographic-asset') { $ours[$c.evidence.occurrences[0].location.ToLower()] = $c }
}
"DETECTED by the collector: $($ours.Count) artefacts"
($doc.metadata.properties | Where-Object { $_.name -like '*:coverage' -or $_.name -like '*:privilege-tier' }).value | ForEach-Object { "  $_" }

$roots = @("$env:SystemDrive\Program Files", "$env:SystemDrive\Program Files (x86)", "$env:SystemDrive\ProgramData")
$nameRx = 'crypto|ssl|gnutls|nettle|hogweed|nss3|sodium|gcrypt|wolfssl|mbed|botan|libssh|gpg|openssh|bcrypt'
$prodRx = 'openssl|gnutls|nettle|network security services|libsodium|libgcrypt|wolfssl|mbed ?tls|botan|libssh|gnupg|cryptograph'
$cand = foreach ($r in $roots) {
  if (Test-Path $r) {
    Get-ChildItem $r -Recurse -Depth 8 -Include *.dll, *.exe -File -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -match $nameRx -or $_.VersionInfo.ProductName -match $prodRx -or $_.VersionInfo.FileDescription -match $prodRx }
  }
}
"EXPECTED by the oracle (broad criteria): $(@($cand).Count) candidates"

$agree = 0; $mismatch = @(); $missing = @()
foreach ($f in $cand) {
  $rel = $f.FullName.Substring($env:SystemDrive.Length + 1).Replace('\', '/').ToLower()
  if ($ours.ContainsKey($rel)) {
    $agree++
    $r = $f.VersionInfo.FileVersionRaw
    $ov = if ($r) { "$($r.Major).$($r.Minor).$($r.Build).$($r.Revision)" } else { '' }
    $cv = $ours[$rel].version
    if ($ov -and $cv -and $ov -ne $cv) { $mismatch += "$rel : oracle=$ov collector=$cv" }
  } else { $missing += [pscustomobject]@{ Name = $f.Name; Product = $f.VersionInfo.ProductName } }
}
$candRel = $cand | ForEach-Object { $_.FullName.Substring($env:SystemDrive.Length + 1).Replace('\', '/').ToLower() }
$falsePos = $ours.Keys | Where-Object { $candRel -notcontains $_ }

"AGREED (found by both):               $agree"
"VERSION MISMATCHES:                   $(@($mismatch).Count)"; $mismatch | ForEach-Object { "  $_" }
"FALSE POSITIVES (collector-only):     $(@($falsePos).Count)"; $falsePos | ForEach-Object { "  $_" }
"MISSING (oracle-only, to adjudicate): $(@($missing).Count)"
$missing | Group-Object Name | Sort-Object Count -Descending | ForEach-Object { "  $($_.Count) x $($_.Name)  [$(($_.Group | Select-Object -First 1).Product)]" }
"Adjudicate MISSING by hand: it mixes real gaps (a crypto library the collector does not recognise), correct exclusions"
"(plugins/wrappers that merely mention crypto) and blind spots the CBOM already lists as cipherhorizon:not-seen."
if (@($mismatch).Count -gt 0 -or @($falsePos).Count -gt 0) { exit 1 }
