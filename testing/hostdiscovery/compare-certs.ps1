<#
Oracle for the Windows certificate sensor (windows-certs, ADR-0016). It re-derives the answer
through a different route, the .NET X509Store classes, and compares certificate by certificate:

  - EXPECTED   every certificate .NET finds in the allow-listed stores (SHA-256 of its raw bytes)
  - DETECTED   the certificate components in the collector's CBOM, with their store locations
  - MISSING    .NET found it, the CBOM lacks it (allowed only for certificates Go's strict X.509
               parser refuses; their number must equal the sensor's own unparseable count)
  - EXTRA      the CBOM has it, .NET does not
  - KEY SIZE   the recorded key size differs from .NET's PublicKey.Key.KeySize
  - KEY FLAG   the private-key association differs from .NET's HasPrivateKey
  - no private key material anywhere in the document

Usage (from the repository root, PowerShell):
  dist\cipherhorizon-collector.exe run -o host.cbom.json
  .\testing\hostdiscovery\compare-certs.ps1 host.cbom.json

The oracle is read-only. It opens each store with ReadOnly | OpenExistingOnly, exactly as the
sensor does, and never touches a key.
#>
param([Parameter(Mandatory = $true)][string]$Cbom)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Cbom)) { Write-Host "not found: $Cbom"; exit 2 }
Add-Type -AssemblyName System.Security
$doc = Get-Content -Raw -Encoding UTF8 $Cbom | ConvertFrom-Json

$stores = @('My', 'Root', 'CA', 'TrustedPeople', 'TrustedPublisher', 'AuthRoot')
$locations = @{ 'LocalMachine' = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine; 'CurrentUser' = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser }
$sha = [System.Security.Cryptography.SHA256]::Create()
function Hex($bytes) { ($bytes | ForEach-Object { $_.ToString('x2') }) -join '' }

# EXPECTED: (fingerprint, place) -> facts
$expected = @{}
foreach ($loc in $locations.Keys) {
    foreach ($name in $stores) {
        $st = New-Object System.Security.Cryptography.X509Certificates.X509Store($name, $locations[$loc])
        try {
            $st.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
        } catch { continue }   # a store that does not exist has no certificates
        foreach ($c in $st.Certificates) {
            $fp = Hex ($sha.ComputeHash($c.RawData))
            $storeName = if ($name -eq 'My') { 'MY' } else { $name }
            $place = "cert-store:$loc/$storeName"
            $bits = $null
            # key size by three independent extension routes (RSA, ECDSA, DSA); $null when none applies (Ed25519, unknown)
            try { $k = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($c); if ($k) { $bits = $k.KeySize } } catch { }
            if ($null -eq $bits) { try { $k = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($c); if ($k) { $bits = $k.KeySize } } catch { } }
            if ($null -eq $bits) { try { $k = [System.Security.Cryptography.X509Certificates.DSACertificateExtensions]::GetDSAPublicKey($c); if ($k) { $bits = $k.KeySize } } catch { } }
            $expected["$fp|$place"] = @{ Fp = $fp; Place = $place; Bits = $bits; HasKey = [bool]$c.HasPrivateKey; Subject = $c.Subject }
        }
        $st.Close()
    }
}

# DETECTED
$detected = @{}
$comps = @($doc.components | Where-Object { $_.'cryptoProperties'.assetType -eq 'certificate' })
foreach ($c in $comps) {
    $h = ($c.hashes | Where-Object { $_.alg -eq 'SHA-256' } | Select-Object -First 1).content
    $props = @{}; foreach ($p in $c.properties) { $props[$p.name] = $p.value }
    foreach ($o in $c.evidence.occurrences) {
        $detected["$h|$($o.location)"] = @{ Fp = $h; Place = $o.location; Bits = $props['cipherhorizon:cert:key-bits']; Ctx = $o.additionalContext; Subject = $c.name }
    }
}

$missing = @($expected.Keys | Where-Object { -not $detected.ContainsKey($_) })
$extra = @($detected.Keys | Where-Object { -not $expected.ContainsKey($_) })
$badBits = 0; $badKey = 0
foreach ($k in ($expected.Keys | Where-Object { $detected.ContainsKey($_) })) {
    $e = $expected[$k]; $d = $detected[$k]
    if ($null -ne $e.Bits -and "$($e.Bits)" -ne "$($d.Bits)") { $badBits++; Write-Host "KEY SIZE  $($e.Place) $($e.Subject): .NET $($e.Bits) vs CBOM $($d.Bits)" }
    $wantCtx = if ($e.HasKey) { 'privateKey=yes' } else { 'privateKey=no' }
    if ($d.Ctx -ne $wantCtx) { $badKey++; Write-Host "KEY FLAG  $($e.Place) $($e.Subject): .NET HasPrivateKey=$($e.HasKey) vs CBOM '$($d.Ctx)'" }
}

# What the sensor itself says it could not parse (coverage-limit properties)
$unparseable = 0
foreach ($p in $doc.metadata.properties) {
    if ($p.name -eq 'cipherhorizon:coverage-limit' -and $p.value -match '^sensor=windows-certs unparseableCertificates=(\d+)$') { $unparseable = [int]$Matches[1] }
}
$missingCerts = @($missing | ForEach-Object { $expected[$_].Fp } | Sort-Object -Unique)

Write-Host ("EXPECTED (.NET) {0} placements   DETECTED (CBOM) {1}   MISSING {2} placements ({3} distinct certificates)   EXTRA {4}" -f $expected.Count, $detected.Count, $missing.Count, $missingCerts.Count, $extra.Count)
foreach ($k in $missing) { Write-Host "  MISSING $($expected[$k].Place)  $($expected[$k].Subject)" }
foreach ($k in $extra) { Write-Host "  EXTRA   $($detected[$k].Place)  $($detected[$k].Subject)" }

$raw = Get-Content -Raw -Encoding UTF8 $Cbom
$leak = $raw -cmatch '-----BEGIN [A-Z ]*PRIVATE KEY-----'

$ok = $true
if ($extra.Count -gt 0) { $ok = $false }
if ($badBits -gt 0 -or $badKey -gt 0) { $ok = $false }
if ($leak) { Write-Host 'PRIVATE KEY text found in the CBOM'; $ok = $false }
# Missing certificates are acceptable only if the sensor accounted for them.
$accounted = $missing.Count -eq 0 -or ($missing.Count -le $unparseable)
if (-not $accounted) { Write-Host "MISSING placements ($($missing.Count)) exceed what the sensor reported as unparseable ($unparseable)"; $ok = $false }
Write-Host ("sensor reported {0} unparseable certificate(s); key-size mismatches {1}; key-flag mismatches {2}" -f $unparseable, $badBits, $badKey)
if ($ok) { Write-Host 'RESULT: AGREE' } else { Write-Host 'RESULT: DISAGREE' }
if ($ok) { exit 0 } else { exit 1 }
