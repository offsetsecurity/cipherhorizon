<#
.SYNOPSIS
  Independent check of the collector's native Windows cryptography inventory (sensor windows-cng).

.DESCRIPTION
  The collector reads CNG through hand-written Go bindings. This script asks the same questions with
  a DIFFERENT implementation (C# P/Invoke compiled by PowerShell) and Microsoft's own `certutil
  -csplist`, then compares:

    1. every registered CNG provider, key storage provider and legacy CSP;
    2. every registered algorithm identifier, and which provider offers each;
    3. every post-quantum parameter set, including NEGATIVE controls (values Windows must refuse);
    4. the SHAPE of the CBOM: legacy algorithms carry a citation, only the allow-listed key storage
       provider was opened.

  It only reads. The probe generates an ephemeral in-memory key pair per parameter set, exactly as the
  collector does, and destroys it.

.PARAMETER Cbom
  A CBOM produced by `cipherhorizon-collector run -o` on THIS machine.
#>
param([Parameter(Mandatory)][string]$Cbom)

$ErrorActionPreference = 'Stop'
if (-not ('CngOracle' -as [type])) { Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class CngOracle {
  [StructLayout(LayoutKind.Sequential)] struct AlgId { public IntPtr Name; public uint Class; public uint Flags; }
  [StructLayout(LayoutKind.Sequential)] struct KspName { public IntPtr Name; public IntPtr Comment; }
  [DllImport("bcrypt.dll")] static extern int BCryptEnumAlgorithms(uint ops, out uint count, out IntPtr list, uint flags);
  [DllImport("bcrypt.dll")] static extern int BCryptEnumProviders([MarshalAs(UnmanagedType.LPWStr)] string alg, out uint count, out IntPtr list, uint flags);
  [DllImport("bcrypt.dll")] static extern int BCryptEnumRegisteredProviders(ref uint cb, out IntPtr list);
  [DllImport("bcrypt.dll")] static extern void BCryptFreeBuffer(IntPtr p);
  [DllImport("bcrypt.dll")] static extern int BCryptOpenAlgorithmProvider(out IntPtr h, [MarshalAs(UnmanagedType.LPWStr)] string alg, string impl, uint flags);
  [DllImport("bcrypt.dll")] static extern int BCryptCloseAlgorithmProvider(IntPtr h, uint flags);
  [DllImport("bcrypt.dll")] static extern int BCryptGenerateKeyPair(IntPtr h, out IntPtr key, uint length, uint flags);
  [DllImport("bcrypt.dll")] static extern int BCryptSetProperty(IntPtr h, [MarshalAs(UnmanagedType.LPWStr)] string prop, byte[] input, uint cb, uint flags);
  [DllImport("bcrypt.dll")] static extern int BCryptFinalizeKeyPair(IntPtr key, uint flags);
  [DllImport("bcrypt.dll")] static extern int BCryptDestroyKey(IntPtr key);
  [DllImport("ncrypt.dll")] static extern int NCryptEnumStorageProviders(out uint count, out IntPtr list, uint flags);
  [DllImport("ncrypt.dll")] static extern void NCryptFreeBuffer(IntPtr p);

  public static string[] Algorithms(uint op) {
    uint n; IntPtr list;
    if (BCryptEnumAlgorithms(op, out n, out list, 0) != 0) return new string[0];
    var r = new List<string>();
    for (int i = 0; i < n; i++) {
      var e = (AlgId)Marshal.PtrToStructure(IntPtr.Add(list, i * Marshal.SizeOf(typeof(AlgId))), typeof(AlgId));
      r.Add(Marshal.PtrToStringUni(e.Name));
    }
    BCryptFreeBuffer(list); return r.ToArray();
  }
  public static string[] ProvidersOf(string alg) {
    uint n; IntPtr list;
    if (BCryptEnumProviders(alg, out n, out list, 0) != 0) return new string[0];
    var r = new List<string>();
    for (int i = 0; i < n; i++) r.Add(Marshal.PtrToStringUni(Marshal.ReadIntPtr(list, i * IntPtr.Size)));
    BCryptFreeBuffer(list); return r.ToArray();
  }
  public static string[] Registered() {
    uint cb = 0; IntPtr list;
    if (BCryptEnumRegisteredProviders(ref cb, out list) != 0) return new string[0];
    int n = Marshal.ReadInt32(list); IntPtr arr = Marshal.ReadIntPtr(list, IntPtr.Size);
    var r = new List<string>();
    for (int i = 0; i < n; i++) r.Add(Marshal.PtrToStringUni(Marshal.ReadIntPtr(arr, i * IntPtr.Size)));
    BCryptFreeBuffer(list); return r.ToArray();
  }
  public static string[] StorageProviders() {
    uint n; IntPtr list;
    if (NCryptEnumStorageProviders(out n, out list, 0) != 0) return new string[0];
    var r = new List<string>();
    for (int i = 0; i < n; i++) r.Add(Marshal.PtrToStringUni(Marshal.ReadIntPtr(list, i * 2 * IntPtr.Size)));
    NCryptFreeBuffer(list); return r.ToArray();
  }
  // Does the default provider accept this parameter set? Ephemeral key, destroyed at once.
  public static bool Accepts(string alg, string set) {
    IntPtr h; if (BCryptOpenAlgorithmProvider(out h, alg, null, 0) != 0) return false;
    try {
      IntPtr key; if (BCryptGenerateKeyPair(h, out key, 0, 0) != 0) return false;
      try {
        var v = System.Text.Encoding.Unicode.GetBytes(set + "\0");
        if (BCryptSetProperty(key, "ParameterSetName", v, (uint)v.Length, 0) != 0) return false;
        return BCryptFinalizeKeyPair(key, 0) == 0;
      } finally { BCryptDestroyKey(key); }
    } finally { BCryptCloseAlgorithmProvider(h, 0); }
  }
}
'@ }

$doc = Get-Content $Cbom -Raw | ConvertFrom-Json
function Prop($c, $n) { ($c.properties | Where-Object { $_.name -eq "cipherhorizon:$n" } | Select-Object -First 1).value }
$ours = @($doc.components | Where-Object { Prop $_ 'provider-kind' })
$fail = 0
function Check($ok, $what) { if ($ok) { "PASS  $what" } else { "FAIL  $what"; $script:fail++ } }

# ---- 1. providers ------------------------------------------------------------------------------
$cngOracle = @([CngOracle]::Registered()) + @([CngOracle]::StorageProviders()) | Sort-Object -Unique
$cspOracle = @(& certutil -csplist 2>$null | Where-Object { $_ -match '^Provider Name:' } | ForEach-Object { ($_ -replace '^Provider Name:\s*', '').Trim() }) | Sort-Object -Unique
$ourCng = @($ours | Where-Object { (Prop $_ 'provider-kind') -ne 'csp' } | ForEach-Object { $_.name }) | Sort-Object -Unique
$ourCsp = @($ours | Where-Object { (Prop $_ 'provider-kind') -eq 'csp' } | ForEach-Object { $_.name }) | Sort-Object -Unique
"CNG providers: oracle $($cngOracle.Count), collector $($ourCng.Count)"
"legacy CSPs:   certutil $($cspOracle.Count), collector $($ourCsp.Count)"
$missingCng = @($cngOracle | Where-Object { $ourCng -notcontains $_ }); $extraCng = @($ourCng | Where-Object { $cngOracle -notcontains $_ })
Check ($missingCng.Count -eq 0 -and $extraCng.Count -eq 0) "CNG and key storage provider names are identical ($($missingCng -join ', ')$($extraCng -join ', '))"
# certutil lists the KSPs too; keep only what it reports that is not a CNG provider.
$cspOnly = @($cspOracle | Where-Object { $cngOracle -notcontains $_ })
$missingCsp = @($cspOnly | Where-Object { $ourCsp -notcontains $_ }); $extraCsp = @($ourCsp | Where-Object { $cspOnly -notcontains $_ })
Check ($missingCsp.Count -eq 0 -and $extraCsp.Count -eq 0) "legacy CSP names are identical to certutil -csplist ($($missingCsp -join ', ')$($extraCsp -join ', '))"

# ---- 2. algorithms and who offers them -------------------------------------------------------------
$oracleAlgs = @(1, 2, 4, 8, 0x10, 0x20, 0x40 | ForEach-Object { [CngOracle]::Algorithms($_) }) | Sort-Object -Unique
$oracleOffers = @{}
foreach ($a in $oracleAlgs) { foreach ($p in [CngOracle]::ProvidersOf($a)) { if (-not $oracleOffers[$p]) { $oracleOffers[$p] = @() }; $oracleOffers[$p] += $a } }
"registered algorithm identifiers: oracle $($oracleAlgs.Count)"
$bad = @()
foreach ($p in $oracleOffers.Keys) {
  $c = $ours | Where-Object { $_.name -eq $p -and (Prop $_ 'provider-kind') -ne 'csp' } | Select-Object -First 1
  $list = @((Prop $c 'native-algorithms') -split ',' | Where-Object { $_ })
  foreach ($a in $oracleOffers[$p]) { if ($list -notcontains $a) { $bad += "$p is missing $a" } }
}
Check ($bad.Count -eq 0) "every algorithm the oracle says a provider offers is named on that provider ($($bad -join '; '))"

# ---- 3. post-quantum parameter sets, with negative controls -----------------------------------------
$catalogNames = @($doc.components | Where-Object { $_.type -eq 'cryptographic-asset' } | ForEach-Object { $_.name })
$prov = ($doc.dependencies | Where-Object { $_.ref -like 'provider:cng:*' -and $_.provides })
$ourProvided = @($prov | ForEach-Object { $_.provides } | ForEach-Object { ($_ -replace '^crypto/algorithm/', '') -replace '@.*$', '' }) | Sort-Object -Unique
$cases = @(
  @('ML-KEM', '512', 'ml-kem-512'), @('ML-KEM', '768', 'ml-kem-768'), @('ML-KEM', '1024', 'ml-kem-1024'),
  @('ML-DSA', '44', 'ml-dsa-44'), @('ML-DSA', '65', 'ml-dsa-65'), @('ML-DSA', '87', 'ml-dsa-87'))
foreach ($c in $cases) {
  $yes = [CngOracle]::Accepts($c[0], $c[1]); $has = $ourProvided -contains $c[2]
  Check ($yes -eq $has) "$($c[0]) parameter set $($c[1]): Windows says $yes, collector reports $has"
}
foreach ($n in @(@('ML-KEM', '999'), @('ML-KEM', '1'), @('ML-DSA', '1'), @('ML-DSA', '999'))) {
  Check (-not [CngOracle]::Accepts($n[0], $n[1])) "negative control: $($n[0]) parameter set $($n[1]) is refused by Windows (so the collector could never report it)"
}
Check ($ourProvided -notcontains 'ml-kem-999' -and $ourProvided -notcontains 'ml-dsa-1') "no invented parameter set appears in the CBOM"

# ---- 4. shape ---------------------------------------------------------------------------------------
$opened = @($ours | Where-Object { (Prop $_ 'opened') -eq 'true' } | ForEach-Object { $_.name })
Check ($opened.Count -eq 1 -and $opened[0] -eq 'Microsoft Software Key Storage Provider') "only the in-box software key storage provider was opened ($($opened -join ', '))"
$hardware = @($ours | Where-Object { $_.name -match 'Platform Crypto|Smart Card Key Storage|Passport|Pluton' -and (Prop $_ 'provider-kind') -ne 'csp' })
Check ($hardware.Count -gt 0 -and @($hardware | Where-Object { (Prop $_ 'opened') -ne 'false' }).Count -eq 0) "hardware and third-party key storage providers are listed and NOT opened ($($hardware.Count) listed)"
$legacy = @($doc.components | Where-Object { $_.type -eq 'cryptographic-asset' -and (Prop $_ 'classical-status') })
Check ($legacy.Count -gt 0 -and @($legacy | Where-Object { -not (Prop $_ 'classical-basis') }).Count -eq 0) "every legacy algorithm ($($legacy.Count)) carries its citation"

"`n$fail failed"
# An explicit code: otherwise the exit status of the last native command (certutil) would leak out.
exit $(if ($fail -gt 0) { 1 } else { 0 })
