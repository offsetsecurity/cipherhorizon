<#
CipherHorizon machine inventory engine for Windows, version 3.0.0

What it does: runs each signature listed below with one of a few read-only capabilities,
and writes what it finds to a plain-text facts file you can read before you upload it.

  registry   reads named values of a registry key (and of its sub-keys to a set depth);
             with subkeys=yes it also lists the names of the sub-keys
  certstore  lists the certificates in the named stores, with whether a private key is associated
  file       finds files by name under folders: path, size, version and SHA-256 (not their content)
  program    lists installed programs whose name matches
  lines      reads text files and keeps only the lines that match
  query      runs ONE of the fixed read-only queries listed in this engine ($Queries below:
             the effective TLS cipher suites, TPM, BitLocker and virtualisation-based security
             state, HTTP.sys certificate bindings, key providers, SMB and WinRM settings, .NET
             runtimes, what the installed OpenSSH can do), named by its id; a signature cannot
             name a command, only pick a query from that table
  listeners  lists listening sockets with the owning process, its executable and the
             cryptographic DLLs that process has loaded (names only)

What it never does: change anything, install anything, make a network connection, open a
file named like a key, or read a private key. It starts no program other than Windows' own
certutil.exe, netsh.exe and ssh.exe from System32, each with the fixed read-only arguments
written in $Queries; everything else is a PowerShell cmdlet in this process.

The signatures (what to collect) come from the CipherHorizon server's signature database
and are listed just below; the server shows the same list on its Inventory page. To collect something new, the database changes, not this engine.

Usage, in PowerShell (as Administrator for a fuller picture; it works without, and says so):

    Unblock-File .\cipherhorizon-inventory.ps1
    powershell -NoProfile -ExecutionPolicy RemoteSigned -File .\cipherhorizon-inventory.ps1

If a policy refuses every unsigned script, read this one, then use -ExecutionPolicy Bypass
instead (for this one process only).

Then upload the output file on the Inventory page of your CipherHorizon server.
#>
param([string]$OutFile = "", [string]$SignatureFile = "")

# ---- signatures: what to collect, from the CipherHorizon signature database --------------
# The server fills this in when it hands the script out; -SignatureFile reads them from a file.
$Signatures = ''
#@@SIGNATURES-BEGIN@@
#@@SIGNATURES-END@@

$ErrorActionPreference = 'SilentlyContinue'
$EngineVersion = '3.0.0'
if (-not $OutFile) { $OutFile = Join-Path (Get-Location) "cipherhorizon-facts-$env:COMPUTERNAME.txt" }

$lines = New-Object System.Collections.Generic.List[string]
function Add-Fact([string[]]$Fields) {
    # A tab or line break inside a value would break the format: replace it with a space.
    $lines.Add((($Fields | ForEach-Object { "$_" -replace "[`t`r`n]", ' ' }) -join "`t"))
}

# Files whose names announce a key are never opened (a .pub public key is allowed).
$KeyName = '(?i)(^|[-_.])(priv|privkey|private|key|keys|secret|pkcs12|p12|pfx|jks|keystore)([-_.]|$)'
function Test-KeyFile([string]$Path) {
    $name = [System.IO.Path]::GetFileName($Path)
    return ($name -match $KeyName) -and -not $name.EndsWith('.pub')
}
function Test-KeyLine([string]$Text) { return ($Text -match 'PRIVATE KEY|BEGIN OPENSSH|BEGIN OpenVPN Static key') }
function Split-List([string]$Value) { return @($Value -split '\|' | Where-Object { $_ -ne '' } | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) }) }
# DLLs whose presence in a process says which cryptography it runs with (the TLS and key-storage
# layers of Windows, and the libraries applications bring along).
$CryptoDll = '(?i)^(schannel|ncrypt|ncryptsslp|ncryptprov|rsaenh|dssenh|libssl[^\\]*|libcrypto[^\\]*|libeay32|ssleay32|nss3|smime3|nspr4|libsodium[^\\]*|libgcrypt[^\\]*|libgnutls[^\\]*|[^\\]*wolfssl[^\\]*|[^\\]*mbed(tls|crypto|x509)[^\\]*|[^\\]*botan[^\\]*|libssh[^\\]*|libtomcrypt[^\\]*|cryptopp[^\\]*|sunec|sunmscapi|libtss2[^\\]*|softhsm2[^\\]*)\.dll$'
$Sys32 = Join-Path $env:WINDIR 'System32'

# ---- the query table ---------------------------------------------------------------------
# Each query is a fixed, read-only script block written here, never in a signature. A signature
# names the id; the engine runs the block and keeps the lines the signature's match selects.
# The three external tools are Windows' own, called by full path.
$TlsVersion = @{ 768 = 'SSL 3.0'; 769 = 'TLS 1.0'; 770 = 'TLS 1.1'; 771 = 'TLS 1.2'; 772 = 'TLS 1.3' }
$Queries = @{
    # One suite name per line (on some builds the cmdlet hands back one object whose Name is the whole list).
    'tls.cipher-suites' = { @(Get-TlsCipherSuite | ForEach-Object { $_.Name }) | ForEach-Object { "$_" -split '\s+' } | Where-Object { $_ -ne '' } }
    'tls.curves' = { @(Get-TlsEccCurve) | ForEach-Object { "$_" -split '\s+' } | Where-Object { $_ -ne '' } }
    'tpm' = {
        $t = Get-CimInstance -Namespace root/cimv2/Security/MicrosoftTpm -ClassName Win32_Tpm
        if ($t) { 'present: yes'; "enabled: $($t.IsEnabled_InitialValue)"; "activated: $($t.IsActivated_InitialValue)"; "owned: $($t.IsOwned_InitialValue)"; "spec: $($t.SpecVersion)"; "manufacturer: $($t.ManufacturerIdTxt) $($t.ManufacturerVersion)" }
        else { 'present: not readable (no TPM, or Administrator rights are needed)' }
    }
    'bitlocker' = { Get-BitLockerVolume | ForEach-Object { "$($_.MountPoint) type=$($_.VolumeType) status=$($_.VolumeStatus) method=$($_.EncryptionMethod) protection=$($_.ProtectionStatus) protectors=$(@($_.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join '/')" } }
    'deviceguard' = {
        $d = Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard
        if ($d) { "vbs-status: $($d.VirtualizationBasedSecurityStatus)"; "services-configured: $($d.SecurityServicesConfigured -join ',')"; "services-running: $($d.SecurityServicesRunning -join ',')"; "code-integrity-enforcement: $($d.CodeIntegrityPolicyEnforcementStatus)" }
    }
    'http.sslcert' = { & (Join-Path $Sys32 'netsh.exe') http show sslcert }
    'certstore.providers' = { & (Join-Path $Sys32 'certutil.exe') -store My; & (Join-Path $Sys32 'certutil.exe') -user -store My }
    'smb.server' = {
        $s = Get-SmbServerConfiguration
        if ($s) { foreach ($n in 'EnableSMB1Protocol', 'EnableSMB2Protocol', 'RequireSecuritySignature', 'EnableSecuritySignature', 'EncryptData', 'RejectUnencryptedAccess', 'EncryptionCiphers', 'Smb2DialectMin', 'Smb2DialectMax', 'EnableInsecureGuestLogons') { if ($null -ne $s.$n) { "${n}: $($s.$n)" } } }
    }
    'winrm.listeners' = { Get-ChildItem WSMan:\localhost\Listener | ForEach-Object { $k = Get-ChildItem $_.PSPath; "$($_.Name): " + (@($k | Where-Object { $_.Name -in 'Transport', 'Port', 'Address', 'Hostname', 'CertificateThumbprint', 'Enabled' } | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' ') } }
    'dotnet.runtimes' = {
        foreach ($root in @((Join-Path $env:ProgramFiles 'dotnet\shared'), (Join-Path ${env:ProgramFiles(x86)} 'dotnet\shared'))) {
            if (Test-Path -LiteralPath $root) { Get-ChildItem -LiteralPath $root -Directory | ForEach-Object { $n = $_.Name; Get-ChildItem -LiteralPath $_.FullName -Directory | ForEach-Object { "$n $($_.Name) $root" } } }
        }
    }
    'host.role' = {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        $roles = @('standalone workstation', 'member workstation', 'standalone server', 'member server', 'backup domain controller', 'primary domain controller')
        if ($cs) { "domain-role: $($roles[[int]$cs.DomainRole])"; "part-of-domain: $($cs.PartOfDomain)"; "hardware: $($cs.Manufacturer) $($cs.Model)" }
    }
    'ssh.algorithms' = {
        $ssh = Join-Path $Sys32 'OpenSSH\ssh.exe'
        if (Test-Path -LiteralPath $ssh) { foreach ($q in 'kex', 'cipher', 'mac', 'key', 'sig') { "${q}: " + (@(& $ssh -Q $q 2>$null) -join ' ') }; 'version: ' + (Get-Item -LiteralPath $ssh).VersionInfo.FileVersion + ' (file version of ssh.exe)' }
    }
    'windows.features' = { Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq 'Enabled' } | ForEach-Object { "$($_.FeatureName): enabled" } }
}

# ---- capabilities ------------------------------------------------------------------------

function Invoke-Registry($Id, $P) {
    $depth = if ($P.depth) { [int]$P.depth } else { 0 }
    $root = Get-Item -Path $P.key
    if (-not $root) { Add-Fact 'skip', $Id, 'not present'; return 0 }
    $keys = @($root)
    if ($depth -gt 0) { $keys += @(Get-ChildItem -Path $P.key -Recurse -Depth ($depth - 1)) }
    $n = 0
    foreach ($k in $keys) {
        if ($P.subkeys -eq 'yes') {
            foreach ($sub in $k.GetSubKeyNames()) { Add-Fact 'fact', $Id, 'registry', $k.Name, '', $sub; $n++ }
        }
        foreach ($name in (Split-List $P.values)) {
            $v = $k.GetValue($name)
            if ($null -eq $v) { continue }
            if ($v -is [array]) { $v = $v -join ',' }
            Add-Fact 'fact', $Id, 'registry', $k.Name, $name, "$v"
            $n++
        }
    }
    return $n
}

function Invoke-CertStore($Id, $P) {
    $n = 0
    foreach ($location in (Split-List $P.locations)) {
        foreach ($store in (Split-List $P.stores)) {
            foreach ($cert in Get-ChildItem -Path "Cert:\$location\$store") {
                if ($cert -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) { continue }
                $hasKey = if ($cert.HasPrivateKey) { 'yes' } else { 'no' }
                Add-Fact 'fact', $Id, 'certstore', $location, $store, $hasKey, ([Convert]::ToBase64String($cert.RawData))
                $n++
            }
        }
    }
    return $n
}

function Invoke-File($Id, $P) {
    $depth = if ($P.depth) { [int]$P.depth } else { 4 }
    $max = if ($P.max) { [int]$P.max } else { 500 }
    $names = Split-List $P.names
    $n = 0
    foreach ($root in (Split-List $P.roots)) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($f in Get-ChildItem -LiteralPath $root -Recurse -Depth $depth -File) {
            $match = $false
            foreach ($nm in $names) { if ($f.Name -like $nm) { $match = $true; break } }
            if (-not $match) { continue }
            if ($n -ge $max) { Add-Fact 'skip', $Id, "stopped at $max files"; return $n }
            if (Test-KeyFile $f.FullName) { continue }
            $sha = ''
            if ($f.Length -le 64MB) { $sha = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLower() }
            $vi = $f.VersionInfo
            Add-Fact 'fact', $Id, 'file', $f.FullName, $f.Length, $sha, $vi.FileVersion, $vi.ProductName
            $n++
        }
    }
    return $n
}

function Invoke-Program($Id, $P) {
    $n = 0
    $roots = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    foreach ($r in $roots) {
        foreach ($k in Get-ChildItem -Path $r) {
            $name = $k.GetValue('DisplayName')
            if (-not $name -or $name -notmatch $P.match) { continue }
            Add-Fact 'fact', $Id, 'program', $name, $k.GetValue('DisplayVersion'), $k.GetValue('Publisher')
            $n++
        }
    }
    return $n
}

# Read-Joined returns a file's lines, joining continuation lines (a trailing backslash) when asked.
function Read-Joined([string]$Path, [bool]$Join) {
    $raw = @(Get-Content -LiteralPath $Path -TotalCount 5000)
    if (-not $Join) { return $raw }
    $out = New-Object System.Collections.Generic.List[string]
    $buf = ''
    foreach ($l in $raw) {
        if ($l -match '\\\s*$') { $buf += ($l -replace '\\\s*$', ''); continue }
        $out.Add($buf + $l); $buf = ''
    }
    if ($buf -ne '') { $out.Add($buf) }
    return $out
}

function Invoke-Lines($Id, $P) {
    $max = if ($P.max) { [int]$P.max } else { 50 }
    $n = 0
    foreach ($pattern in (Split-List $P.paths)) {
        foreach ($f in Get-ChildItem -Path $pattern -File) {
            if (Test-KeyFile $f.FullName) { continue }
            foreach ($line in (Read-Joined $f.FullName ($P.join -eq 'backslash'))) {
                if ($line -notmatch $P.match) { continue }
                if (Test-KeyLine $line) { continue }
                if ($n -ge $max) { return $n }
                $text = if ($line.Length -gt 1000) { $line.Substring(0, 1000) } else { $line }
                Add-Fact 'fact', $Id, 'line', $f.FullName, $text
                $n++
            }
        }
    }
    return $n
}

function Invoke-Query($Id, $P) {
    $max = if ($P.max) { [int]$P.max } else { 200 }
    if (-not $Queries.ContainsKey($P.query)) { Add-Fact 'skip', $Id, "query $($P.query) is not in this engine"; return 0 }
    $n = 0
    $out = @()
    try { $out = @(& $Queries[$P.query]) } catch { Add-Fact 'skip', $Id, "query failed: $($_.Exception.Message)"; return 0 }
    foreach ($o in $out) {
        $line = "$o"
        if ($line.Trim() -eq '') { continue }
        if ($P.match -and $line -notmatch $P.match) { continue }
        if (Test-KeyLine $line) { continue }
        if ($n -ge $max) { break }
        $text = if ($line.Length -gt 1000) { $line.Substring(0, 1000) } else { $line }
        Add-Fact 'fact', $Id, 'query', $P.query, $text
        $n++
    }
    return $n
}

$procInfo = @{}
function Get-ProcInfo([int]$ProcId) {
    if ($procInfo.ContainsKey($ProcId)) { return $procInfo[$ProcId] }
    $info = @{ name = ''; path = ''; libs = '' }
    $p = Get-Process -Id $ProcId
    if ($p) {
        $info.name = $p.ProcessName
        $info.path = "$($p.Path)"
        # Module names only (never their content); another user's process may refuse, and that is fine.
        try { $info.libs = (@($p.Modules | ForEach-Object { $_.ModuleName } | Where-Object { $_ -match $CryptoDll } | Sort-Object -Unique) -join ',') } catch { }
    }
    $procInfo[$ProcId] = $info
    return $info
}

function Invoke-Listeners($Id, $P) {
    $max = if ($P.max) { [int]$P.max } else { 500 }
    $n = 0
    $seen = @{}
    foreach ($c in @(Get-NetTCPConnection -State Listen)) {
        $key = "tcp $($c.LocalAddress) $($c.LocalPort) $($c.OwningProcess)"
        if ($seen.ContainsKey($key)) { continue }; $seen[$key] = $true
        if ($n -ge $max) { break }
        $i = Get-ProcInfo $c.OwningProcess
        Add-Fact 'fact', $Id, 'listener', 'tcp', $c.LocalAddress, $c.LocalPort, $c.OwningProcess, $i.name, $i.path, $i.libs
        $n++
    }
    foreach ($u in @(Get-NetUDPEndpoint)) {
        $key = "udp $($u.LocalAddress) $($u.LocalPort) $($u.OwningProcess)"
        if ($seen.ContainsKey($key)) { continue }; $seen[$key] = $true
        if ($n -ge $max) { break }
        $i = Get-ProcInfo $u.OwningProcess
        Add-Fact 'fact', $Id, 'listener', 'udp', $u.LocalAddress, $u.LocalPort, $u.OwningProcess, $i.name, $i.path, $i.libs
        $n++
    }
    return $n
}

# ---- run ---------------------------------------------------------------------------------

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$os = Get-CimInstance -ClassName Win32_OperatingSystem

Add-Fact 'cipherhorizon-machine-facts', '3'
Add-Fact 'script', 'windows-powershell', $EngineVersion
Add-Fact 'host', 'name', $env:COMPUTERNAME
Add-Fact 'host', 'os', 'windows'
if ($os) { Add-Fact 'host', 'os-version', "$($os.Caption) $($os.Version)" }
Add-Fact 'host', 'privilege', $(if ($isAdmin) { 'admin' } else { 'user' })
Add-Fact 'host', 'collected', (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

$sigText = if ($SignatureFile) { Get-Content -Raw -LiteralPath $SignatureFile } else { $Signatures }
$total = 0
foreach ($sigLine in ($sigText -split "`r?`n")) {
    $f = $sigLine -split "`t"
    if ($f[0] -eq 'signatures') { Add-Fact 'signatures', $f[1]; continue }
    if ($f[0] -ne 'sig' -or $f.Count -lt 3) { continue }
    $id = $f[1]; $capability = $f[2]
    $params = @{}
    if ($f.Count -gt 3) {
        foreach ($kv in $f[3..($f.Count - 1)]) { $i = $kv.IndexOf('='); if ($i -gt 0) { $params[$kv.Substring(0, $i)] = $kv.Substring($i + 1) } }
    }
    $count = switch ($capability) {
        'registry'  { Invoke-Registry $id $params }
        'certstore' { Invoke-CertStore $id $params }
        'file'      { Invoke-File $id $params }
        'program'   { Invoke-Program $id $params }
        'lines'     { Invoke-Lines $id $params }
        'query'     { Invoke-Query $id $params }
        'listeners' { Invoke-Listeners $id $params }
        default     { Add-Fact 'skip', $id, "capability $capability is not in this engine"; 0 }
    }
    Add-Fact 'ran', $id, ([int]$count)
    $total += [int]$count
}
if (-not $isAdmin) { Add-Fact 'note', 'Ran without Administrator rights: the machine''s personal store, TPM, BitLocker, SMB server and WinRM settings, and other users'' processes may be missing or incomplete.' }

# UTF-8 without a byte-order mark, one fact per line.
[System.IO.File]::WriteAllLines($OutFile, $lines, (New-Object System.Text.UTF8Encoding $false))
# The facts file lists certificates, programs and settings: readable by this account,
# Administrators and SYSTEM only, not by every user of the machine.
try {
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    foreach ($sid in @($me, (New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'), (New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'))) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')))
    }
    Set-Acl -LiteralPath $OutFile -AclObject $acl -ErrorAction Stop
} catch {
    Write-Warning "could not limit who can read $OutFile ($($_.Exception.Message)); it has the folder's permissions"
}
Write-Host "wrote $OutFile ($($lines.Count) lines, $total facts)"
Write-Host 'next: read it if you like (it is plain text), then upload it on the Inventory page of CipherHorizon.'
