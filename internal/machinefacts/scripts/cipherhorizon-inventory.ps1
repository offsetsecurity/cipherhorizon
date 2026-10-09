<#
CipherHorizon machine inventory engine for Windows, version 2.0.1

What it does: runs each signature listed below with one of a few read-only capabilities,
and writes what it finds to a plain-text facts file you can read before you upload it.

  registry   reads named values of a registry key (and of its sub-keys to a set depth)
  certstore  lists the certificates in the named stores, with whether a private key is associated
  file       finds files by name under folders: path, size, version and SHA-256 (not their content)
  program    lists installed programs whose name matches
  lines      reads text files and keeps only the lines that match

What it never does: change anything, install anything, start another program, make a
network connection, open a file named like a key, or read a private key.

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
$EngineVersion = '2.0.1'
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
function Split-List([string]$Value) { return @($Value -split '\|' | Where-Object { $_ -ne '' } | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) }) }

# ---- capabilities ------------------------------------------------------------------------

function Invoke-Registry($Id, $P) {
    $depth = if ($P.depth) { [int]$P.depth } else { 0 }
    $root = Get-Item -Path $P.key
    if (-not $root) { Add-Fact 'skip', $Id, 'not present'; return 0 }
    $keys = @($root)
    if ($depth -gt 0) { $keys += @(Get-ChildItem -Path $P.key -Recurse -Depth ($depth - 1)) }
    $n = 0
    foreach ($k in $keys) {
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

function Invoke-Lines($Id, $P) {
    $max = if ($P.max) { [int]$P.max } else { 50 }
    $n = 0
    foreach ($pattern in (Split-List $P.paths)) {
        foreach ($f in Get-ChildItem -Path $pattern -File) {
            if (Test-KeyFile $f.FullName) { continue }
            foreach ($line in Get-Content -LiteralPath $f.FullName -TotalCount 5000) {
                if ($line -notmatch $P.match) { continue }
                if ($line -match 'PRIVATE KEY') { continue }
                if ($n -ge $max) { return $n }
                $text = if ($line.Length -gt 1000) { $line.Substring(0, 1000) } else { $line }
                Add-Fact 'fact', $Id, 'line', $f.FullName, $text
                $n++
            }
        }
    }
    return $n
}

# ---- run ---------------------------------------------------------------------------------

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$os = Get-CimInstance -ClassName Win32_OperatingSystem

Add-Fact 'cipherhorizon-machine-facts', '2'
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
        default     { Add-Fact 'skip', $id, "capability $capability is not in this engine"; 0 }
    }
    Add-Fact 'ran', $id, ([int]$count)
    $total += [int]$count
}
if (-not $isAdmin) { Add-Fact 'note', 'Ran without Administrator rights: stores and folders only an administrator can read may be incomplete.' }

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
