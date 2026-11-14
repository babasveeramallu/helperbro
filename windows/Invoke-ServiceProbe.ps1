#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('http','https','dns','tcp','smtp','pop3','imap','ftp')][string]$Protocol,
    [Parameter(Mandatory)][string]$Target,
    [Parameter(Mandatory)][ValidateRange(1,65535)][int]$Port,
    [string]$Expect = '-',
    [string]$Path = '/',
    [ValidateRange(1,30)][int]$Timeout = 5
)
$ErrorActionPreference = 'Stop'
if ($Target -notmatch '^(?:[A-Za-z0-9_][A-Za-z0-9_.:-]*|:[A-Fa-f0-9:.]+)$') { throw 'Invalid target host.' }
if (-not $Expect -or $Expect -match '[\r\n]') { throw 'Invalid expected text.' }
if (-not $Path.StartsWith('/') -or $Path -match '[\s\x00-\x1f]') { throw 'Invalid HTTP path.' }
if ($Protocol -eq 'dns') {
    $parts = $Expect -split '=', 2
    $address = $null
    if ($parts.Count -ne 2 -or $parts[0] -notmatch '^[A-Za-z0-9_][A-Za-z0-9_.-]*$' -or
        -not [Net.IPAddress]::TryParse($parts[1], [ref]$address)) {
        throw 'DNS requires -Expect NAME=ADDRESS.'
    }
}
. (Join-Path $PSScriptRoot '..\vendor\labyrinth\core\probe\Probe.ps1')
$result = Invoke-LabProbe -Proto $Protocol.ToLowerInvariant() -Target $Target -Port $Port -Expect $Expect -Path $Path -Timeout $Timeout
Write-Output $result
if ($result -like 'pass *') { exit 0 }
if ($result -like 'fail *') { exit 1 }
if ($result -like 'unknown *') { exit 2 }
throw 'Probe returned an invalid result.'
