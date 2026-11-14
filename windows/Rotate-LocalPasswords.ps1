#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Rotates explicitly selected local passwords with a passphrase-encrypted recovery store.
.DESCRIPTION
Saves and verifies the encrypted store before changing accounts. Show decrypts an
existing store without rotating accounts. This script never creates decoy files.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet('Generate', 'Show')][string]$Action = 'Generate',
    [string[]]$Account,
    [ValidateRange(16, 64)][int]$Length = 24,
    [string]$StoreDirectory = (Join-Path $env:LOCALAPPDATA 'helperbro\Credentials'),
    [string]$StorePath
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\Common.ps1')
. (Join-Path $PSScriptRoot 'lib\Standalone.ps1')

if ($Action -eq 'Show') {
    if (-not $StorePath) {
        $latest = Get-ChildItem -LiteralPath $StoreDirectory -File -Filter 'local-passwords-*.dat' |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $latest) { throw "No credential store found in $StoreDirectory" }
        $StorePath = $latest.FullName
    }
    Unprotect-CCDCStore -Passphrase (Read-CCDCPassphrase) -Path $StorePath |
        ConvertFrom-Csv -Delimiter "`t" | Format-List Account, Password, Generated
    return
}

if (-not $Account) { throw 'Specify explicit local -Account names. Exclude scoring, service and break-glass accounts.' }
if ((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).DomainRole -ge 4) {
    throw 'Domain controllers have no local SAM accounts; this tool does not rotate domain passwords.'
}
$users = @(foreach ($name in ($Account | Sort-Object -Unique)) {
    if ([System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($name)) {
        throw "Specify a literal local account name, not a wildcard pattern: $name"
    }
    $user = Get-LocalUser -Name $name -ErrorAction Stop
    if (-not $user) { throw "Unknown local account: $name" }
    $user
})
$selected = @($users | Where-Object { $PSCmdlet.ShouldProcess($_.Name, 'Rotate local password and save encrypted recovery store') })
if (-not $selected.Count) { return }
$passphrase = Read-CCDCPassphrase -Confirm
New-ProtectedDirectory -Path $StoreDirectory
$rows = @("Account`tPassword`tGenerated")
$secrets = @{}
try {
    foreach ($user in $selected) {
        $password = New-CCDCStrongPassword -Length $Length
        $secrets[$user.Name] = $password
        $rows += ("{0}`t{1}`t{2}" -f $user.Name, $password, (Get-Date -Format s))
    }
    $store = Join-Path $StoreDirectory ("local-passwords-{0}-{1}.dat" -f (Get-Date -Format 'yyyyMMdd-HHmmss'), [guid]::NewGuid().ToString('N'))
    Protect-CCDCStore -PlainText ($rows -join "`n") -Passphrase $passphrase -Path $store
    if ($LASTEXITCODE -ne 0) { throw "Could not restrict credential store ACL: $store. No passwords changed." }
    if ((Unprotect-CCDCStore -Passphrase $passphrase -Path $store) -cne ($rows -join "`n")) {
        throw 'Credential store verification failed; no passwords changed.'
    }
    Write-Host "Encrypted credential store saved and verified: $store"
    foreach ($user in $selected) {
        Set-LocalUser -Name $user.Name -Password (ConvertTo-SecureString $secrets[$user.Name] -AsPlainText -Force) -ErrorAction Stop
        Write-Host "Rotated local password for $($user.Name)."
    }
    Write-Host "View with: .\windows\Rotate-LocalPasswords.ps1 -Action Show -StorePath `"$store`""
} finally {
    $secrets.Clear()
    $password = $null
    $rows = $null
    $passphrase = $null
}
