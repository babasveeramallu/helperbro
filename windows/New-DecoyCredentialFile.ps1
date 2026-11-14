#Requires -Version 5.1
<#
.SYNOPSIS
Creates an explicitly labeled fake credential file for an approved defensive exercise.
.DESCRIPTION
Does not read or change Windows accounts. All generated values are fake.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string[]]$Account = @('example-admin', 'example-service'),
    [string]$OutputDirectory = (Join-Path $env:LOCALAPPDATA 'helperbro\Decoys')
)
$ErrorActionPreference = 'Stop'
if (-not $Account.Count -or @($Account | Where-Object { [string]::IsNullOrWhiteSpace($_) -or $_ -match "[`t`r`n]" }).Count) {
    throw 'Use nonempty fake account labels without tabs or newlines.'
}
if (-not $PSCmdlet.ShouldProcess($OutputDirectory, 'Create labeled fake credentials (no account changes)')) { return }
. (Join-Path $PSScriptRoot 'lib\Common.ps1')
New-ProtectedDirectory -Path $OutputDirectory
$path = Join-Path $OutputDirectory ('decoy-credentials-' + [guid]::NewGuid().ToString('N') + '.txt')
$lines = @('# DECOY ONLY: fake values; these are not Windows account credentials.')
$lines += foreach ($name in $Account) { "$name`tFAKE-$([guid]::NewGuid().ToString('N'))`tDECOY" }
Set-Content -LiteralPath $path -Value $lines -Encoding UTF8
Write-Host "Fake decoy file created: $path. No accounts were changed."
