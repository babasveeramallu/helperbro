#Requires -Version 5.1
<#
.SYNOPSIS
Displays DPAPI-protected passwords for the Windows user who created the file.
After display, prompts to delete the file once credentials are safely recorded.
#>
[CmdletBinding()]
param([string]$Path)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\CredentialProtection.ps1')
if (-not $Path) {
    $latest = Get-ChildItem (Join-Path $env:LOCALAPPDATA 'CCDC\Reports') -Filter 'rotated-credentials-*.txt' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $latest) { throw 'No rotated-credentials file found.' }
    $Path = $latest.FullName
}
$entryFailed = $false
$rows = @(foreach ($line in (Get-Content -LiteralPath $Path)) {
    try {
        $p = $line -split "`t"
        if ($p.Count -eq 3) {
            $secret = Unprotect-CCDCCredential $p[1]
            [pscustomobject]@{ Account = $p[0]; Password = ([Net.NetworkCredential]::new('', $secret).Password); Status = $p[2] }
        } elseif ($p.Count -eq 2 -and ($p[1] -eq 'CHANGED' -or $p[1] -like 'FAILED:*')) {
            [pscustomobject]@{ Account = $p[0]; Password = ''; Status = $p[1] }
        } else {
            throw "Unrecognized credential file entry in $Path; file retained."
        }
    } catch {
        $entryFailed = $true
        Write-Warning "A credential file entry could not be read in $Path; file retained."
    }
})
if (-not @($rows | Where-Object { $_.Password }).Count) { throw "No protected credentials found in $Path; file retained." }
$rows | Format-List Account, Password, Status | Out-Host
$rows = $null
if ($entryFailed) { throw "Only readable entries were displayed from $Path; file retained because some entries could not be read." }
if ((Read-Host 'After saving the credentials securely, type DELETE to remove this file (anything else keeps it)') -ceq 'DELETE') {
    Remove-Item -LiteralPath $Path -ErrorAction Stop
    Write-Host "Credential file deleted: $Path"
} else {
    Write-Warning "Credential file retained: $Path"
}
