#Requires -Version 5.1
# Synthetic stores and mocked account operations only.
$ErrorActionPreference = 'Stop'
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('helperbro-password-tools-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $fixture 'lib') -Force | Out-Null
try {
    foreach ($name in @('Rotate-LocalPasswords.ps1','New-DecoyCredentialFile.ps1')) {
        $text = Get-Content -LiteralPath (Join-Path $PSScriptRoot $name) -Raw
        $text = $text.Replace('#Requires -RunAsAdministrator', '# Fixture runs with mocked accounts.')
        Set-Content -LiteralPath (Join-Path $fixture $name) -Value $text -Encoding UTF8
    }
    Copy-Item (Join-Path $PSScriptRoot 'lib\Common.ps1'), (Join-Path $PSScriptRoot 'lib\Standalone.ps1') (Join-Path $fixture 'lib')
    Add-Content -LiteralPath (Join-Path $fixture 'lib\Common.ps1') -Value @'

function New-ProtectedDirectory { param($Path) New-Item -ItemType Directory -Path $Path -Force | Out-Null }
function icacls.exe { $global:LASTEXITCODE = 0 }
'@
    Add-Content -LiteralPath (Join-Path $fixture 'lib\Standalone.ps1') -Value @'

function Get-CimInstance { param($ClassName,$ErrorAction) [pscustomobject]@{DomainRole=0} }
function Get-LocalUser { param($Name,$ErrorAction) [pscustomobject]@{Name=$Name} }
function Read-CCDCPassphrase { param([switch]$Confirm) ConvertTo-SecureString 'Synthetic-passphrase-42!' -AsPlainText -Force }
function Set-LocalUser {
    param($Name,$Password,$ErrorAction)
    $files = @(Get-ChildItem -LiteralPath $global:ToolTestStore -Filter 'local-passwords-*.dat')
    if ($files.Count -ne 1) { throw 'Expected recovery store before account change.' }
    $rows = Unprotect-CCDCStore -Passphrase (Read-CCDCPassphrase) -Path $files[0].FullName | ConvertFrom-Csv -Delimiter "`t"
    $saved = @($rows | Where-Object Account -eq $Name)
    $plain = [Net.NetworkCredential]::new('', $Password).Password
    if ($saved.Count -ne 1 -or $saved[0].Password -cne $plain) { throw 'Saved password does not match account change.' }
    $global:ToolTestChanged += $Name
}
'@
    $global:ToolTestStore = Join-Path $fixture 'store'
    $global:ToolTestChanged = @()
    & (Join-Path $fixture 'Rotate-LocalPasswords.ps1') -Account fixture-user -StoreDirectory $global:ToolTestStore -WhatIf
    if ((Test-Path $global:ToolTestStore) -or $global:ToolTestChanged.Count) { throw 'WhatIf wrote a store or changed accounts.' }
    Write-Host 'PASS rotation WhatIf has no writes'
    & (Join-Path $fixture 'Rotate-LocalPasswords.ps1') -Account fixture-user -StoreDirectory $global:ToolTestStore -Confirm:$false
    if ($global:ToolTestChanged.Count -ne 1) { throw 'Expected one mocked rotation.' }
    $show = & (Join-Path $fixture 'Rotate-LocalPasswords.ps1') -Action Show -StoreDirectory $global:ToolTestStore | Out-String
    if ($show -notmatch 'fixture-user' -or $show -notmatch 'Password') { throw 'Show did not render recovery credentials.' }
    Write-Host 'PASS encrypted recovery before mock rotation and Show'
    $store = @(Get-ChildItem $global:ToolTestStore -Filter '*.dat')[0].FullName
    $legacyDir = Join-Path $fixture 'old-store'
    New-Item -ItemType Directory -Path $legacyDir | Out-Null
    $legacy = Join-Path $legacyDir 'legacy.dat'
    Copy-Item -LiteralPath $store -Destination $legacy
    $show = & (Join-Path $fixture 'Rotate-LocalPasswords.ps1') -Action Show -StorePath $legacy | Out-String
    if ($show -notmatch 'fixture-user') { throw 'Explicit legacy store path failed.' }
    Write-Host 'PASS explicit store path'
    Add-Content -LiteralPath (Join-Path $fixture 'lib\Standalone.ps1') -Value @'

function Unprotect-CCDCStore { param($Passphrase,$Path) throw 'Simulated verification failure' }
'@
    $global:ToolTestStore = Join-Path $fixture 'failed-store'
    $global:ToolTestChanged = @()
    $failed = $false
    try { & (Join-Path $fixture 'Rotate-LocalPasswords.ps1') -Account fixture-user -StoreDirectory $global:ToolTestStore -Confirm:$false }
    catch { $failed = $_.Exception.Message -like '*Simulated verification failure*' }
    if (-not $failed -or $global:ToolTestChanged.Count) { throw 'Recovery verification failure did not prevent account changes.' }
    Write-Host 'PASS verification failure prevents rotation'
    Add-Content -LiteralPath (Join-Path $fixture 'lib\Standalone.ps1') -Value @'

function Get-CimInstance { param($ClassName,$ErrorAction) [pscustomobject]@{DomainRole=5} }
'@
    $global:ToolTestStore = Join-Path $fixture 'dc-store'
    $failed = $false
    try { & (Join-Path $fixture 'Rotate-LocalPasswords.ps1') -Account fixture-user -StoreDirectory $global:ToolTestStore -Confirm:$false }
    catch { $failed = $_.Exception.Message -like '*no local SAM accounts*' }
    if (-not $failed -or (Test-Path $global:ToolTestStore) -or $global:ToolTestChanged.Count) { throw 'Domain-controller refusal failed.' }
    Write-Host 'PASS domain-controller refusal'
    $decoys = Join-Path $fixture 'decoys'
    & (Join-Path $fixture 'New-DecoyCredentialFile.ps1') -OutputDirectory $decoys -WhatIf
    if (Test-Path $decoys) { throw 'Decoy WhatIf wrote files.' }
    & (Join-Path $fixture 'New-DecoyCredentialFile.ps1') -OutputDirectory $decoys -Confirm:$false
    $files = @(Get-ChildItem $decoys -Filter 'decoy-credentials-*.txt')
    if ($files.Count -ne 1 -or (Get-Content $files[0].FullName -Raw) -notmatch 'DECOY ONLY' -or $global:ToolTestChanged.Count) { throw 'Decoy output not isolated.' }
    Write-Host 'PASS separate labeled decoy and WhatIf'
} finally {
    Remove-Variable ToolTestStore, ToolTestChanged -Scope Global -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
