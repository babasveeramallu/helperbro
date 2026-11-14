#requires -Version 5.1
# Uses synthetic credentials and temporary files; no accounts are changed.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\CredentialProtection.ps1')
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('ccdc-credentials-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
try {
    $password = 'Synthetic-Test-Password-42!'
    $secure = ConvertTo-SecureString $password -AsPlainText -Force
    $protected = Protect-CCDCCredential $secure
    if (-not $protected.StartsWith('dpapi:') -or $protected.Contains($password)) { throw 'Credential was not protected.' }
    if ([Net.NetworkCredential]::new('', (Unprotect-CCDCCredential $protected)).Password -cne $password) { throw 'DPAPI round trip failed.' }
    Write-Host 'PASS current-user DPAPI round trip'

    $viewer = Join-Path $PSScriptRoot 'Show-RotatedCredentials.ps1'
    $shell = (Get-Process -Id $PID).Path
    $path = Join-Path $fixture 'credentials.txt'
    Set-Content -LiteralPath $path -Value "test-user`t$protected`tPENDING", "test-user`tCHANGED" -Encoding UTF8
    $output = 'KEEP' | & $shell -NoProfile -File $viewer -Path $path 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $path) -or $output -notmatch [regex]::Escape($password) -or $output -notmatch 'CHANGED') {
        throw "Viewer did not show and retain the protected record: $output"
    }
    $output = 'DELETE' | & $shell -NoProfile -File $viewer -Path $path 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or (Test-Path -LiteralPath $path) -or $output -notmatch 'Credential file deleted') {
        throw "Viewer did not delete the file after confirmation: $output"
    }
    Write-Host 'PASS display, retain, and confirmed deletion'

    foreach ($invalid in @('obf:ZmFrZQ==', 'dpapi:not-valid')) {
        Set-Content -LiteralPath $path -Value "test-user`t$invalid`tPENDING" -Encoding UTF8
        $ErrorActionPreference = 'Continue'
        try {
            $output = 'DELETE' | & $shell -NoProfile -File $viewer -Path $path 2>&1 | Out-String
            $code = $LASTEXITCODE
        } finally { $ErrorActionPreference = 'Stop' }
        if ($code -eq 0 -or -not (Test-Path -LiteralPath $path)) {
            throw 'Invalid or legacy credential was accepted or deleted.'
        }
    }
    Write-Host 'PASS legacy and corrupt records fail without deletion'

    $scriptDir = Join-Path $fixture 'scripts'
    $libDir = Join-Path $scriptDir 'lib'
    New-Item -ItemType Directory -Path $libDir -Force | Out-Null
    Copy-Item (Join-Path $PSScriptRoot 'lib\*.ps1') $libDir
    $entry = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'first-hour.ps1') -Raw
    $adminCheck = "if (-not `$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
    if (-not $entry.Contains($adminCheck)) { throw 'Fixture cannot locate the elevation check.' }
    $entry = $entry.Replace($adminCheck, 'if ($false)')
    Set-Content -LiteralPath (Join-Path $scriptDir 'first-hour.ps1') -Value $entry -Encoding UTF8
    Add-Content -LiteralPath (Join-Path $libDir 'UsbStorage.ps1') -Value @'

function New-ProtectedDirectory { param($Path) New-Item -ItemType Directory -Path $Path -Force | Out-Null }
function Write-Log { param($Level, $Message) Write-Host "$Level $Message" }
function Get-CCDCBaseline { param($IsDomainJoined, $Path) }
function Save-CCDCSysinternalsSnapshot { param($Dir, $Tag, $OutDir) }
function Get-ItemProperty { param($LiteralPath) [pscustomobject]@{ InstallationType='Client'; EditionID='Pro'; ProductName='Fixture' } }
function Get-ChildItem { param($LiteralPath, $ErrorAction) }
function Get-CimInstance {
    param($ClassName, $Namespace, $Filter)
    if ($ClassName -eq 'Win32_OperatingSystem') { [pscustomobject]@{ ProductType=1; Caption='Fixture' } }
    elseif ($ClassName -eq 'Win32_ComputerSystem') { [pscustomobject]@{ PartOfDomain=$false; Workgroup='Fixture' } }
}
function Get-LocalUser {
    $sid = if ($env:CCDC_FIXTURE_SCENARIO -eq 'current-user') {
        [Security.Principal.WindowsIdentity]::GetCurrent().User
    } else { [Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-1001') }
    [pscustomobject]@{ Name='fixture-user'; SID=$sid; Enabled=$true }
}
function Get-ScheduledTask {}
function Read-Host { param($Prompt) 'ROTATE 1 LOCAL PASSWORDS' }
function New-RandomPassword { 'Synthetic-Test-Password-42!' }
function icacls.exe { $global:LASTEXITCODE = 0 }
function Set-LocalUser {
    param($Name, $Password)
    Set-Content -LiteralPath (Join-Path $env:CCDC_FIXTURE_REPORT 'changed.txt') -Value 'changed'
    $file = [IO.Directory]::GetFiles($env:CCDC_FIXTURE_REPORT, 'rotated-credentials-*.txt')[0]
    $record = @(Get-Content -LiteralPath $file)[0] -split "`t"
    $saved = Unprotect-CCDCCredential $record[1]
    if ($record[2] -ne 'PENDING' -or
        [Net.NetworkCredential]::new('', $saved).Password -cne [Net.NetworkCredential]::new('', $Password).Password) {
        throw 'A readable recovery record must exist before the password change.'
    }
}
if ($env:CCDC_FIXTURE_SCENARIO -eq 'decrypt-failure') {
    function Unprotect-CCDCCredential { param($Text) throw 'Simulated DPAPI failure' }
}
'@
    Set-Content -LiteralPath (Join-Path $scriptDir 'invoke.ps1') -Value @'
& (Join-Path $PSScriptRoot 'first-hour.ps1') -RotatePasswords -IncludeAccount fixture-user -ExcludeAccount @('scoring','breakglass') -SkipRestorePoint -ReportDirectory $env:CCDC_FIXTURE_REPORT -Confirm:$false
exit $LASTEXITCODE
'@ -Encoding UTF8
    foreach ($case in @(
        @{ Name='success'; Code=0; Changed=$true }
        @{ Name='decrypt-failure'; Code=1; Changed=$false }
        @{ Name='current-user'; Code=1; Changed=$false }
    )) {
        $report = Join-Path $fixture $case.Name
        $env:CCDC_FIXTURE_SCENARIO = $case.Name
        $env:CCDC_FIXTURE_REPORT = $report
        $ErrorActionPreference = 'Continue'
        try {
            $output = & $shell -NoProfile -File (Join-Path $scriptDir 'invoke.ps1') 2>&1 | Out-String
            $code = $LASTEXITCODE
        } finally { $ErrorActionPreference = 'Stop' }
        $changed = Test-Path -LiteralPath (Join-Path $report 'changed.txt')
        if ($code -ne $case.Code -or $changed -ne $case.Changed) { throw "Rotation fixture $($case.Name) failed: $output" }
        if ($case.Name -eq 'success') {
            $recordFile = @(Get-ChildItem -LiteralPath $report -Filter 'rotated-credentials-*.txt')[0]
            $contents = Get-Content -LiteralPath $recordFile.FullName -Raw
            if ($contents -notmatch 'dpapi:' -or $contents.Contains($password) -or $contents -notmatch 'CHANGED') { throw 'Invalid rotation output.' }
        }
        if ($case.Name -eq 'current-user' -and (Test-Path -LiteralPath (Join-Path $report 'password-rotation-ledger.txt'))) {
            throw 'Current-user guard ran after creating the ledger.'
        }
        Write-Host "PASS rotation fixture $($case.Name)"
    }
} finally {
    Remove-Item Env:\CCDC_FIXTURE_SCENARIO, Env:\CCDC_FIXTURE_REPORT -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
