#requires -Version 5.1
# Runs the actual entry point against isolated stand-ins; no DNS or system changes.
$ErrorActionPreference = 'Stop'
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('ccdc-addns-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $fixture 'addns'), (Join-Path $fixture 'lib') -Force | Out-Null
try {
    Copy-Item (Join-Path $PSScriptRoot 'addns\harden-addns.ps1') (Join-Path $fixture 'addns')
    Copy-Item (Join-Path $PSScriptRoot 'lib\Common.ps1'), (Join-Path $PSScriptRoot 'lib\Baseline.ps1'), (Join-Path $PSScriptRoot 'lib\RoleCommon.ps1') (Join-Path $fixture 'lib')
    Add-Content -LiteralPath (Join-Path $fixture 'lib\RoleCommon.ps1') -Value @'

function Initialize-CCDCRole {
    param($Role, $ReportDirectory)
    $script:Report = 'mock'
    $script:Stamp = 'mock'
    $role = if ($global:FixtureScenario -eq 'non-dc') { 3 } else { 5 }
    $script:Computer = [pscustomobject]@{ DomainRole = $role; PartOfDomain = $true }
}
function Write-Log { param($Level, $Message) Write-Host "$Level $Message" }
function Assert-CCDCAdmin {
    if ($global:FixtureScenario -eq 'not-admin') { throw 'Mock elevation required' }
}
function Get-CCDCBaseline { param($IsDomainJoined, $Path) }
function Show-CCDCCommonHostAudit {}
function Complete-CCDCRole {}
function Get-Module { param([switch]$ListAvailable, $Name) }
function Get-Service { param($Name, $ErrorAction) if ($Name -eq 'DNS') { [pscustomobject]@{ Status = 'Running' } } }
function Get-DnsServerZone {
    Add-Content -LiteralPath $global:FixtureCalls -Value 'enumerate' -WhatIf:$false
    [pscustomobject]@{ ZoneName = 'example.test'; ZoneType = 'Primary'; IsAutoCreated = $false
        IsDsIntegrated = $true; DynamicUpdate = 'NonsecureAndSecure'; SecureSecondaries = 'TransferAnyServer' }
}
function Set-DnsServerPrimaryZone {
    param($Name, $DynamicUpdate, $SecureSecondaries, $SecondaryServers)
    Add-Content -LiteralPath $global:FixtureCalls -Value "change:$Name" -WhatIf:$false
}
function Get-DnsServerForwarder { param($ErrorAction) [pscustomobject]@{ IPAddress = @() } }
function Get-DnsServerRecursion { param($ErrorAction) [pscustomobject]@{ Enable = $true } }
function Get-ItemProperty { param($Path, $ErrorAction) [pscustomobject]@{} }
'@
    Set-Content -LiteralPath (Join-Path $fixture 'invoke.ps1') -Value @'
param([string]$Scenario, [string]$Calls)
$global:FixtureScenario = $Scenario
$global:FixtureCalls = $Calls
$env:USERDNSDOMAIN = ''
$arguments = @{ SecureDnsZones = $true; Confirm = $false }
if ($Scenario -notin @('plan', 'audit')) { $arguments.Apply = $true }
if ($Scenario -eq 'audit') { $arguments.Remove('SecureDnsZones') }
if ($Scenario -eq 'whatif') { $arguments.WhatIf = $true }
& (Join-Path $PSScriptRoot 'addns\harden-addns.ps1') @arguments
exit $LASTEXITCODE
'@
    $shell = (Get-Process -Id $PID).Path
    foreach ($case in @(
        @{ Name = 'non-dc'; Code = 1; Enumerated = $false; Changes = 0; Message = 'non-domain-controller' }
        @{ Name = 'not-admin'; Code = 1; Enumerated = $false; Changes = 0; Message = 'Mock elevation required' }
        @{ Name = 'plan'; Code = 0; Enumerated = $true; Changes = 0; Message = 'PLAN ONLY' }
        @{ Name = 'audit'; Code = 0; Enumerated = $true; Changes = 0; Message = 'DNS zone' }
        @{ Name = 'whatif'; Code = 0; Enumerated = $true; Changes = 0; Message = 'What if' }
        @{ Name = 'authorized'; Code = 0; Enumerated = $true; Changes = 2; Message = 'DNS zone' }
    )) {
        $calls = Join-Path $fixture "$($case.Name).txt"
        $output = & $shell -NoProfile -File (Join-Path $fixture 'invoke.ps1') -Scenario $case.Name -Calls $calls 2>&1 | Out-String
        $code = $LASTEXITCODE
        $lines = if (Test-Path -LiteralPath $calls) { @(Get-Content -LiteralPath $calls) } else { @() }
        $enumerated = @($lines | Where-Object { $_ -eq 'enumerate' }).Count -gt 0
        $changes = @($lines | Where-Object { $_ -like 'change:*' }).Count
        if ($code -ne $case.Code -or $enumerated -ne $case.Enumerated -or $changes -ne $case.Changes -or $output -notmatch [regex]::Escape($case.Message)) {
            throw "FAIL $($case.Name): exit=$code enumerated=$enumerated changes=$changes output=$output"
        }
        Write-Host "PASS $($case.Name)"
    }
} finally {
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
