#requires -Version 5.1
# AD, net.exe and secedit.exe operations are mocked; no real policy changes.
$ErrorActionPreference = 'Stop'
& {
    . (Join-Path $PSScriptRoot 'lib\AccountPolicy.ps1')
    $fixture = Join-Path ([IO.Path]::GetTempPath()) ('ccdc-policy-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $fixture | Out-Null
    function Write-Log { param($Level,$Message) }
    function Get-Module { param([switch]$ListAvailable,$Name) [pscustomobject]@{Name='ActiveDirectory'} }
    function Import-Module { param($Name,$ErrorAction) }
    function Get-ADDomain { param($ErrorAction) [pscustomobject]@{DNSRoot='example.test'} }
    function Get-ADDefaultDomainPasswordPolicy {
        param($Identity,$ErrorAction)
        [pscustomobject]$script:PolicyState.AD.Clone()
    }
    function Set-ADDefaultDomainPasswordPolicy {
        param($Identity,$MinPasswordLength,$ComplexityEnabled,$PasswordHistoryCount,$MaxPasswordAge,
            $LockoutThreshold,$LockoutDuration,$LockoutObservationWindow,$ErrorAction)
        foreach ($name in @('MinPasswordLength','ComplexityEnabled','PasswordHistoryCount','MaxPasswordAge','LockoutThreshold','LockoutDuration','LockoutObservationWindow')) {
            if ($PSBoundParameters.ContainsKey($name)) {
                $script:PolicyState.AD[$name]=$PSBoundParameters[$name]
                $script:PolicyState.ADKeys.Add($name)
            }
        }
    }
    function Get-Command {
        param($Name,$ErrorAction)
        if ($Name -eq 'net.exe') { [pscustomobject]@{Source='Invoke-FixtureNet'} }
        elseif ($Name -eq 'secedit.exe') { [pscustomobject]@{Source='Invoke-FixtureSecedit'} }
        else { throw "Unexpected command discovery: $Name" }
    }
    function Invoke-FixtureNet {
        $script:PolicyState.NetCalls.Add(($args -join ' '))
        $global:LASTEXITCODE=0
        if ($args.Count -eq 1) {
            "Minimum password length: 8`nMaximum password age (days): 60`nLength of password history maintained: 5"
        }
    }
    function Invoke-FixtureSecedit {
        $global:LASTEXITCODE=0
        $cfg=$args[[array]::IndexOf($args, '/cfg')+1]
        if ($args[0] -eq '/export') {
            $lines=@('[System Access]')
            foreach ($key in $script:PolicyState.Local.Keys) { $lines += "$key = $($script:PolicyState.Local[$key])" }
            $lines += '[Version]', 'signature="$CHICAGO$"', 'Revision=1'
            Set-Content -LiteralPath $cfg -Value $lines -Encoding Unicode -WhatIf:$false
        } elseif ($args[0] -eq '/configure') {
            $text=Get-Content -LiteralPath $cfg -Raw
            foreach ($match in [regex]::Matches($text, '(?m)^(\w+)\s*=\s*(-?\d+)\s*$')) {
                $script:PolicyState.Local[$match.Groups[1].Value]=[int]$match.Groups[2].Value
            }
            $script:PolicyState.Configures++
        } else { throw 'Unexpected secedit operation' }
    }
    try {
        foreach ($domain in @($false,$true)) {
            foreach ($case in @('default','disabled-existing','enabled','whatif','invalid-window','missing-switch')) {
                $script:PolicyState=@{
                    AD=@{MinPasswordLength=3;ComplexityEnabled=$false;PasswordHistoryCount=1;MaxPasswordAge=(New-TimeSpan -Days 90)
                        LockoutThreshold=17;LockoutDuration=(New-TimeSpan -Minutes 42);LockoutObservationWindow=(New-TimeSpan -Minutes 12)}
                    Local=@{MinimumPasswordLength=3;PasswordComplexity=0;PasswordHistorySize=1;MaximumPasswordAge=90
                        LockoutBadCount=17;LockoutDuration=42;ResetLockoutCount=12}
                    ADKeys=[System.Collections.Generic.List[string]]::new()
                    NetCalls=[System.Collections.Generic.List[string]]::new();Configures=0
                }
                if ($case -eq 'disabled-existing') {
                    $script:PolicyState.AD.LockoutThreshold=0
                    $script:PolicyState.Local.LockoutBadCount=0
                }
                $parameters=@{IsDomainJoined=$domain;ReportDirectory=$fixture;Confirm=$false}
                if ($case -in @('enabled','whatif','invalid-window')) {
                    $parameters.EnableAccountLockout=$true
                    $parameters.LockoutThreshold=11
                    $parameters.LockoutDurationMinutes=25
                    $parameters.LockoutObservationWindowMinutes=9
                }
                if ($case -eq 'whatif') { $parameters.WhatIf=$true }
                if ($case -eq 'invalid-window') { $parameters.LockoutObservationWindowMinutes=26 }
                if ($case -eq 'missing-switch') { $parameters.LockoutThreshold=11 }
                $failed=$false
                try { Set-CCDCAccountPolicy @parameters }
                catch {
                    if ($case -eq 'invalid-window') { $failed=$_.Exception.Message -like '*cannot exceed*' }
                    elseif ($case -eq 'missing-switch') { $failed=$_.Exception.Message -like '*require -EnableAccountLockout*' }
                    else { throw }
                }
                if ($case -in @('invalid-window','missing-switch') -and -not $failed) { throw 'Expected parameter validation failure.' }
                $applied = $case -in @('default','disabled-existing','enabled')
                $threshold=if ($case -eq 'enabled') {11} elseif ($case -eq 'disabled-existing') {0} else {17}
                $duration=if ($case -eq 'enabled') {25} else {42}
                $window=if ($case -eq 'enabled') {9} else {12}
                if ($domain) {
                    $state=$script:PolicyState.AD
                    if ($state.LockoutThreshold -ne $threshold -or $state.LockoutDuration.TotalMinutes -ne $duration -or $state.LockoutObservationWindow.TotalMinutes -ne $window) { throw "Wrong AD lockout values for $case" }
                    if ($case -in @('default','disabled-existing') -and @($script:PolicyState.ADKeys | Where-Object { $_ -like 'Lockout*' }).Count) { throw 'Default sent AD lockout parameters.' }
                    if ($applied -and ($state.MinPasswordLength -ne 8 -or -not $state.ComplexityEnabled -or $state.PasswordHistoryCount -ne 5 -or $state.MaxPasswordAge.TotalDays -ne 60)) { throw 'Password settings not preserved in AD path.' }
                    if (-not $applied -and $script:PolicyState.ADKeys.Count) { throw 'Unexpected AD write.' }
                } else {
                    $state=$script:PolicyState.Local
                    if ($state.LockoutBadCount -ne $threshold -or $state.LockoutDuration -ne $duration -or $state.ResetLockoutCount -ne $window) { throw "Wrong local lockout values for $case" }
                    if ($case -in @('default','disabled-existing') -and @($script:PolicyState.NetCalls | Where-Object { $_ -match '/lockout' }).Count) { throw 'Default sent net lockout arguments.' }
                    if ($case -eq 'enabled' -and -not @($script:PolicyState.NetCalls | Where-Object { $_ -match '/lockoutthreshold:11 /lockoutduration:25 /lockoutwindow:9' }).Count) { throw 'Parameterized net lockout arguments missing.' }
                    if ($applied -and ($state.MinimumPasswordLength -ne 8 -or $state.PasswordComplexity -ne 1 -or $state.PasswordHistorySize -ne 5 -or $state.MaximumPasswordAge -ne 60)) { throw 'Password settings not preserved in local path.' }
                    if (-not $applied -and ($script:PolicyState.Configures -or $script:PolicyState.NetCalls.Count)) { throw 'Unexpected local policy write.' }
                }
                Write-Host "PASS account policy domain=$domain $case"
            }
        }
    } finally {
        Remove-Variable PolicyState -Scope Script -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}
