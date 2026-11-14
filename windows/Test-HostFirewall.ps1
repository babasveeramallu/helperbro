#requires -Version 5.1
# All firewall, listener and backup commands are mocked.
$ErrorActionPreference = 'Stop'
& {
    . (Join-Path $PSScriptRoot 'lib\HostFirewall.ps1')
    $fixture = Join-Path ([IO.Path]::GetTempPath()) ('ccdc-host-firewall-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $fixture | Out-Null
    $ReportDirectory = $fixture
    function Write-Log { param($Level,$Message) $script:HostMessages.Add("$Level $Message") }
    function Get-NetFirewallProfile { param($PolicyStore,$ErrorAction) [pscustomobject]@{DefaultInboundAction='Block'} }
    function Get-NetTCPConnection {
        param($State,$ErrorAction)
        foreach ($port in @(3389,5985,445,8080)) { [pscustomobject]@{LocalPort=$port;OwningProcess=1} }
    }
    function Get-NetUDPEndpoint { param($ErrorAction) }
    function Get-CimInstance { param($ClassName,$Filter,$ErrorAction) [pscustomobject]@{ProcessId=1;Name='FixtureService'} }
    function Get-NetFirewallRule {
        param($PolicyStore,$Direction,$Enabled,$Action,$DisplayName,$ErrorAction)
        foreach ($rule in @($script:HostRules.Values)) {
            if ($DisplayName -and $rule.DisplayName -ne $DisplayName) { continue }
            if ($Enabled -and -not $rule.Enabled) { continue }
            $rule
        }
    }
    function Export-Clixml { param([Parameter(ValueFromPipeline)]$InputObject,$LiteralPath) process {} }
    function netsh.exe {
        param($Context,$Verb,$File)
        if ($Verb -ne 'export') { throw 'Unexpected rollback in test' }
        Set-Content -LiteralPath $File -Value 'synthetic snapshot'
        $global:LASTEXITCODE=0
    }
    function Disable-NetFirewallRule {
        param([Parameter(ValueFromPipeline)]$InputObject)
        process { $InputObject.Enabled=$false; $script:HostDisabled.Add($InputObject.Name) }
    }
    function Set-NetFirewallProfile { param($Name,$DefaultInboundAction,$Enabled,$ErrorAction) }
    function New-NetFirewallRule {
        param($PolicyStore,$DisplayName,$Direction,$Action,$Enabled,$Protocol,$LocalPort,$RemoteAddress,$Profile)
        $rule=[pscustomobject]@{Name=$DisplayName;DisplayName=$DisplayName;Enabled=$true;RemoteAddress=@($RemoteAddress);PolicyStoreSourceType='Local'}
        $script:HostRules[$DisplayName]=$rule
        $rule
    }
    function Set-NetFirewallRule { param($InputObject,$Enabled,$Action,$Profile) $InputObject.Enabled=$true }
    function Get-NetFirewallPortFilter { param($AssociatedNetFirewallRule) $AssociatedNetFirewallRule }
    function Set-NetFirewallPortFilter { param($InputObject,$Protocol,$LocalPort) }
    function Get-NetFirewallAddressFilter { param($AssociatedNetFirewallRule,$ErrorAction) $AssociatedNetFirewallRule }
    function Set-NetFirewallAddressFilter { param($InputObject,$RemoteAddress) $InputObject.RemoteAddress=@($RemoteAddress) }
    try {
        foreach ($case in @('default','range-only','management','system','disable','whatif','missing-range')) {
            $script:HostRules=@{}
            foreach ($pair in @(@('Site-Service','Any'),@('CCDC-Host-RDP-3389','10.1.0.0/16'))) {
                $script:HostRules[$pair[0]]=[pscustomobject]@{Name=$pair[0];DisplayName=$pair[0];Enabled=$true;RemoteAddress=@($pair[1]);PolicyStoreSourceType='Local'}
            }
            $script:HostMessages=[System.Collections.Generic.List[string]]::new()
            $script:HostDisabled=[System.Collections.Generic.List[string]]::new()
            $args=@{Confirm=$false}
            if ($case -eq 'range-only') { $args.ManagementRange=@('10.2.0.0/16') }
            if ($case -eq 'management') { $args.ScopeManagementPorts=$true; $args.ManagementRange=@('10.2.0.0/16') }
            if ($case -eq 'system') { $args.ScopeSystemPorts=$true; $args.ManagementRange=@('10.2.0.0/16') }
            if ($case -eq 'disable') { $args.DisableExistingInboundAllows=$true }
            if ($case -eq 'whatif') { $args.WhatIf=$true; $args.DisableExistingInboundAllows=$true }
            if ($case -eq 'missing-range') { $args.ScopeManagementPorts=$true }
            $failed=$false
            try { Set-CCDCWindowsFirewall @args }
            catch { if ($case -ne 'missing-range') { throw }; $failed=$_.Exception.Message -like '*requires -ManagementRange*' }
            if ($case -eq 'missing-range') {
                if (-not $failed -or $script:HostDisabled.Count) { throw 'Missing range did not fail before writes.' }
            } elseif ($case -eq 'whatif') {
                if ($script:HostDisabled.Count -or $script:HostRules.Count -ne 2) { throw 'WhatIf mutated policy.' }
            } else {
                $rdp=$script:HostRules['CCDC-Host-RDP-3389']
                $winrm=$script:HostRules['CCDC-Host-WinRM-5985']
                $smb=$script:HostRules['CCDC-Detected-TCP-445']
                if (-not @($script:HostMessages | Where-Object { $_ -like '*Existing inbound allow name=Site-Service*' }).Count) { throw 'Existing rules were not reported.' }
                if ($case -ne 'disable' -and ($script:HostDisabled.Count -or -not $script:HostRules['Site-Service'].Enabled)) { throw 'Existing site rule was disabled without opt-in.' }
                $expectedRdp = if ($case -eq 'management') {'10.2.0.0/16'} elseif ($case -eq 'disable') {'Any'} else {'10.1.0.0/16'}
                if ("$($rdp.RemoteAddress)" -ne $expectedRdp) { throw "Unexpected RDP scope in $case" }
                $expectedWinrm = if ($case -eq 'management') {'10.2.0.0/16'} else {'Any'}
                if ("$($winrm.RemoteAddress)" -ne $expectedWinrm) { throw "Unexpected WinRM scope in $case" }
                $expectedSmb = if ($case -eq 'system') {'10.2.0.0/16'} else {'Any'}
                if ("$($smb.RemoteAddress)" -ne $expectedSmb) { throw "Unexpected SMB scope in $case" }
                if ($case -eq 'disable' -and ($script:HostDisabled.Count -ne 2 -or -not @($script:HostMessages | Where-Object { $_ -match 'disabled-rule summary \(2\).*Site-Service' }).Count)) { throw 'Explicit disable was not applied and summarized.' }
                if ($case -in @('management','system') -and -not @($script:HostMessages | Where-Object { $_ -like '*scoped-rule summary*remote=10.2.0.0/16*' }).Count) { throw "Scoped rules were not summarized: $($script:HostMessages -join '; ')" }
            }
            Write-Host "PASS host firewall $case"
        }
    } finally {
        Remove-Variable HostRules,HostMessages,HostDisabled -Scope Script -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}
