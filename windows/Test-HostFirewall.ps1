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
        foreach ($port in $script:HostListeners) { [pscustomobject]@{LocalPort=$port;OwningProcess=1} }
    }
    function Get-NetUDPEndpoint {
        param($ErrorAction)
        if ($script:HostUdpListener) { [pscustomobject]@{LocalPort=3389;OwningProcess=1} }
    }
    function Get-CimInstance { param($ClassName,$Filter,$ErrorAction) [pscustomobject]@{ProcessId=1;Name='FixtureService'} }
    function Get-NetFirewallRule {
        param($PolicyStore,$Direction,$Enabled,$Action,$DisplayName,$ErrorAction)
        if ($script:HostQueryFailure) { throw 'Simulated policy store access failure' }
        if ($Direction -or $Action -or $Enabled) { throw 'Filtered no-match queries are not supported in this fixture' }
        foreach ($rule in @($script:HostRules.Values)) {
            if ($DisplayName -and $rule.DisplayName -ne $DisplayName) { continue }
            if ($Enabled -and -not $rule.Enabled) { continue }
            $rule
        }
    }
    function Export-Clixml { param([Parameter(ValueFromPipeline)]$InputObject,$LiteralPath) process {} }
    function netsh.exe {
        param($Context,$Verb,$File)
        if ($Verb -eq 'import') { $script:HostImports++; $global:LASTEXITCODE=0; return }
        if ($Verb -ne 'export') { throw 'Unexpected netsh verb in test' }
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
        $rule=[pscustomobject]@{Name=$DisplayName;DisplayName=$DisplayName;Enabled=$true;Direction=$Direction;Action=$Action;Protocol=$Protocol;LocalPort=$LocalPort;RemoteAddress=@($RemoteAddress);PolicyStoreSourceType='Local'}
        $script:HostRules[$DisplayName]=$rule
        $rule
    }
    function Set-NetFirewallRule { param($InputObject,$Enabled,$Action,$Profile) $InputObject.Enabled=$true }
    function Get-NetFirewallPortFilter { param($AssociatedNetFirewallRule,$ErrorAction) $AssociatedNetFirewallRule }
    function Set-NetFirewallPortFilter {
        param($InputObject,$Protocol,$LocalPort)
        $InputObject.Protocol=$Protocol
        $InputObject.LocalPort=$LocalPort
    }
    function Get-NetFirewallAddressFilter { param($AssociatedNetFirewallRule,$ErrorAction) $AssociatedNetFirewallRule }
    function Set-NetFirewallAddressFilter {
        param($InputObject,$RemoteAddress)
        $InputObject.RemoteAddress = @(switch ($script:HostReadback) {
            'mask' { '10.2.0.0/255.255.0.0' }
            'cidr' { '10.2.0.0/16' }
            'ipv6' { '2001:db8:0:1::/64' }
            'host' { '10.2.3.4/32' }
            'wrong' { '10.0.0.0/8' }
            default { $RemoteAddress }
        })
    }
    try {
        foreach ($case in @('default','range-only','management','system','disable','whatif','missing-range',
            'inactive','empty','query-error','mask-readback','mask-input','ipv6-readback','host-readback','wrong-readback','invalid-mask',
            'dual-protocol','dual-disable','dual-scoped','legacy-udp','fresh-dual')) {
            $script:HostListeners=@(3389,5985,445,8080)
            $script:HostUdpListener=$false
            $script:HostQueryFailure=$false
            $script:HostImports=0
            $script:HostReadback=''
            $script:HostRules=@{}
            foreach ($pair in @(@('Site-Service','Any'),@('CCDC-Host-RDP-3389','10.1.0.0/16'))) {
                $script:HostRules[$pair[0]]=[pscustomobject]@{Name=$pair[0];DisplayName=$pair[0];Enabled=$true;Direction='Inbound';Action='Allow';Protocol='6';LocalPort=3389;RemoteAddress=@($pair[1]);PolicyStoreSourceType='Local'}
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
            if ($case -eq 'inactive') {
                $script:HostListeners=@()
                foreach ($name in @('CCDC-Host-WinRM-5985','CCDC-Host-WinRM-5986','CCDC-Host-RDP-TCP-3389','CCDC-Host-RDP-UDP-3389',
                    'CCDC-Detected-TCP-445','CCDC-Detected-UDP-137','CCDC-Detected-TCP-50000','CCDC-Detected-TCP-60000')) {
                    $protocol=if ($name -like '*-UDP-*') { 'UDP' } else { 'TCP' }
                    $script:HostRules[$name]=[pscustomobject]@{Name=$name;DisplayName=$name;Enabled=($name -notlike '*60000');Direction='Inbound';Action='Allow';Protocol=$protocol;LocalPort=[int]($name.Split('-')[-1]);RemoteAddress=@('Any');PolicyStoreSourceType='Local'}
                }
                $args.ScopeManagementPorts=$true; $args.ScopeSystemPorts=$true; $args.ManagementRange=@('10.2.0.0/16')
            }
            if ($case -eq 'empty') { $script:HostRules=@{} }
            if ($case -eq 'query-error') { $script:HostQueryFailure=$true }
            if ($case -in @('dual-protocol','dual-disable','dual-scoped','legacy-udp','fresh-dual')) {
                $script:HostUdpListener=$true
                if ($case -eq 'dual-disable') { $args.DisableExistingInboundAllows=$true }
                if ($case -eq 'dual-scoped') { $args.ScopeManagementPorts=$true; $args.ManagementRange=@('10.2.0.0/16') }
                if ($case -eq 'legacy-udp') { $script:HostRules['CCDC-Host-RDP-3389'].Protocol='17' }
                if ($case -eq 'fresh-dual') { $script:HostRules.Remove('CCDC-Host-RDP-3389') }
            }
            if ($case -in @('mask-readback','mask-input','ipv6-readback','host-readback','wrong-readback','invalid-mask')) {
                $args.ScopeManagementPorts=$true; $args.ManagementRange=@('10.2.0.0/16')
                switch ($case) {
                    'mask-readback' { $script:HostReadback='mask' }
                    'mask-input' { $script:HostReadback='cidr'; $args.ManagementRange=@('10.2.0.0/255.255.0.0') }
                    'ipv6-readback' { $script:HostReadback='ipv6'; $args.ManagementRange=@('2001:0db8:0:1::25/64') }
                    'host-readback' { $script:HostReadback='host'; $args.ManagementRange=@('10.2.3.4') }
                    'wrong-readback' { $script:HostReadback='wrong' }
                    'invalid-mask' { $args.ManagementRange=@('10.2.0.0/255.0.255.0') }
                }
            }
            $failed=$false
            try { Set-CCDCWindowsFirewall @args }
            catch {
                $message=$_.Exception.Message
                switch ($case) {
                    'missing-range' { $failed=$message -like '*requires -ManagementRange*' }
                    'query-error' { $failed=$message -like '*policy store access failure*' }
                    'wrong-readback' { $failed=$message -like '*Source scope verification failed*restored from*' }
                    'invalid-mask' { $failed=$message -like '*Noncontiguous firewall mask*' }
                    default { throw }
                }
            }
            if ($case -eq 'missing-range') {
                if (-not $failed -or $script:HostDisabled.Count) { throw 'Missing range did not fail before writes.' }
            } elseif ($case -eq 'whatif') {
                if ($script:HostDisabled.Count -or $script:HostRules.Count -ne 2) { throw 'WhatIf mutated policy.' }
            } elseif ($case -in @('query-error','invalid-mask')) {
                if (-not $failed -or $script:HostImports -or $script:HostDisabled.Count -or $script:HostRules.Count -ne 2) { throw 'Invalid input or store failure did not stop before changes.' }
            } elseif ($case -eq 'wrong-readback') {
                if (-not $failed -or $script:HostImports -ne 1) { throw 'Genuinely different readback did not trigger backup recovery.' }
            } elseif ($case -eq 'empty') {
                if ($script:HostRules.Count -ne 4 -or $script:HostImports) { throw 'An empty allow set prevented discovered rules from being created.' }
            } elseif ($case -eq 'inactive') {
                foreach ($name in @('CCDC-Host-RDP-3389','CCDC-Host-WinRM-5985','CCDC-Host-WinRM-5986','CCDC-Host-RDP-TCP-3389','CCDC-Host-RDP-UDP-3389',
                    'CCDC-Detected-TCP-445','CCDC-Detected-UDP-137','CCDC-Detected-TCP-50000')) {
                    $summaryName=$name -replace 'CCDC-Host-RDP-3389','CCDC-Host-RDP-TCP-3389' -replace 'CCDC-Host-WinRM-(598[56])','CCDC-Host-WinRM-TCP-$1'
                    if ("$($script:HostRules[$name].RemoteAddress)" -ne '10.2.0.0/16' -or
                        -not @($script:HostMessages | Where-Object { $_ -like "*scoped-rule summary*$summaryName remote=10.2.0.0/16*" }).Count) {
                        throw "Inactive helper was not scoped and summarized: $name"
                    }
                }
                if ($script:HostRules['CCDC-Detected-TCP-60000'].Enabled -or
                    "$($script:HostRules['Site-Service'].RemoteAddress)" -ne 'Any') { throw 'Inactive scoping enabled a disabled rule or narrowed unrelated rules.' }
            } elseif ($case -in @('mask-readback','mask-input','ipv6-readback','host-readback')) {
                if ($script:HostImports -or -not @($script:HostMessages | Where-Object { $_ -like '*scoped-rule summary*CCDC-Host-RDP-TCP-3389*' }).Count) {
                    throw 'Equivalent address forms failed verification.'
                }
            } elseif ($case -in @('dual-protocol','dual-disable','dual-scoped','legacy-udp','fresh-dual')) {
                $tcpName=if ($case -in @('legacy-udp','fresh-dual')) { 'CCDC-Host-RDP-TCP-3389' } else { 'CCDC-Host-RDP-3389' }
                $udpName=if ($case -eq 'legacy-udp') { 'CCDC-Host-RDP-3389' } else { 'CCDC-Host-RDP-UDP-3389' }
                $tcp=$script:HostRules[$tcpName]
                $udp=$script:HostRules[$udpName]
                if (-not $tcp -or -not $udp -or $tcp.Name -eq $udp.Name -or
                    "$($tcp.Protocol)" -notin @('TCP','6') -or "$($udp.Protocol)" -notin @('UDP','17') -or
                    $tcp.LocalPort -ne 3389 -or $udp.LocalPort -ne 3389 -or -not $tcp.Enabled -or -not $udp.Enabled) {
                    throw 'Simultaneous RDP transports did not retain distinct enabled rules and port filters.'
                }
                $tcpScope=if ($case -eq 'dual-scoped') { '10.2.0.0/16' } elseif ($case -in @('dual-disable','legacy-udp','fresh-dual')) { 'Any' } else { '10.1.0.0/16' }
                $udpScope=if ($case -eq 'dual-scoped') { '10.2.0.0/16' } elseif ($case -eq 'legacy-udp') { '10.1.0.0/16' } else { 'Any' }
                if ("$($tcp.RemoteAddress)" -ne $tcpScope -or "$($udp.RemoteAddress)" -ne $udpScope) { throw 'Protocol-specific rules did not preserve the requested scopes.' }
            } else {
                $rdp=$script:HostRules['CCDC-Host-RDP-3389']
                $winrm=$script:HostRules['CCDC-Host-WinRM-TCP-5985']
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
        Remove-Variable HostRules,HostMessages,HostDisabled,HostListeners,HostUdpListener,HostQueryFailure,HostImports,HostReadback -Scope Script -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}
