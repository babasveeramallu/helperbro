function ConvertTo-CCDCFirewallNetwork {
    param([Parameter(Mandatory)][string]$Range)
    $parts = $Range.Split('/')
    $address = $null
    if ($parts.Count -gt 2 -or -not [Net.IPAddress]::TryParse($parts[0], [ref]$address)) {
        throw "Invalid firewall address/CIDR: $Range"
    }
    $bytes = $address.GetAddressBytes()
    $prefix = $bytes.Length * 8
    if ($parts.Count -eq 2) {
        if ([int]::TryParse($parts[1], [ref]$prefix)) {
            if ($prefix -lt 0 -or $prefix -gt $bytes.Length * 8) { throw "Invalid firewall prefix: $Range" }
        } else {
            $mask = $null
            if (-not [Net.IPAddress]::TryParse($parts[1], [ref]$mask) -or $mask.AddressFamily -ne $address.AddressFamily) {
                throw "Invalid firewall mask: $Range"
            }
            $prefix = 0
            $ended = $false
            foreach ($octet in $mask.GetAddressBytes()) {
                for ($bit = 7; $bit -ge 0; $bit--) {
                    if ($octet -band (1 -shl $bit)) {
                        if ($ended) { throw "Noncontiguous firewall mask: $Range" }
                        $prefix++
                    } else { $ended = $true }
                }
            }
        }
    }
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bits = [Math]::Min(8, [Math]::Max(0, $prefix - 8 * $i))
        $bytes[$i] = $bytes[$i] -band (256 - [int][Math]::Pow(2, 8 - $bits))
    }
    "$([Net.IPAddress]::new($bytes))/$prefix"
}

function Set-CCDCWindowsFirewall {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [string[]]$ManagementRange = @(),
        [switch]$ScopeManagementPorts,
        [switch]$ScopeSystemPorts,
        [switch]$DisableExistingInboundAllows
    )
    if (($ScopeManagementPorts -or $ScopeSystemPorts) -and -not $ManagementRange.Count) {
        throw 'Port scoping requires -ManagementRange; no rules changed.'
    }
    $managementNetworks = @($ManagementRange | ForEach-Object { ConvertTo-CCDCFirewallNetwork $_ } | Sort-Object -Unique)
    $systemPorts = @(135,137,138,139,445,5040,5050,5353,7680,1900,3702)
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    $listeners = @()
    $listeners += Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Protocol='TCP'; Port=[int]$_.LocalPort; PID=[int]$_.OwningProcess } }
    $listeners += Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Protocol='UDP'; Port=[int]$_.LocalPort; PID=[int]$_.OwningProcess } }
    $listeners = @($listeners | Sort-Object Protocol,Port,PID -Unique)
    $serviceMap = @(Get-CimInstance Win32_Service -Filter "State='Running'" -ErrorAction Stop)
    $detected = @(foreach ($listener in $listeners) {
        $service = $serviceMap | Where-Object { $_.ProcessId -eq $listener.PID } | Select-Object -First 1
        if ($service) { [pscustomobject]@{ Protocol=$listener.Protocol; Port=$listener.Port; Service=$service.Name; PID=$listener.PID } }
        else { Write-Log FLAG "Listener $($listener.Protocol)/$($listener.Port) PID=$($listener.PID) has no mapped running service; not auto-allowed." }
    })
    # Kernel-owned listeners (PID 4: http.sys and the SMB server) never map to a service process,
    # so map the well-known ones to the service that serves them: RDP, WinRM, IIS and the SMB server.
    $kernelServices = @(
        @{Port=3389;Service='TermService'},@{Port=5985;Service='WinRM'},@{Port=5986;Service='WinRM'},
        @{Port=80;Service='W3SVC'},@{Port=443;Service='W3SVC'},
        @{Port=445;Service='LanmanServer'},@{Port=139;Service='LanmanServer'}
    )
    foreach ($special in $kernelServices) {
        $hasListener = @($listeners | Where-Object { $_.Protocol -eq 'TCP' -and $_.Port -eq $special.Port }).Count -gt 0
        $service = $serviceMap | Where-Object Name -eq $special.Service | Select-Object -First 1
        if ($hasListener -and $service -and -not (@($detected | Where-Object { $_.Protocol -eq 'TCP' -and $_.Port -eq $special.Port }).Count)) {
            $detected += [pscustomobject]@{ Protocol='TCP'; Port=$special.Port; Service=$special.Service; PID=$service.ProcessId }
            Write-Log INFO "Mapped shared/system listener TCP/$($special.Port) to running service $($special.Service)."
        }
    }
    $gpoAllows = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {
        $_.Direction -eq 'Inbound' -and "$($_.Enabled)" -eq 'True' -and $_.Action -eq 'Allow' -and $_.PolicyStoreSourceType -eq 'GroupPolicy'
    })
    if ($gpoAllows.Count) { Write-Log FLAG 'Active GPO inbound allow rules are preserved and may permit access beyond the requested local scopes.' }
    $localRules = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
    $localAllows = @($localRules | Where-Object { $_.Direction -eq 'Inbound' -and "$($_.Enabled)" -eq 'True' -and $_.Action -eq 'Allow' })
    foreach ($rule in $localAllows) {
        $port = 0
        $protocol = 'TCP'
        if ($ScopeManagementPorts -and $rule.DisplayName -match '^CCDC-Host-(RDP-3389|WinRM-598[56])$') {
            $port = [int]($rule.DisplayName.Split('-')[-1])
        } elseif ($ScopeSystemPorts -and $rule.DisplayName -match '^CCDC-Detected-(TCP|UDP)-([0-9]{1,5})$') {
            $protocol = $Matches[1]
            $candidate = [int]$Matches[2]
            if ($candidate -in $systemPorts -or ($candidate -ge 49152 -and $candidate -le 65535)) { $port = $candidate }
        }
        if ($port -and -not @($detected | Where-Object { $_.Protocol -eq $protocol -and $_.Port -eq $port }).Count) {
            $detected += [pscustomobject]@{ Protocol=$protocol; Port=$port; Service='existing helper'; PID=0 }
        }
    }
    foreach ($rule in $localAllows) {
        $filter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
        Write-Log INFO "Existing inbound allow name=$($rule.Name) display=$($rule.DisplayName) remote=$(@($filter.RemoteAddress) -join ','); disable requested=$DisableExistingInboundAllows"
    }
    if (($ScopeManagementPorts -or $ScopeSystemPorts) -and -not $DisableExistingInboundAllows) {
        Write-Log FLAG 'Existing allows are preserved; scoped helper rules do not override other broader allow rules.'
    }
    Write-Log INFO "Detected $(@($detected).Count) listener/service pairs. Management range=$($ManagementRange -join ',')."
    if ($PSCmdlet.ShouldProcess('Windows Defender Firewall', "Set inbound default Block; disable existing allows=$DisableExistingInboundAllows; scope management=$ScopeManagementPorts; scope system=$ScopeSystemPorts")) {
        $backupPath = Join-Path $ReportDirectory ("firewall-before-{0}.clixml" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        $backupWfw = [System.IO.Path]::ChangeExtension($backupPath, '.wfw')
        Get-NetFirewallProfile | Export-Clixml -LiteralPath $backupPath
        & netsh.exe advfirewall export $backupWfw | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $backupWfw)) { throw 'Could not export a restorable Windows Firewall backup; no rules changed.' }
        try {
            $localAllows | Export-Clixml -LiteralPath ($backupPath + '.rules')
            $disabled = [System.Collections.Generic.List[string]]::new()
            $narrowed = [System.Collections.Generic.List[string]]::new()
            if ($DisableExistingInboundAllows) {
                foreach ($rule in $localAllows) {
                    $rule | Disable-NetFirewallRule -ErrorAction Stop
                    $disabled.Add("$($rule.Name) ($($rule.DisplayName))")
                    Write-Log CHANGE "Disabled inbound allow name=$($rule.Name) display=$($rule.DisplayName)"
                }
            }
            Set-NetFirewallProfile -Name Domain,Private,Public -DefaultInboundAction Block -Enabled True -ErrorAction Stop
            foreach ($entry in $detected) {
                $name = switch ($entry.Port) {
                    3389 { "CCDC-Host-RDP-$($entry.Port)"; break }
                    { $_ -in @(5985,5986) } { "CCDC-Host-WinRM-$($entry.Port)"; break }
                    default { "CCDC-Detected-$($entry.Protocol)-$($entry.Port)" }
                }
                $systemPort = $ScopeSystemPorts -and $entry.Port -in $systemPorts -or ($ScopeSystemPorts -and $entry.Port -ge 49152)
                $scoped = ($ScopeManagementPorts -and $entry.Port -in @(3389,5985,5986)) -or $systemPort
                $remote = if ($scoped) { $ManagementRange } else { 'Any' }
                $existingRule = $localRules | Where-Object DisplayName -eq $name
                if ($existingRule -and -not $scoped -and -not $DisableExistingInboundAllows) {
                    Write-Log INFO "Preserved existing helper rule and scope: $name"
                    continue
                }
                if (-not $existingRule) {
                    $existingRule = New-NetFirewallRule -PolicyStore PersistentStore -DisplayName $name -Direction Inbound -Action Allow -Enabled True -Protocol $entry.Protocol -LocalPort $entry.Port -RemoteAddress $remote -Profile Domain,Private,Public
                    $localRules += $existingRule
                } else {
                    Set-NetFirewallRule -InputObject $existingRule -Enabled True -Action Allow -Profile Domain,Private,Public
                    $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $existingRule
                    Set-NetFirewallPortFilter -InputObject $portFilter -Protocol $entry.Protocol -LocalPort $entry.Port
                }
                $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $existingRule
                Set-NetFirewallAddressFilter -InputObject $addressFilter -RemoteAddress $remote
                if ($scoped) {
                    $actual = @((Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $existingRule -ErrorAction Stop).RemoteAddress)
                    $actualNetworks = @($actual | ForEach-Object { ConvertTo-CCDCFirewallNetwork $_ } | Sort-Object -Unique)
                    if (-not $actualNetworks.Count -or (Compare-Object $managementNetworks $actualNetworks)) {
                        throw "Source scope verification failed for $name."
                    }
                }
                Write-Log CHANGE "Allow $($entry.Protocol)/$($entry.Port) service=$($entry.Service) remote=$($remote -join ',')"
                if ($scoped) { $narrowed.Add("$name remote=$($remote -join ',')") }
            }
            $after = Get-NetFirewallProfile
            if (@($after | Where-Object { $_.DefaultInboundAction -ne 'Block' }).Count) { throw 'Firewall default-action verification failed.' }
            Write-Log INFO "Firewall disabled-rule summary ($($disabled.Count)): $($disabled -join '; ')"
            Write-Log INFO "Firewall scoped-rule summary ($($narrowed.Count)): $($narrowed -join '; ')"
            Write-Log CHANGE "Firewall defaults verified as Block. Backup=$backupWfw; test scoring/admin reachability before continuing."
        } catch {
            $failure = $_.Exception.Message
            & netsh.exe advfirewall import $backupWfw | Out-Null
            $rollbackCode = $LASTEXITCODE
            if ($rollbackCode -ne 0) { throw "Firewall apply failed: $failure; automatic restore also failed (exit $rollbackCode). Backup=$backupWfw" }
            throw "Firewall apply failed: $failure; restored from $backupWfw."
        }
    }
}


