#requires -Version 5.1
<#
.SYNOPSIS
Commit or revert a pending packet-firewall change; also run by its SYSTEM timer.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$RunDirectory,
    [ValidateSet('Commit', 'Revert')][string]$Action = 'Revert',
    [Alias('PlanOnly')][switch]$AuditOnly,
    [switch]$ScoringVerified,
    [switch]$Force
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lib\PacketDefense.ps1"
if (-not (Test-PacketAdministrator)) { throw 'Recovery/commit requires elevation.' }
if (-not $AuditOnly -and $Action -eq 'Commit' -and -not $ScoringVerified) {
    throw 'Test scoring, remote administration and Splunk from the appropriate network before using -ScoringVerified.'
}
Assert-PacketLocalPath $RunDirectory
$RunDirectory = [IO.Path]::GetFullPath($RunDirectory)
$stateFile = Join-Path $RunDirectory 'state.json'
$lockFile = Join-Path $RunDirectory 'operation.lock'
if ($AuditOnly) { Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json; return }
if ($Force) { $ConfirmPreference = 'None' }
if (-not $PSCmdlet.ShouldProcess($RunDirectory, "$Action packet firewall run")) { return }
# Exclusive file ownership serializes the watchdog and operator confirmation.
$lock = [IO.File]::Open($lockFile, 'Open', 'ReadWrite', 'None')
try {
    $state = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
    if ($state.TaskName -notmatch '^CCDC-FirewallRollback-[a-f0-9]{32}$' -or $state.Computer -ne $env:COMPUTERNAME) {
        throw 'Rollback metadata does not match this computer or task namespace.'
    }
    if ($state.Status -in @('Committed', 'Reverted')) {
        if (Get-ScheduledTask -TaskName $state.TaskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $state.TaskName -Confirm:$false -ErrorAction Stop
        }
        Write-Host "Run already $($state.Status); no firewall changes."
        return
    }
    if ($state.Status -ne 'Pending') { throw "Unexpected rollback state: $($state.Status)" }
    if ($Action -eq 'Commit') {
        if ([DateTime]::UtcNow -ge [DateTime]::Parse($state.DeadlineUtc).ToUniversalTime()) {
            throw 'Confirmation deadline passed. Leave rollback armed; inspect the actual firewall state.'
        }
        $state.Status = 'Committed'
    }
    else {
        if ($state.SchemaVersion -ne 2 -or $state.RunId -cnotmatch '^[a-f0-9]{32}$' -or
            (Split-Path $RunDirectory -Leaf) -cne "run-$($state.RunId)") {
            throw 'Invalid or legacy rollback metadata; use the recovery script saved with that run.'
        }
        $names = @($state.RuleNames)
        if (-not $names.Count -or @($names | Sort-Object -Unique).Count -ne $names.Count -or
            @($names | Where-Object { $_ -cnotlike "CCDC-Packet-$($state.RunId)-*" }).Count) {
            throw 'Invalid run-specific firewall rule list; rollback remains armed.'
        }
        $original = @($state.Profiles)
        if ($original.Count -ne 3 -or @($original.Name | Sort-Object -Unique).Count -ne 3 -or
            @($original | Where-Object {
                $_.Name -notin @('Domain','Private','Public') -or
                $_.Enabled -notin @('True','False','NotConfigured') -or
                $_.DefaultInboundAction -notin @('Allow','Block','NotConfigured') -or
                $_.DefaultOutboundAction -notin @('Allow','Block','NotConfigured')
            }).Count) {
            throw 'Invalid saved firewall profiles; rollback remains armed.'
        }
        $current = @(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop)
        if ($current.Count -ne 3 -or @($current.Name | Sort-Object -Unique).Count -ne 3 -or
            @($current | Where-Object { $_.Name -notin @('Domain','Private','Public') }).Count) {
            throw 'Cannot inspect all three local firewall profiles; rollback remains armed.'
        }
        $target = @{ Enabled='True'; DefaultInboundAction='Block'; DefaultOutboundAction='Allow' }
        $profileApplyStarted = Test-Path -LiteralPath (Join-Path $RunDirectory 'profile-apply-started') -PathType Leaf -ErrorAction Stop
        $unrestorable = New-Object 'System.Collections.Generic.List[string]'
        $restores = @(foreach ($profile in $original) {
            $now = $current | Where-Object Name -eq $profile.Name
            $parameters = @{ PolicyStore='PersistentStore'; Name=$profile.Name; ErrorAction='Stop' }
            foreach ($field in @('Enabled','DefaultInboundAction','DefaultOutboundAction')) {
                if (-not $profileApplyStarted) { continue }
                $before = "$($profile.$field)"
                $actual = "$($now.$field)"
                if ($before -eq $target[$field] -or $actual -eq $before) { continue }
                if ($actual -ne $target[$field]) {
                    throw "Firewall profile $($profile.Name) $field changed independently; rollback remains armed. Coordinate manual recovery."
                }
                if ($before -eq 'NotConfigured') {
                    # NotConfigured writes are documented only for GPOs, not PersistentStore.
                    $unrestorable.Add("$($profile.Name).$field")
                    continue
                }
                $parameters[$field] = $before
            }
            ,$parameters
        })
        foreach ($name in $names) {
            $rules = @(Get-PacketLocalFirewallRule -Name $name)
            if (@($rules | Where-Object { $_.Name -cne $name -or $_.Group -ne 'CCDC Packet Baseline' }).Count) {
                throw "Run-specific rule is no longer owned: $name. Rollback remains armed."
            }
        }
        foreach ($parameters in $restores) {
            if ($parameters.Count -gt 3) {
                Set-NetFirewallProfile @parameters
                $verified = @(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop |
                    Where-Object Name -eq $parameters.Name)
                if ($verified.Count -ne 1) { throw "Cannot verify profile $($parameters.Name); rollback remains armed." }
                foreach ($field in @('Enabled','DefaultInboundAction','DefaultOutboundAction')) {
                    if ($parameters.ContainsKey($field) -and "$($verified[0].$field)" -ne $parameters[$field]) {
                        throw "Failed to restore profile $($parameters.Name) $field; rollback remains armed."
                    }
                }
            }
        }
        foreach ($name in $names) {
            $rules = @(Get-PacketLocalFirewallRule -Name $name)
            foreach ($rule in $rules) {
                if ($rule.Name -cne $name -or $rule.Group -ne 'CCDC Packet Baseline') {
                    throw "Run-specific rule is no longer owned: $name. Rollback remains armed."
                }
                $rule | Remove-NetFirewallRule -ErrorAction Stop
            }
            if (@(Get-PacketLocalFirewallRule -Name $name).Count) {
                throw "Failed to remove run-specific rule $name; rollback remains armed."
            }
        }
        if ($unrestorable.Count) {
            throw "Run-specific rules removed, but cannot restore NotConfigured in PersistentStore for: $($unrestorable -join ', '). These fields remain at the applied values. Recovery is incomplete; state remains Pending and rollback remains armed. Coordinate manual recovery from the console."
        }
        $state.Status = 'Reverted'
    }
    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $stateFile -Encoding UTF8
    # Write terminal state BEFORE removing the timer; a racing timer sees no work.
    if (Get-ScheduledTask -TaskName $state.TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $state.TaskName -Confirm:$false -ErrorAction Stop
    }
    Write-Host "Run $($state.Status). State: $stateFile"
}
finally { $lock.Dispose() }
