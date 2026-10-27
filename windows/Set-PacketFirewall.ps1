#requires -Version 5.1
<#
.SYNOPSIS
Additive AD/MSSQL/Wkst firewall baseline with an independent SYSTEM rollback timer.
.DESCRIPTION
Preserves all existing allow/block rules. It is not a strict allowlist or egress
filter. Apply from console; commit separately after external scoring verification.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][ValidateSet('AD', 'MSSQL', 'Wkst')][string]$Role,
    [string]$Indexer = '172.20.240.20',
    [ValidateRange(1, 65535)][int]$IndexerPort = 9997,
    [string[]]$AdditionalTcpPorts = @(),
    [string[]]$AdditionalUdpPorts = @(),
    [ValidateRange(3, 30)][int]$RollbackMinutes = 10,
    [string]$OutputDirectory = "$env:ProgramData\CCDC\Firewall",
    [Alias('PlanOnly')][switch]$AuditOnly,
    [switch]$Force
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lib\PacketDefense.ps1"
if (-not [Environment]::Is64BitProcess) { throw 'Use x64 PowerShell.' }
if (-not (Test-PacketAdministrator)) { throw 'Run elevated, including audit, to inspect the effective firewall policy.' }
$computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
if (($Role -eq 'AD') -ne ([int]$computer.DomainRole -ge 4)) { throw 'Role does not match domain-controller status.' }
if ($Role -eq 'MSSQL' -and -not @(Get-Service 'MSSQLSERVER', 'MSSQL$*' -ErrorAction SilentlyContinue).Count) {
    throw 'No MSSQL database-engine service was found.'
}
$listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
$plan = @(Get-PacketFirewallPlan -Role $Role -ListeningTcp $listeners.LocalPort `
    -AdditionalTcpPorts $AdditionalTcpPorts -AdditionalUdpPorts $AdditionalUdpPorts `
    -Indexer $Indexer -IndexerPort $IndexerPort)
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
$blocks = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Action Block -ErrorAction Stop)
$allows = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)
$exposure = foreach ($rule in $allows) {
    $pf = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
    $af = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
    [pscustomobject]@{
        Name = $rule.Name; DisplayName = $rule.DisplayName; SourceType = "$($rule.PolicyStoreSourceType)"
        Protocol = "$($pf.Protocol)"; LocalPort = @($pf.LocalPort); RemoteAddress = @($af.RemoteAddress)
    }
}
Write-Warning 'Additive baseline: existing inbound allows and explicit blocks are preserved. No claim that all unnecessary ports are closed.'
Write-Warning 'AD permits the standard dynamic RPC range. Outbound default remains Allow; the Splunk rule is not an egress restriction.'
$report = [pscustomobject]@{
    Computer = $env:COMPUTERNAME; Role = $Role; Plan = $plan; Profiles = $profiles
    ExistingInboundAllows = @($exposure)
    ExistingExplicitBlocks = @($blocks | Select-Object Name, DisplayName, Direction, PolicyStoreSourceType)
    UnplannedListeners = @($listeners | Where-Object {
        $candidate = $_.LocalPort
        -not @($plan | Where-Object {
            if ($_.Protocol -ne 'TCP' -or $_.Direction -ne 'Inbound') { return $false }
            if ($_.Port -match '^(\d+)-(\d+)$') { return $candidate -ge [int]$Matches[1] -and $candidate -le [int]$Matches[2] }
            "$candidate" -eq $_.Port
        }).Count
    } | Select-Object LocalAddress, LocalPort, OwningProcess)
}
if ($AuditOnly) { $report; return }
if ($blocks.Count) {
    throw 'Active explicit block rules exist. Inspect them in -AuditOnly: block rules override allows. Review centrally/locally before apply; none are removed automatically.'
}
if (@($profiles | Where-Object { "$($_.AllowLocalFirewallRules)" -eq 'False' -or "$($_.AllowInboundRules)" -eq 'False' }).Count) {
    throw 'Effective policy disables local rule merging or inbound exceptions. Review GPO; no local changes applied.'
}
Assert-PacketLocalPath $OutputDirectory
if (@(Get-ScheduledTask -TaskName 'CCDC-FirewallRollback-*' -ErrorAction SilentlyContinue).Count) {
    throw 'A packet firewall rollback task already exists. Commit/revert or investigate that run before starting another.'
}
# Do not overwrite or broaden an unrelated rule that uses our reserved name.
foreach ($entry in $plan) {
    $existing = Get-NetFirewallRule -PolicyStore PersistentStore -Name $entry.Name -ErrorAction SilentlyContinue
    if ($existing -and $existing.Group -ne 'CCDC Packet Baseline') {
        throw "Unowned rule has a reserved name: $($entry.Name). Nothing was overwritten."
    }
}
if ($Force) { $ConfirmPreference = 'None' }
if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Add packet firewall rules and enable default inbound block with timed rollback')) { return }
$run = Join-Path $OutputDirectory ("run-" + [guid]::NewGuid().ToString('N'))
New-PacketPrivateDirectory $run
$backup = Join-Path $run 'before.wfw'
& "$env:SystemRoot\System32\netsh.exe" advfirewall export $backup
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $backup)) { throw 'Firewall backup failed; nothing applied.' }
$report | ConvertTo-Json -Depth 9 | Set-Content -LiteralPath (Join-Path $run 'audit.json') -Encoding UTF8
$recovery = Join-Path $run 'Invoke-PacketFirewallRecovery.ps1'
Copy-Item -LiteralPath "$PSScriptRoot\Invoke-PacketFirewallRecovery.ps1" -Destination $recovery
New-Item -ItemType Directory -Path (Join-Path $run 'lib') -ErrorAction Stop | Out-Null
Copy-Item -LiteralPath "$PSScriptRoot\lib\PacketDefense.ps1" -Destination (Join-Path $run 'lib\PacketDefense.ps1')
[IO.File]::WriteAllText((Join-Path $run 'operation.lock'), '')
$deadline = (Get-Date).AddMinutes($RollbackMinutes)
$taskName = 'CCDC-FirewallRollback-' + [guid]::NewGuid().ToString('N')
$state = [ordered]@{
    Status = 'Pending'; TaskName = $taskName; Computer = $env:COMPUTERNAME; Role = $Role
    DeadlineUtc = $deadline.ToUniversalTime().ToString('o')
    BackupHash = (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash
}
$state | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $run 'state.json') -Encoding UTF8
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$recovery`" -RunDirectory `"$run`" -Action Revert -Force"
$trigger = New-ScheduledTaskTrigger -Once -At $deadline
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
try {
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings `
        -User 'SYSTEM' -RunLevel Highest -ErrorAction Stop | Out-Null
    if ((Get-ScheduledTask -TaskName $taskName -ErrorAction Stop).State -ne 'Ready') {
        throw 'Rollback task is not Ready; firewall was not changed.'
    }
    # The same lock prevents rollback importing while an apply operation is in flight.
    $lock = [IO.File]::Open((Join-Path $run 'operation.lock'), 'Open', 'ReadWrite', 'None')
}
catch {
    $failure = $_
    # No firewall changes have begun. Cancel an incompletely armed watchdog so
    # it cannot later overwrite somebody else's policy with this unused backup.
    $state.Status = 'Reverted'
    $state | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $run 'state.json') -Encoding UTF8
    try {
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
        }
    }
    catch { Write-Error "Could not remove unused rollback task '$taskName': $($_.Exception.Message)" -ErrorAction Continue }
    throw $failure
}
try {
    foreach ($entry in $plan) {
        $parameters = @{
            PolicyStore = 'PersistentStore'; Name = $entry.Name; DisplayName = $entry.Name
            Group = 'CCDC Packet Baseline'; Enabled = 'True'; Action = 'Allow'
            Profile = 'Any'; Direction = $entry.Direction; Protocol = $entry.Protocol
            RemoteAddress = $entry.Remote
        }
        if ($entry.Port) {
            if ($entry.Direction -eq 'Outbound') { $parameters.RemotePort = $entry.Port }
            else { $parameters.LocalPort = $entry.Port }
        }
        if ($entry.IcmpType) { $parameters.IcmpType = $entry.IcmpType }
        # Refresh only our owned rule; all unrelated rules remain untouched.
        Get-NetFirewallRule -PolicyStore PersistentStore -Name $entry.Name -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule -ErrorAction Stop
        New-NetFirewallRule @parameters -ErrorAction Stop | Out-Null
    }
    # Allow rules are created BEFORE default inbound blocking is enabled.
    Set-NetFirewallProfile -PolicyStore PersistentStore -Profile Domain,Private,Public `
        -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction Stop
    $active = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    if ($active.Count -ne 3 -or @($active | Where-Object {
        "$($_.Enabled)" -ne 'True' -or "$($_.DefaultInboundAction)" -ne 'Block' -or "$($_.DefaultOutboundAction)" -ne 'Allow'
    }).Count) { throw 'Effective profile verification failed (possible domain override).' }
    foreach ($entry in $plan) {
        $rule = Get-NetFirewallRule -PolicyStore ActiveStore -Name $entry.Name -ErrorAction Stop
        if ("$($rule.Enabled)" -ne 'True' -or "$($rule.Action)" -ne 'Allow' -or
            "$($rule.Direction)" -ne $entry.Direction) { throw "Rule not effective: $($entry.Name)" }
        $filter = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
        $addressFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
        $wantedProtocol = switch ($entry.Protocol) { 'TCP' { '6' }; 'UDP' { '17' }; 'ICMPv4' { '1' }; 'ICMPv6' { '58' } }
        if ("$($filter.Protocol)" -notin @($entry.Protocol, $wantedProtocol)) { throw "Protocol mismatch: $($entry.Name)" }
        $actualPort = if ($entry.Direction -eq 'Outbound') { "$($filter.RemotePort)" } else { "$($filter.LocalPort)" }
        if ($entry.Port -and $actualPort -ne $entry.Port) { throw "Port mismatch: $($entry.Name)" }
        if (@($addressFilter.RemoteAddress).Count -ne 1 -or "$($addressFilter.RemoteAddress)" -ne $entry.Remote) {
            throw "Source/destination address mismatch: $($entry.Name)"
        }
    }
    if ([DateTime]::UtcNow -ge $deadline.ToUniversalTime()) { throw 'Apply exceeded rollback confirmation deadline.' }
    Write-Host "PENDING verification. Rollback at $($deadline.ToString('o')); run: $run"
    Write-Host "After EXTERNAL scoring/admin/Splunk checks, commit:"
    Write-Host "& `"$recovery`" -RunDirectory `"$run`" -Action Commit -ScoringVerified"
}
catch {
    $failure = $_
    $lock.Dispose()
    $lock = $null
    try { & $recovery -RunDirectory $run -Action Revert -Force }
    catch { Write-Error "Immediate rollback failed: $($_.Exception.Message). Scheduled rollback remains armed; backup=$backup" -ErrorAction Continue }
    throw $failure
}
finally { if ($lock) { $lock.Dispose() } }
