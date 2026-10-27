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
        Write-Host "Run already $($state.Status); no firewall import."
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
        $backup = Join-Path $RunDirectory 'before.wfw'
        if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $state.BackupHash) {
            throw 'Firewall backup checksum mismatch; refusing import.'
        }
        & "$env:SystemRoot\System32\netsh.exe" advfirewall import $backup
        if ($LASTEXITCODE -ne 0) { throw "Firewall import failed: exit $LASTEXITCODE" }
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
