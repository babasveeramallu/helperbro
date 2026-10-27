#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$RunDirectory,
    [Alias('PlanOnly')][switch]$AuditOnly,
    [switch]$Force
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lib\PacketDefense.ps1"
if (-not (Test-PacketAdministrator)) { throw 'Cleanup requires elevation.' }
Assert-PacketLocalPath $RunDirectory
$path = Join-Path $RunDirectory 'decoy.json'
$state = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
if ($state.RunId -notmatch '^[a-f0-9]{32}$' -or
    $state.TaskName -ne "CCDC-DecoyCleanup-$($state.RunId)") { throw 'Invalid decoy cleanup metadata.' }
if ($AuditOnly) { $state; return }
if ($Force) { $ConfirmPreference = 'None' }
if (-not $PSCmdlet.ShouldProcess($RunDirectory, 'Remove only the recorded decoy firewall exceptions')) { return }
foreach ($name in $state.Rules) {
    if ($name -notmatch ("^CCDC-Decoy-" + $state.RunId + '-[0-9]{4,5}$')) { throw "Invalid decoy rule name: $name" }
    $rule = Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue
    if ($rule) {
        if ($rule.Group -ne 'CCDC Decoy') { throw "Refusing to remove unowned rule: $name" }
        $rule | Remove-NetFirewallRule -ErrorAction Stop
    }
}
$state.Status = 'RulesRemoved'
$state | ConvertTo-Json | Set-Content -LiteralPath $path -Encoding UTF8
if (Get-ScheduledTask -TaskName $state.TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $state.TaskName -Confirm:$false -ErrorAction Stop
}
Write-Host "Decoy rules removed. This does not kill a foreground process: $path"
