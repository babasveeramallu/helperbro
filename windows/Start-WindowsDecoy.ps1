#requires -Version 5.1
<#
.SYNOPSIS
Bounded detection-only TCP canaries. No ports, service install or startup persistence by default.
.DESCRIPTION
Runs in the foreground, accepts then immediately closes connections without
reading payloads or credentials. Application events are compatible with the UF
Application input. Requires explicit approval, unused ports and a local bind IP.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [int[]]$Ports = @(),
    [string]$ListenAddress = '127.0.0.1',
    [ValidateRange(1, 120)][int]$DurationMinutes = 15,
    [ValidateRange(1, 120)][int]$MaxConnectionEventsPerMinute = 30,
    [string]$OutputDirectory = "$env:ProgramData\CCDC\Decoys",
    [switch]$ApprovedByWhiteTeam,
    [switch]$OpenFirewall,
    [Alias('PlanOnly')][switch]$AuditOnly,
    [switch]$Force
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lib\PacketDefense.ps1"
. "$PSScriptRoot\lib\DecoyListener.ps1"
if (-not [Environment]::Is64BitProcess) { throw 'Use x64 PowerShell.' }
if (-not (Test-PacketAdministrator)) { throw 'Run elevated so Application event-source and firewall state can be checked.' }
if (-not $Ports.Count) {
    if ($AuditOnly -or $WhatIfPreference) {
        Write-Warning 'No decoy ports configured. No listener, firewall exception, event source or service will be created.'
        return
    }
    throw 'No default decoy ports. Supply explicit approved unused -Ports.'
}
$address = $null
if (-not [Net.IPAddress]::TryParse($ListenAddress, [ref]$address) -or
    $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
    $address.Equals([Net.IPAddress]::Any)) {
    throw 'Use a specific local IPv4 bind address, not a wildcard or hostname.'
}
$localIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | ForEach-Object IPAddress)
if ($address.ToString() -notin $localIps -and -not [Net.IPAddress]::IsLoopback($address)) {
    throw 'ListenAddress is not assigned locally.'
}
$occupied = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object { [int]$_.LocalPort })
Assert-PacketDecoyPorts -Ports $Ports -Occupied $occupied
$source = 'CCDC-Decoy'
if ([Diagnostics.EventLog]::SourceExists($source) -and
    [Diagnostics.EventLog]::LogNameFromSourceName($source, '.') -ne 'Application') {
    throw 'CCDC-Decoy is registered to a different event log.'
}
Write-Warning 'This is a detectable connection canary, not SMB/RDP/WinRM emulation or proof that a client is hostile/AI-driven.'
Write-Host "Bind=$ListenAddress; ports=$($Ports -join ','); lifetime=$DurationMinutes minute(s); firewall exceptions=$OpenFirewall"
if ($AuditOnly) {
    [pscustomobject]@{
        ListenAddress = $ListenAddress; Ports = $Ports; DurationMinutes = $DurationMinutes
        OpenFirewall = [bool]$OpenFirewall; EventSource = $source; ApprovalRequired = -not $ApprovedByWhiteTeam
    }
    return
}
if ($Force) { $ConfirmPreference = 'None' }
if (-not $PSCmdlet.ShouldProcess($ListenAddress, 'Run bounded detection-only TCP decoys')) { return }
if (-not $ApprovedByWhiteTeam) { throw 'Obtain organizer approval before using -ApprovedByWhiteTeam. No listener started.' }
if ($OpenFirewall -and [Net.IPAddress]::IsLoopback($address)) {
    throw 'Loopback listeners do not need inbound network exceptions; omit -OpenFirewall.'
}
if (@(Get-ScheduledTask -TaskName 'CCDC-FirewallRollback-*' -ErrorAction SilentlyContinue).Count) {
    throw 'Finish the pending firewall verification first. A full-policy rollback could remove decoy exceptions.'
}
if (-not [Diagnostics.EventLog]::SourceExists($source)) {
    # This source registration persists after the foreground listener exits.
    [Diagnostics.EventLog]::CreateEventSource($source, 'Application')
}
$runId = [guid]::NewGuid().ToString('N')
$listeners = @()
$cleanup = $null
$run = $null
$emit = {
    param([int]$EventId, $Record)
    $Record | Add-Member -NotePropertyName RunId -NotePropertyValue $runId
    $Record | Add-Member -NotePropertyName Hostname -NotePropertyValue $env:COMPUTERNAME
    [Diagnostics.EventLog]::WriteEntry($source, ($Record | ConvertTo-Json -Compress),
        [Diagnostics.EventLogEntryType]::Information, $EventId)
}
try {
    # Bind ALL ports before opening firewall exceptions. Bind failure is fatal.
    foreach ($port in $Ports) {
        $listener = New-Object Net.Sockets.TcpListener($address, $port)
        $listener.ExclusiveAddressUse = $true
        $listeners += $listener
        $listener.Start(8)
    }
    & $emit 9100 ([pscustomobject]@{
        Kind = 'Started'; ListenAddress = $address.ToString(); Ports = $Ports
        DurationMinutes = $DurationMinutes; Utc = [DateTime]::UtcNow.ToString('o')
    })
    if ($OpenFirewall) {
        Assert-PacketLocalPath $OutputDirectory
        $run = Join-Path $OutputDirectory "run-$runId"
        New-PacketPrivateDirectory $run
        New-Item -ItemType Directory -Path (Join-Path $run 'lib') -ErrorAction Stop | Out-Null
        Copy-Item -LiteralPath "$PSScriptRoot\lib\PacketDefense.ps1" -Destination (Join-Path $run 'lib\PacketDefense.ps1')
        $cleanup = Join-Path $run 'Invoke-DecoyCleanup.ps1'
        Copy-Item -LiteralPath "$PSScriptRoot\Invoke-DecoyCleanup.ps1" -Destination $cleanup
        $taskName = "CCDC-DecoyCleanup-$runId"
        $cleanupState = [ordered]@{
            RunId = $runId; TaskName = $taskName; Rules = @($Ports | ForEach-Object { "CCDC-Decoy-$runId-$_" })
            Status = 'Pending'; DeadlineUtc = (Get-Date).AddMinutes($DurationMinutes + 1).ToUniversalTime().ToString('o')
        }
        $cleanupState | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $run 'decoy.json') -Encoding UTF8
        $taskAction = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$cleanup`" -RunDirectory `"$run`" -Force"
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($DurationMinutes + 1)
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2) `
            -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $trigger -Settings $settings `
            -User SYSTEM -RunLevel Highest -ErrorAction Stop | Out-Null
        if ((Get-ScheduledTask -TaskName $taskName -ErrorAction Stop).State -ne 'Ready') {
            throw 'Decoy rule cleanup timer is not ready; no exceptions opened.'
        }
        Write-Host "Independent exception cleanup scheduled. Run directory: $run"
        $program = (Get-Process -Id $PID -ErrorAction Stop).Path
        foreach ($port in $Ports) {
            $name = "CCDC-Decoy-$runId-$port"
            # Scope to this executable, bound local address and port; never clear
            # existing rules, create block rules or bind a genuine scored port.
            New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $name -Group 'CCDC Decoy' `
                -Enabled True -Action Allow -Direction Inbound -Protocol TCP -LocalPort $port `
                -LocalAddress $address.ToString() -RemoteAddress Any -Program $program -Profile Any -ErrorAction Stop | Out-Null
            $effective = Get-NetFirewallRule -PolicyStore ActiveStore -Name $name -ErrorAction Stop
            if ("$($effective.Enabled)" -ne 'True' -or "$($effective.Action)" -ne 'Allow') {
                throw "Decoy exception is not effective: $name"
            }
        }
        Write-Warning 'Existing blocks/GPO/network rules can still prevent access. Test from another authorized host.'
    }
    Invoke-PacketDecoyLoop -Listeners $listeners -DurationSeconds ($DurationMinutes * 60) `
        -MaxConnectionEventsPerMinute $MaxConnectionEventsPerMinute -Emit $emit
}
catch {
    $failure = $_
    Write-Error "Decoy failed: $($failure.Exception.Message)" -ErrorAction Continue
    throw $failure
}
finally {
    $cleanupFailed = $false
    foreach ($listener in $listeners) { $listener.Stop() }
    if ($cleanup -and (Test-Path -LiteralPath (Join-Path $run 'decoy.json'))) {
        try { & $cleanup -RunDirectory $run -Force }
        catch {
            $cleanupFailed = $true
            Write-Error "Scheduled exception cleanup remains necessary: $($_.Exception.Message); run=$run" -ErrorAction Continue
        }
    }
    try {
        & $emit 9103 ([pscustomobject]@{ Kind = 'Stopped'; Utc = [DateTime]::UtcNow.ToString('o') })
    }
    catch {
        $cleanupFailed = $true
        Write-Error "Could not log stop event: $($_.Exception.Message)" -ErrorAction Continue
    }
    if ($cleanupFailed) { throw 'Decoy cleanup/stop logging did not complete successfully. Inspect the reported errors and cleanup task.' }
}
