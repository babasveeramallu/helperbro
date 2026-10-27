#requires -Version 5.1
# Safe offline tests: no services, channels, registry, installer or network changes.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\WindowsForwarder.Common.ps1"
$checks = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "FAIL: $Message" }
    $script:checks++
}
foreach ($file in @('Set-WindowsForwarder.ps1', 'WindowsForwarder.Common.ps1', 'Test-WindowsForwarder.ps1')) {
    $errors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $file), [ref]$null, [ref]$errors)
    Assert-True ($errors.Count -eq 0) "PowerShell parser: $file"
}
foreach ($role in @('AD', 'MSSQL', 'Wkst')) {
    $channels = @(Get-CCDCForwarderChannels $role)
    Assert-True ($channels -contains 'Security') "$role collects Security"
    Assert-True ($channels -contains 'Microsoft-Windows-PowerShell/Operational') "$role collects PowerShell"
    Assert-True ($channels -contains 'Microsoft-Windows-Sysmon/Operational') "$role can collect Sysmon"
    Assert-True (($channels | Select-Object -Unique).Count -eq $channels.Count) "$role has unique channels"
    $text = New-CCDCForwarderInputs -Channels $channels
    foreach ($channel in $channels) {
        $stanza = "WinEventLog://$channel"
        $expectedIndex = if ($channel -like '*Sysmon*') { 'sysmon' } else { 'wineventlog' }
        Assert-True ((Get-CCDCConfValue $text $stanza 'index') -eq $expectedIndex) "$role index for $channel"
        Assert-True ((Get-CCDCConfValue $text $stanza 'disabled') -eq '0') "$role enables $channel"
        Assert-True ((Get-CCDCConfValue $text $stanza 'renderXml') -eq 'true') "$role XML for $channel"
        Assert-True ((Get-CCDCConfValue $text $stanza 'sourcetype') -eq "XmlWinEventLog:$channel") "$role sourcetype for $channel"
        Assert-True ((Get-CCDCConfValue $text $stanza 'start_from') -eq 'newest') "$role bounded first subscription for $channel"
    }
}
Assert-True ((Get-CCDCForwarderChannels AD) -contains 'Directory Service') 'AD includes directory service'
Assert-True ((Get-CCDCForwarderChannels Wkst) -notcontains 'Directory Service') 'Wkst excludes directory service'
$sql = 'C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Log\ERRORLOG'
$sqlText = New-CCDCForwarderInputs -Channels @('Application') -SqlLogs @($sql)
Assert-True ((Get-CCDCConfValue $sqlText "monitor://$sql" 'index') -eq 'mssql') 'SQL file index'
Assert-True ((Get-CCDCConfValue $sqlText "monitor://$sql" 'sourcetype') -eq 'ccdc:mssql:errorlog') 'SQL file sourcetype'
Assert-True ($sqlText -notmatch '\.xel|\.trc') 'No binary SQL audit/trace monitoring'
$out = New-CCDCForwarderOutputs -Indexer '172.20.240.20' -Port 9997
Assert-True ((Get-CCDCConfValue $out 'tcpout' 'defaultGroup') -eq 'ccdc_windows_indexer') 'Forwarding group'
Assert-True ((Get-CCDCConfValue $out 'tcpout:ccdc_windows_indexer' 'server') -eq '172.20.240.20:9997') 'Packet receiver'
Assert-True ((Get-CCDCConfValue $out 'tcpout:ccdc_windows_indexer' 'useACK') -eq 'true') 'ACK enabled'
Assert-True ($null -eq (Get-CCDCConfValue $out 'missing' 'server')) 'Missing stanza does not leak another value'
foreach ($invalid in @("bad`n[stanza]", 'bad,host', 'host:1234')) {
    $rejected = $false
    try { $null = New-CCDCForwarderOutputs $invalid 9997 } catch { $rejected = $true }
    Assert-True $rejected 'Reject output config injection'
}
$rejected = $false
try { $null = New-CCDCForwarderInputs -Channels @("Security`n[evil]") } catch { $rejected = $true }
Assert-True $rejected 'Reject channel injection'

# Execute the real entry point with only discovery mocked, stopping at its
# missing-install audit branch. It must not create even an output directory.
$fixture = Join-Path ([IO.Path]::GetTempPath()) ("ccdc-uf-test-" + [guid]::NewGuid().ToString('N'))
if ([Environment]::Is64BitProcess) {
    try {
        function Get-Service { param($Name, $ErrorAction) return $null }
        & "$PSScriptRoot\Set-WindowsForwarder.ps1" -Role Wkst -SplunkHome $fixture -OutputDirectory $fixture -AuditOnly
        Assert-True (-not (Test-Path -LiteralPath $fixture)) 'Audit creates no installation/output files'
        & "$PSScriptRoot\Set-WindowsForwarder.ps1" -Role Wkst -SplunkHome $fixture -OutputDirectory $fixture -WhatIf
        Assert-True (-not (Test-Path -LiteralPath $fixture)) 'WhatIf creates no installation/output files'
    }
    finally { Remove-Item Function:\Get-Service }
}
else { Write-Warning 'x86 host: testing rendering/parser only; use x64 for entry-point tests.' }

# The actual entry point is copied into an isolated fixture with a mock helper.
# All system discovery, event-log commands, network checks, ACLs and services are
# mocked. Only files within this freshly allocated fixture can be changed.
if ([Environment]::Is64BitProcess) {
    New-Item -ItemType Directory -Path "$fixture\bin" -Force | Out-Null
    try {
        Copy-Item "$PSScriptRoot\Set-WindowsForwarder.ps1", "$PSScriptRoot\mssql-props.conf" $fixture
        [IO.File]::WriteAllText("$fixture\bin\splunk.exe", '')
        $helper = Get-Content -Raw "$PSScriptRoot\WindowsForwarder.Common.ps1"
        $helper += @'

function Test-CCDCForwarderAdministrator { $true }
function Get-Service {
    param($Name, $ErrorAction)
    if ($Name -ne 'SplunkForwarder') { return }
    $item = [pscustomobject]@{ Status = 'Running' }
    $item | Add-Member -MemberType ScriptMethod -Name WaitForStatus -Value { param($State, $Timeout) }
    $item
}
function Get-CimInstance {
    param($ClassName, $Filter, $ErrorAction)
    if ($ClassName -eq 'Win32_ComputerSystem') { [pscustomobject]@{ DomainRole = 0 } }
    else { [pscustomobject]@{ StartName = 'LocalSystem'; StartMode = $global:CCDCMock.StartMode } }
}
function Test-CCDCForwarderPort { param($ComputerName, $Port) $global:CCDCMock.Reachable }
function Invoke-CCDCForwarderCli {
    param($Exe, $Arguments)
    if ($Arguments[1] -eq 'outputs') { return $desiredOutputs }
    if ($global:CCDCMock.Override) { return $desiredInputs.Replace('disabled = 0', 'disabled = 1') }
    return $desiredInputs
}
function Invoke-MockedEventLog {
    param($Action, $Channel, $Option)
    $global:LASTEXITCODE = 0
    if ($Action -eq 'gl') {
        if ($Channel -like '*TaskScheduler*' -and $global:CCDCMock.ChannelDisabled) { '<channel enabled="false" />' }
        else { '<channel enabled="true" />' }
        return
    }
    if ($Action -ne 'sl' -or $Channel -notlike '*TaskScheduler*') { throw 'Unexpected event-log command' }
    $global:CCDCMock.ChannelDisabled = $Option -eq '/e:false'
    $global:CCDCMock.ChannelChanges++
}
Set-Alias -Name "$env:SystemRoot\System32\wevtutil.exe" -Value Invoke-MockedEventLog
if ((Get-Command "$env:SystemRoot\System32\wevtutil.exe").CommandType -ne 'Alias') {
    throw 'Native event-log isolation was not established'
}
function New-CCDCForwarderPrivateDirectory {
    param($Path, [switch]$AllowServiceRead)
    if (-not $Path.StartsWith($global:CCDCMock.Root, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Attempted file write outside fixture'
    }
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
}
function Restart-Service {
    param($Name, $ErrorAction)
    $global:CCDCMock.Restarts++
    if ($global:CCDCMock.FailRestartOnce) {
        $global:CCDCMock.FailRestartOnce = $false
        throw 'Simulated UF restart failure'
    }
}
function Start-Service { throw 'Unexpected service start' }
function Stop-Service { throw 'Unexpected service stop' }
function Set-Service {
    param($Name, $StartupType, $ErrorAction)
    if ($Name -ne 'SplunkForwarder') { throw 'Unexpected service configuration' }
    $global:CCDCMock.StartMode = if ($StartupType -eq 'Automatic') { 'Auto' } else { $StartupType }
}
'@
        [IO.File]::WriteAllText("$fixture\WindowsForwarder.Common.ps1", $helper)
        $global:CCDCMock = @{
            Root = $fixture; Reachable = $true; Override = $false; Restarts = 0
            ChannelDisabled = $true; ChannelChanges = 0; StartMode = 'Auto'; FailRestartOnce = $false
        }
        $before = @(Get-ChildItem -LiteralPath $fixture -Recurse).Count
        $result = & "$fixture\Set-WindowsForwarder.ps1" -Role Wkst -SplunkHome $fixture -OutputDirectory "$fixture\reports" -AuditOnly
        Assert-True ($result.ConfigChangeNeeded) 'Installed audit finds missing config'
        Assert-True ($result.Channels -contains 'Security') 'Installed audit discovers channels'
        Assert-True (@(Get-ChildItem -LiteralPath $fixture -Recurse).Count -eq $before) 'Installed audit creates no files'
        Assert-True ($global:CCDCMock.Restarts -eq 0) 'Installed audit never restarts service'
        Assert-True ($result.DisabledChannels -contains 'Microsoft-Windows-TaskScheduler/Operational') 'Audit reports disabled source channels'
        Assert-True ($global:CCDCMock.ChannelChanges -eq 0) 'Installed audit never enables source channels'

        $global:CCDCMock.Reachable = $false
        $rejected = $false
        try { & "$fixture\Set-WindowsForwarder.ps1" -Role Wkst -SplunkHome $fixture -OutputDirectory "$fixture\reports" -AllowPlaintext -Force }
        catch { $rejected = $_.Exception.Message -like '*Receiver is not reachable*' }
        Assert-True $rejected 'Unreachable receiver blocks apply before changes'
        Assert-True (@(Get-ChildItem -LiteralPath $fixture -Recurse).Count -eq $before) 'Unreachable apply creates no files'

        $global:CCDCMock.Reachable = $true
        & "$fixture\Set-WindowsForwarder.ps1" -Role Wkst -SplunkHome $fixture -OutputDirectory "$fixture\reports" -AllowPlaintext -Force
        Assert-True ($global:CCDCMock.Restarts -eq 1) 'First apply restarts mocked UF once'
        Assert-True (-not $global:CCDCMock.ChannelDisabled) 'Apply enables selected disabled channel'
        $managed = "$fixture\etc\apps\ccdc_windows_forwarder\local"
        $saved = [IO.File]::ReadAllText("$managed\inputs.conf")
        Assert-True ($saved -match '\[WinEventLog://Security\]') 'Apply persists real renderer output'
        & "$fixture\Set-WindowsForwarder.ps1" -Role Wkst -SplunkHome $fixture -OutputDirectory "$fixture\reports" -AllowPlaintext -Force
        Assert-True ($global:CCDCMock.Restarts -eq 1) 'Repeat apply is service-idempotent'

        # Force a file update then fail merged-config verification. The existing
        # app must be restored and no restart attempted for the failed config.
        [IO.File]::WriteAllText("$managed\inputs.conf", '# old app contents')
        $global:CCDCMock.Override = $true
        $global:CCDCMock.ChannelDisabled = $true
        $rejected = $false
        try { & "$fixture\Set-WindowsForwarder.ps1" -Role Wkst -SplunkHome $fixture -OutputDirectory "$fixture\reports" -AllowPlaintext -Force }
        catch { $rejected = $_.Exception.Message -like '*Effective event input overridden*' }
        Assert-True $rejected 'Effective-config override fails closed'
        Assert-True ([IO.File]::ReadAllText("$managed\inputs.conf") -ceq '# old app contents') 'Failure restores original app contents'
        Assert-True ($global:CCDCMock.Restarts -eq 1) 'Rejected config is not restarted'
        Assert-True ($global:CCDCMock.ChannelDisabled) 'Failure restores source channel enabled state'

        $global:CCDCMock.Override = $false
        $global:CCDCMock.StartMode = 'Manual'
        $global:CCDCMock.FailRestartOnce = $true
        $rejected = $false
        try { & "$fixture\Set-WindowsForwarder.ps1" -Role Wkst -SplunkHome $fixture -OutputDirectory "$fixture\reports" -AllowPlaintext -Force }
        catch { $rejected = $_.Exception.Message -like '*Simulated UF restart failure*' }
        Assert-True $rejected 'Service failure is propagated'
        Assert-True ([IO.File]::ReadAllText("$managed\inputs.conf") -ceq '# old app contents') 'Service failure restores app'
        Assert-True ($global:CCDCMock.Restarts -eq 3) 'Service failure attempts restart of old configuration'
        Assert-True ($global:CCDCMock.StartMode -eq 'Manual') 'Service failure restores original startup mode'
        Assert-True ($global:CCDCMock.ChannelDisabled) 'Service failure restores channel state'
    }
    finally {
        Remove-Variable CCDCMock -Scope Global -ErrorAction SilentlyContinue
        # This is the named, fresh test fixture, never a workspace/system path.
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}
Write-Host "PASS: $checks checks. Offline tests only; target VM delivery not tested."
