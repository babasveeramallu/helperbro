#requires -Version 5.1
# Offline policy/mock tests plus a bounded loopback-only socket lifecycle test.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lib\PacketDefense.ps1"
$checks = 0
function Assert-Defense {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "FAIL: $Message" }
    $script:checks++
}
foreach ($name in @('Set-PacketFirewall.ps1', 'Invoke-PacketFirewallRecovery.ps1',
    'Start-WindowsDecoy.ps1', 'Invoke-DecoyCleanup.ps1', 'lib\PacketDefense.ps1', 'lib\DecoyListener.ps1', 'Test-PacketDefense.ps1')) {
    $errors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name), [ref]$null, [ref]$errors)
    Assert-Defense ($errors.Count -eq 0) "Parse $name"
}
foreach ($role in @('AD', 'MSSQL', 'Wkst')) {
    $plan = @(Get-PacketFirewallPlan $role -ListeningTcp @(3389, 5985))
    Assert-Defense (@($plan.Name | Select-Object -Unique).Count -eq $plan.Count) "$role unique names"
    Assert-Defense (@($plan | Where-Object { $_.Direction -eq 'Inbound' -and $_.Remote -ne 'Any' }).Count -eq 0) "$role no scoring-only restrictions"
    foreach ($port in @('3389', '5985')) {
        Assert-Defense (@($plan | Where-Object { $_.Protocol -eq 'TCP' -and $_.Port -eq $port }).Count -eq 1) "$role retains listening admin $port"
    }
    Assert-Defense (@($plan | Where-Object { $_.Protocol -like 'ICMP*' }).Count -eq 2) "$role ICMP v4/v6"
    $out = @($plan | Where-Object Direction -eq Outbound)
    Assert-Defense ($out.Count -eq 1 -and $out[0].Remote -eq '172.20.240.20' -and $out[0].Port -eq '9997') "$role Splunk destination"
}
$ad = @(Get-PacketFirewallPlan AD)
foreach ($port in @('53','88','135','389','445','464','636','3268','3269','5985','5986','49152-65535')) {
    Assert-Defense (@($ad | Where-Object { $_.Protocol -eq 'TCP' -and $_.Port -eq $port }).Count -eq 1) "AD TCP dependency $port"
}
$sql = @(Get-PacketFirewallPlan MSSQL)
foreach ($port in @('139','445','1433','3389')) {
    Assert-Defense (@($sql | Where-Object { $_.Protocol -eq 'TCP' -and $_.Port -eq $port }).Count -eq 1) "MSSQL scoring TCP $port"
}
$wk = @(Get-PacketFirewallPlan Wkst)
Assert-Defense (@($wk | Where-Object { $_.Direction -eq 'Inbound' -and $_.Protocol -eq 'TCP' }).Count -eq 0) 'Wkst does not open unrequested admin/server ports'
foreach ($bad in @('0', '65536', '200-100', "80`n[evil]", 'Any')) {
    $rejected = $false
    try { Assert-PacketPorts @($bad) } catch { $rejected = $true }
    Assert-Defense $rejected "Reject invalid port $bad"
}
foreach ($bad in @(0, 445, 1433, 3389, 5985, 8089, 9997, 49152, 65535)) {
    $rejected = $false
    try { Assert-PacketDecoyPorts @($bad) } catch { $rejected = $true }
    Assert-Defense $rejected "Decoy refuses protected port $bad"
}
$rejected = $false
try { Assert-PacketDecoyPorts @(2222) -Occupied @(2222) } catch { $rejected = $true }
Assert-Defense $rejected 'Occupied decoy refused'
$rejected = $false
try { Assert-PacketDecoyPorts @() } catch { $rejected = $true }
Assert-Defense $rejected 'No default decoy exposure'
Assert-PacketDecoyPorts @(2222, 2323)

if (-not [Environment]::Is64BitProcess) {
    Write-Warning "PASS: $checks parser/policy checks only; use x64 for isolation and socket tests."
    return
}
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('ccdc-defense-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path "$fixture\lib" -Force | Out-Null
$job = $null
try {
    Copy-Item "$PSScriptRoot\Set-PacketFirewall.ps1", "$PSScriptRoot\Invoke-PacketFirewallRecovery.ps1", "$PSScriptRoot\Start-WindowsDecoy.ps1",
        "$PSScriptRoot\Invoke-DecoyCleanup.ps1" $fixture
    Copy-Item "$PSScriptRoot\lib\DecoyListener.ps1" "$fixture\lib"
    $helper = Get-Content -LiteralPath "$PSScriptRoot\lib\PacketDefense.ps1" -Raw
    $helper += @'

function Test-PacketAdministrator { $true }
function Get-CimInstance { param($ClassName,$ErrorAction) [pscustomobject]@{ DomainRole = 0 } }
function Get-NetTCPConnection { param($State,$ErrorAction) [pscustomobject]@{ LocalPort=5985; LocalAddress='0.0.0.0'; OwningProcess=1 } }
function New-PacketPrivateDirectory {
    param($Path)
    if (-not $Path.StartsWith($global:DefenseFixture.Root, [StringComparison]::OrdinalIgnoreCase)) { throw 'Write escaped fixture' }
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
}
function Get-NetFirewallProfile {
    param($PolicyStore,$ErrorAction)
    foreach ($profile in @('Domain','Private','Public')) {
        [pscustomobject]@{ Name=$profile; Enabled=$global:DefenseFixture.Enabled
            DefaultInboundAction=$global:DefenseFixture.Inbound; DefaultOutboundAction='Allow'
            AllowLocalFirewallRules=$true; AllowInboundRules=$true }
    }
}
function Get-NetFirewallRule {
    param($PolicyStore,$Name,$Enabled,$Action,$Direction,$ErrorAction)
    foreach ($r in @($global:DefenseFixture.Rules.Values)) {
        if ($Name -and $r.Name -ne $Name) { continue }
        if ($Action -and $r.Action -ne $Action) { continue }
        if ($Direction -and $r.Direction -ne $Direction) { continue }
        $r
    }
}
function Get-NetFirewallPortFilter {
    [CmdletBinding()]param([Parameter(ValueFromPipeline)]$Rule)
    process {
        [pscustomobject]@{ Protocol=$Rule.Protocol; LocalPort=$Rule.LocalPort; RemotePort=$Rule.RemotePort }
    }
}
function Get-NetFirewallAddressFilter {
    [CmdletBinding()]param([Parameter(ValueFromPipeline)]$Rule)
    process { [pscustomobject]@{ RemoteAddress=$Rule.RemoteAddress } }
}
function Remove-NetFirewallRule {
    [CmdletBinding()]param([Parameter(ValueFromPipeline)]$Rule)
    process {
        if ($Rule.Group -notin @('CCDC Packet Baseline','CCDC Decoy')) { throw 'Attempted to remove unowned rule' }
        $global:DefenseFixture.Rules.Remove($Rule.Name)
    }
}
function New-NetFirewallRule {
    param($PolicyStore,$Name,$DisplayName,$Group,$Enabled,$Action,$Profile,$Direction,$Protocol,$RemoteAddress,$LocalPort,$RemotePort,$IcmpType,$ErrorAction)
    if ($global:DefenseFixture.FailCreate) { throw 'Simulated rule failure' }
    $r=[pscustomobject]@{Name=$Name;DisplayName=$DisplayName;Group=$Group;Enabled=$true;Action=$Action;Profile=$Profile
        Direction=$Direction;Protocol=$Protocol;RemoteAddress=$RemoteAddress;LocalPort=$LocalPort;RemotePort=$RemotePort}
    $global:DefenseFixture.Rules[$Name]=$r
    $r
}
function Set-NetFirewallProfile {
    param($PolicyStore,$Profile,$Enabled,$DefaultInboundAction,$DefaultOutboundAction,$ErrorAction)
    $global:DefenseFixture.Enabled=$true
    $global:DefenseFixture.Inbound=$DefaultInboundAction
}
function Get-ScheduledTask {
    param($TaskName,$ErrorAction)
    foreach ($task in @($global:DefenseFixture.Tasks.Values)) { if ($task.TaskName -like $TaskName) { $task } }
}
function New-ScheduledTaskAction { param($Execute,$Argument) [pscustomobject]@{ Execute=$Execute; Argument=$Argument } }
function New-ScheduledTaskTrigger { param([switch]$Once,$At) [pscustomobject]@{ At=$At } }
function New-ScheduledTaskSettingsSet {
    param([switch]$StartWhenAvailable,$ExecutionTimeLimit,$RestartCount,$RestartInterval,
        [switch]$AllowStartIfOnBatteries,[switch]$DontStopIfGoingOnBatteries)
    [pscustomobject]@{ Retry=$RestartCount }
}
function Register-ScheduledTask {
    param($TaskName,$Action,$Trigger,$Settings,$User,$RunLevel,$ErrorAction)
    $state=if ($global:DefenseFixture.BadTask) { 'Disabled' } else { 'Ready' }
    $task=[pscustomobject]@{TaskName=$TaskName;State=$state;User=$User;Action=$Action}
    $global:DefenseFixture.Tasks[$TaskName]=$task
    $task
}
function Unregister-ScheduledTask {
    param($TaskName,$Confirm,$ErrorAction)
    $global:DefenseFixture.Tasks.Remove($TaskName)
}
function Invoke-DefenseNetsh {
    param($Context,$Verb,$File)
    $global:LASTEXITCODE=0
    if ($Verb -eq 'export') {
        $snapshot=@{Rules=$global:DefenseFixture.Rules.Clone();Enabled=$global:DefenseFixture.Enabled;Inbound=$global:DefenseFixture.Inbound}
        $global:DefenseFixture.Snapshots[$File]=$snapshot
        [IO.File]::WriteAllText($File,'synthetic firewall snapshot')
    } elseif ($Verb -eq 'import') {
        $snapshot=$global:DefenseFixture.Snapshots[$File]
        $global:DefenseFixture.Rules=$snapshot.Rules.Clone()
        $global:DefenseFixture.Enabled=$snapshot.Enabled
        $global:DefenseFixture.Inbound=$snapshot.Inbound
        $global:DefenseFixture.Imports++
    } else { throw 'Unexpected netsh verb' }
}
Set-Alias -Name "$env:SystemRoot\System32\netsh.exe" -Value Invoke-DefenseNetsh -WhatIf:$false
if ((Get-Command "$env:SystemRoot\System32\netsh.exe").CommandType -ne 'Alias') { throw 'netsh isolation failed' }
'@
    [IO.File]::WriteAllText("$fixture\lib\PacketDefense.ps1", $helper)
    $unowned = [pscustomobject]@{ Name='Existing-Admin'; DisplayName='Existing admin'; Group='site'
        Enabled=$true; Action='Allow'; Direction='Inbound'; Protocol='TCP';LocalPort='5985';RemoteAddress='Any' }
    $global:DefenseFixture = @{
        Root=$fixture; Rules=@{'Existing-Admin'=$unowned}; Tasks=@{}; Snapshots=@{}
        Enabled=$false; Inbound='Allow'; Imports=0; FailCreate=$false; BadTask=$false
    }
    $before=@(Get-ChildItem $fixture -Recurse).Count
    & "$fixture\Start-WindowsDecoy.ps1" -AuditOnly
    Assert-Defense (@(Get-ChildItem $fixture -Recurse).Count -eq $before) 'No-port decoy audit creates no files'
    Assert-Defense ($global:DefenseFixture.Tasks.Count -eq 0) 'No-port decoy audit schedules nothing'
    $report = & "$fixture\Set-PacketFirewall.ps1" -Role Wkst -OutputDirectory "$fixture\runs" -AuditOnly
    Assert-Defense ($report.ExistingInboundAllows.Count -eq 1) 'Audit exposes existing allows'
    Assert-Defense (-not (Test-Path "$fixture\runs")) 'Audit creates no reports/tasks'
    Assert-Defense ($global:DefenseFixture.Tasks.Count -eq 0) 'Audit no scheduled changes'
    & "$fixture\Set-PacketFirewall.ps1" -Role Wkst -OutputDirectory "$fixture\runs" -WhatIf
    Assert-Defense (-not (Test-Path "$fixture\runs")) 'WhatIf writes nothing'

    & "$fixture\Set-PacketFirewall.ps1" -Role Wkst -OutputDirectory "$fixture\runs" -Force
    $run = (Get-ChildItem "$fixture\runs" -Directory | Select-Object -First 1).FullName
    Assert-Defense ($global:DefenseFixture.Enabled -and $global:DefenseFixture.Inbound -eq 'Block') 'Apply enables default inbound block'
    Assert-Defense ($global:DefenseFixture.Rules.ContainsKey('Existing-Admin')) 'Apply preserves preexisting admin rule'
    Assert-Defense ($global:DefenseFixture.Tasks.Count -eq 1) 'Independent timer armed'
    $rejected=$false
    try { & "$fixture\Set-PacketFirewall.ps1" -Role Wkst -OutputDirectory "$fixture\runs" -Force } catch { $rejected=$_.Exception.Message -like '*rollback task already exists*' }
    Assert-Defense $rejected 'Pending run prevents stacking'
    $rejected=$false
    try { & "$fixture\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $run -Action Commit -Force } catch { $rejected=$_.Exception.Message -like '*-ScoringVerified*' }
    Assert-Defense $rejected 'Commit requires external-check acknowledgement'
    & "$fixture\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $run -Action Commit -ScoringVerified -Force
    Assert-Defense ($global:DefenseFixture.Tasks.Count -eq 0) 'Commit removes rollback task'
    Assert-Defense ((Get-Content "$run\state.json" -Raw | ConvertFrom-Json).Status -eq 'Committed') 'Commit persists terminal state'

    & "$fixture\Set-PacketFirewall.ps1" -Role Wkst -OutputDirectory "$fixture\runs" -Force
    $pending = Get-ChildItem "$fixture\runs" -Directory | Where-Object { (Get-Content "$($_.FullName)\state.json" -Raw | ConvertFrom-Json).Status -eq 'Pending' }
    & "$fixture\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $pending.FullName -Action Revert -Force
    Assert-Defense ($global:DefenseFixture.Imports -eq 1) 'Revert imports saved policy'
    Assert-Defense ($global:DefenseFixture.Tasks.Count -eq 0) 'Revert removes timer'
    Assert-Defense ($global:DefenseFixture.Rules.ContainsKey('Existing-Admin')) 'Revert preserves old site rule'
    $global:DefenseFixture.FailCreate=$true
    $rejected=$false
    try { & "$fixture\Set-PacketFirewall.ps1" -Role Wkst -OutputDirectory "$fixture\runs" -Force } catch { $rejected=$_.Exception.Message -like '*Simulated rule failure*' }
    Assert-Defense $rejected 'Rule failure is propagated'
    Assert-Defense ($global:DefenseFixture.Imports -eq 2) 'Rule failure immediately restores snapshot'
    Assert-Defense ($global:DefenseFixture.Tasks.Count -eq 0) 'Recovered failure removes its timer'
    $global:DefenseFixture.FailCreate=$false

    # Expired confirmation must not disarm the watchdog or import silently.
    & "$fixture\Set-PacketFirewall.ps1" -Role Wkst -OutputDirectory "$fixture\runs" -Force
    $pending = Get-ChildItem "$fixture\runs" -Directory | Where-Object { (Get-Content "$($_.FullName)\state.json" -Raw | ConvertFrom-Json).Status -eq 'Pending' }
    $state=Get-Content "$($pending.FullName)\state.json" -Raw | ConvertFrom-Json
    $state.DeadlineUtc=[DateTime]::UtcNow.AddMinutes(-1).ToString('o')
    $state | ConvertTo-Json | Set-Content "$($pending.FullName)\state.json" -Encoding UTF8
    $rejected=$false
    try { & "$fixture\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $pending.FullName -Action Commit -ScoringVerified -Force }
    catch { $rejected=$_.Exception.Message -like '*deadline passed*' }
    Assert-Defense $rejected 'Expired confirmation rejected'
    Assert-Defense ($global:DefenseFixture.Tasks.Count -eq 1) 'Expired confirmation leaves timer armed'
    [IO.File]::AppendAllText("$($pending.FullName)\before.wfw",'changed')
    $rejected=$false
    try { & "$fixture\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $pending.FullName -Action Revert -Force }
    catch { $rejected=$_.Exception.Message -like '*checksum mismatch*' }
    Assert-Defense $rejected 'Tampered rollback snapshot refused'
    [IO.File]::WriteAllText("$($pending.FullName)\before.wfw",'synthetic firewall snapshot')
    & "$fixture\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $pending.FullName -Action Revert -Force
    Assert-Defense ($global:DefenseFixture.Tasks.Count -eq 0) 'Watchdog action remains usable after failed confirmation'

    $block=[pscustomobject]@{Name='Existing-Block';DisplayName='site block';Group='site';Action='Block';Direction='Inbound'}
    $global:DefenseFixture.Rules[$block.Name]=$block
    $before=@(Get-ChildItem "$fixture\runs" -Directory).Count
    $rejected=$false
    try { & "$fixture\Set-PacketFirewall.ps1" -Role Wkst -OutputDirectory "$fixture\runs" -Force }
    catch { $rejected=$_.Exception.Message -like '*explicit block rules exist*' }
    Assert-Defense $rejected 'Explicit-block conflict refuses apply'
    Assert-Defense (@(Get-ChildItem "$fixture\runs" -Directory).Count -eq $before) 'Block conflict does not create backup/task'
    $global:DefenseFixture.Rules.Remove($block.Name)

    $canaryId=[guid]::NewGuid().ToString('N')
    $cleanupRun=Join-Path $fixture 'canary-cleanup'
    New-Item -ItemType Directory -Path $cleanupRun | Out-Null
    $canaryName="CCDC-Decoy-$canaryId-2222"
    $taskName="CCDC-DecoyCleanup-$canaryId"
    $global:DefenseFixture.Rules[$canaryName]=[pscustomobject]@{Name=$canaryName;Group='CCDC Decoy';Action='Allow';Direction='Inbound'}
    $global:DefenseFixture.Tasks[$taskName]=[pscustomobject]@{TaskName=$taskName;State='Ready'}
    @{RunId=$canaryId;TaskName=$taskName;Rules=@($canaryName);Status='Pending'} |
        ConvertTo-Json | Set-Content "$cleanupRun\decoy.json" -Encoding UTF8
    & "$fixture\Invoke-DecoyCleanup.ps1" -RunDirectory $cleanupRun -AuditOnly | Out-Null
    Assert-Defense ($global:DefenseFixture.Rules.ContainsKey($canaryName)) 'Cleanup audit preserves exception'
    & "$fixture\Invoke-DecoyCleanup.ps1" -RunDirectory $cleanupRun -Force
    Assert-Defense (-not $global:DefenseFixture.Rules.ContainsKey($canaryName)) 'Cleanup removes exact decoy exception'
    Assert-Defense ($global:DefenseFixture.Rules.ContainsKey('Existing-Admin')) 'Decoy cleanup leaves unrelated rules'
    Assert-Defense ($global:DefenseFixture.Tasks.Count -eq 0) 'Cleanup unregisters timer'

    $global:DefenseFixture.BadTask=$true
    $rejected=$false
    try { & "$fixture\Set-PacketFirewall.ps1" -Role Wkst -OutputDirectory "$fixture\runs" -Force }
    catch { $rejected=$_.Exception.Message -like '*task is not Ready*' }
    Assert-Defense $rejected 'Unready watchdog blocks apply'
    Assert-Defense ($global:DefenseFixture.Tasks.Count -eq 0) 'Unready unused watchdog is removed'
    $global:DefenseFixture.BadTask=$false

    # Loopback sockets only: no services, event-source registrations or firewall
    # changes. The worker emits objects instead of writing to Windows Event Log.
    $ready = Join-Path $fixture 'socket-ready.txt'
    $job = Start-Job -ArgumentList "$PSScriptRoot\lib\DecoyListener.ps1", $ready -ScriptBlock {
        param($Library, $Ready)
        $ErrorActionPreference='Stop'
        . $Library
        $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
        $listener.Start(8)
        [IO.File]::WriteAllText($Ready, "$($listener.LocalEndpoint.Port)")
        Invoke-PacketDecoyLoop -Listeners @($listener) -DurationSeconds 4 -MaxConnectionEventsPerMinute 2 -Emit {
            param($EventId,$Record)
            [pscustomobject]@{ EventId=$EventId; Record=$Record }
        }
    }
    $wait = [Diagnostics.Stopwatch]::StartNew()
    while (-not (Test-Path $ready) -and $wait.Elapsed.TotalSeconds -lt 15) { Start-Sleep -Milliseconds 100 }
    Assert-Defense (Test-Path $ready) 'Isolated loopback test listener ready'
    $port = [int](Get-Content $ready)
    for ($i=0; $i -lt 5; $i++) {
        $client=New-Object Net.Sockets.TcpClient
        try { $client.Connect([Net.IPAddress]::Loopback,$port) } finally { $client.Dispose() }
    }
    $null = Wait-Job -Job $job -Timeout 15
    Assert-Defense ($job.State -eq 'Completed') 'Bounded listener terminates'
    $records = @(Receive-Job -Job $job -ErrorAction Stop)
    Assert-Defense (@($records | Where-Object EventId -eq 9101).Count -eq 2) 'Connection log cap enforced'
    Assert-Defense (($records | Where-Object EventId -eq 9102).Record.SuppressedConnections -eq 3) 'Suppressed connections summarized'
    $client = New-Object Net.Sockets.TcpClient
    $closed=$false
    try { $client.Connect([Net.IPAddress]::Loopback,$port) } catch [Net.Sockets.SocketException] { $closed=$true } finally { $client.Dispose() }
    Assert-Defense $closed 'Listener socket closes at deadline'
}
finally {
    if ($job) { if ($job.State -eq 'Running') { Stop-Job -Job $job }; Remove-Job -Job $job }
    Remove-Variable DefenseFixture -Scope Global -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
Write-Host "PASS: $checks checks. Firewall/scheduler operations mocked; no real scoring/network policy validation."
