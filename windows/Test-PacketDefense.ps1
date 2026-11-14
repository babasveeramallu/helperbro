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
    foreach ($name in @('Domain','Private','Public')) {
        $profile = $global:DefenseFixture.Profiles[$name]
        [pscustomobject]@{ Name=$name; Enabled=$profile.Enabled
            DefaultInboundAction=$profile.Inbound; DefaultOutboundAction=$profile.Outbound
            AllowLocalFirewallRules=$true; AllowInboundRules=$true }
    }
}
function Get-NetFirewallRule {
    param($PolicyStore,$Name,$Enabled,$Action,$Direction,$ErrorAction)
    if ($global:DefenseFixture.FailRuleQuery) { throw 'Simulated firewall query failure' }
    $matched = @(foreach ($r in @($global:DefenseFixture.Rules.Values)) {
        if ($Name -and $r.Name -ne $Name) { continue }
        if ($Action -and $r.Action -ne $Action) { continue }
        if ($Direction -and $r.Direction -ne $Direction) { continue }
        $r
    })
    if ($Name -and -not $matched.Count) {
        $global:DefenseFixture.MissingRuleQueries++
        throw [Management.Automation.ErrorRecord]::new(
            [Microsoft.PowerShell.Cmdletization.Cim.CimJobException]::new('No matching MSFT_NetFirewallRule objects found'),
            'CmdletizationQuery_NotFound_InstanceID,Get-NetFirewallRule',
            [Management.Automation.ErrorCategory]::ObjectNotFound, $Name)
    }
    if ($Action -and -not $matched.Count -and $ErrorAction -eq 'Stop') {
        throw 'No matching MSFT_NetFirewallRule objects found'
    }
    $matched
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
        $global:DefenseFixture.RemoveCount++
        if ($global:DefenseFixture.FailRemoveAt -and $global:DefenseFixture.RemoveCount -ge $global:DefenseFixture.FailRemoveAt) { throw 'Simulated rule removal failure' }
        $global:DefenseFixture.Rules.Remove($Rule.Name)
    }
}
function New-NetFirewallRule {
    param($PolicyStore,$Name,$DisplayName,$Group,$Enabled,$Action,$Profile,$Direction,$Protocol,$RemoteAddress,$LocalPort,$RemotePort,$IcmpType,$ErrorAction)
    $global:DefenseFixture.CreateCount++
    if ($global:DefenseFixture.FailCreateAt -and $global:DefenseFixture.CreateCount -ge $global:DefenseFixture.FailCreateAt) {
        if ($global:DefenseFixture.ProfileChangeOnCreateFailure) { $global:DefenseFixture.Profiles.Domain.Inbound='Block' }
        throw 'Simulated rule failure'
    }
    $r=[pscustomobject]@{Name=$Name;DisplayName=$DisplayName;Group=$Group;Enabled=$true;Action=$Action;Profile=$Profile
        Direction=$Direction;Protocol=$Protocol;RemoteAddress=$RemoteAddress;LocalPort=$LocalPort;RemotePort=$RemotePort}
    $global:DefenseFixture.Rules[$Name]=$r
    $r
}
function Set-NetFirewallProfile {
    param($PolicyStore,$Name,$Enabled,$DefaultInboundAction,$DefaultOutboundAction,$ErrorAction)
    if ($global:DefenseFixture.FailProfile) { throw 'Simulated profile failure' }
    if ($PolicyStore -eq 'PersistentStore' -and @('Enabled','DefaultInboundAction','DefaultOutboundAction' |
        Where-Object { $PSBoundParameters.ContainsKey($_) -and $PSBoundParameters[$_] -eq 'NotConfigured' }).Count) {
        throw 'NotConfigured writes to PersistentStore are unsupported in this fixture'
    }
    foreach ($profileName in $Name) {
        $profile = $global:DefenseFixture.Profiles[$profileName]
        if ($PSBoundParameters.ContainsKey('Enabled')) { $profile.Enabled = "$Enabled" }
        if ($PSBoundParameters.ContainsKey('DefaultInboundAction')) { $profile.Inbound = "$DefaultInboundAction" }
        if ($PSBoundParameters.ContainsKey('DefaultOutboundAction')) { $profile.Outbound = "$DefaultOutboundAction" }
    }
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
        [IO.File]::WriteAllText($File,'synthetic firewall snapshot')
    } elseif ($Verb -eq 'import') {
        $global:DefenseFixture.Imports++
        throw 'Full policy import is not permitted in this fixture'
    } else { throw 'Unexpected netsh verb' }
}
Set-Alias -Name "$env:SystemRoot\System32\netsh.exe" -Value Invoke-DefenseNetsh -WhatIf:$false
if ((Get-Command "$env:SystemRoot\System32\netsh.exe").CommandType -ne 'Alias') { throw 'netsh isolation failed' }
'@
    [IO.File]::WriteAllText("$fixture\lib\PacketDefense.ps1", $helper)
    $unowned = [pscustomobject]@{ Name='Existing-Admin'; DisplayName='Existing admin'; Group='site'
        Enabled=$true; Action='Allow'; Direction='Inbound'; Protocol='TCP';LocalPort='5985';RemoteAddress='Any' }
    $global:DefenseFixture = @{
        Root=$fixture; Rules=@{'Existing-Admin'=$unowned}; Tasks=@{}
        Profiles=@{
            Domain=@{Enabled='False';Inbound='Allow';Outbound='Block';LogBlocked='False'}
            Private=@{Enabled='False';Inbound='Allow';Outbound='Block'}
            Public=@{Enabled='True';Inbound='Block';Outbound='Allow'}
        }
        Imports=0; MissingRuleQueries=0; FailCreateAt=0; CreateCount=0; FailRemoveAt=0; RemoveCount=0; FailRuleQuery=$false; FailProfile=$false; ProfileChangeOnCreateFailure=$false; BadTask=$false
    }
    $before=@(Get-ChildItem $fixture -Recurse).Count
    & "$fixture\Start-WindowsDecoy.ps1" -AuditOnly
    Assert-Defense (@(Get-ChildItem $fixture -Recurse).Count -eq $before) 'No-port decoy audit creates no files'
    Assert-Defense ($global:DefenseFixture.Tasks.Count -eq 0) 'No-port decoy audit schedules nothing'
    $report = & "$fixture\Set-PacketFirewall.ps1" -Role Wkst -OutputDirectory "$fixture\runs" -AuditOnly
    Assert-Defense ($report.ExistingInboundAllows.Count -eq 1) 'Audit exposes existing allows'
    Assert-Defense ($report.ExistingExplicitBlocks.Count -eq 0) 'Audit accepts no active block rules'
    Assert-Defense (-not (Test-Path "$fixture\runs")) 'Audit creates no reports/tasks'
    Assert-Defense ($global:DefenseFixture.Tasks.Count -eq 0) 'Audit no scheduled changes'
    & "$fixture\Set-PacketFirewall.ps1" -Role Wkst -OutputDirectory "$fixture\runs" -WhatIf
    Assert-Defense (-not (Test-Path "$fixture\runs")) 'WhatIf writes nothing'

    & "$fixture\Set-PacketFirewall.ps1" -Role Wkst -OutputDirectory "$fixture\runs" -Force
    $run = (Get-ChildItem "$fixture\runs" -Directory | Select-Object -First 1).FullName
    Assert-Defense ($global:DefenseFixture.Profiles.Domain.Enabled -eq 'True' -and $global:DefenseFixture.Profiles.Domain.Inbound -eq 'Block') 'Apply enables default inbound block'
    Assert-Defense ($global:DefenseFixture.Rules.ContainsKey('Existing-Admin')) 'Apply preserves preexisting admin rule'
    Assert-Defense ($global:DefenseFixture.Tasks.Count -eq 1) 'Independent timer armed'
    $rejected=$false
    try { & "$fixture\Set-PacketFirewall.ps1" -Role Wkst -OutputDirectory "$fixture\runs" -Force } catch { $rejected=$_.Exception.Message -like '*rollback task already exists*' }
    Assert-Defense $rejected 'Pending run prevents stacking'
    $state = Get-Content "$run\state.json" -Raw | ConvertFrom-Json
    $manual = [pscustomobject]@{Name='Teammate-Service';DisplayName='Teammate service';Group='site';Enabled=$true;Action='Allow';Direction='Inbound';Protocol='TCP';LocalPort='12345';RemoteAddress='Any'}
    $global:DefenseFixture.Rules[$manual.Name] = $manual
    $global:DefenseFixture.Profiles.Domain.LogBlocked = 'True'
    & "$fixture\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $run -Action Revert -Force
    Assert-Defense ($global:DefenseFixture.Imports -eq 0) 'Revert never imports full policy'
    Assert-Defense ($global:DefenseFixture.Tasks.Count -eq 0) 'Revert removes timer'
    Assert-Defense ($global:DefenseFixture.Rules.ContainsKey('Existing-Admin') -and $global:DefenseFixture.Rules.ContainsKey('Teammate-Service')) 'Revert preserves existing and newly added site rules'
    Assert-Defense (@($state.RuleNames | Where-Object { $global:DefenseFixture.Rules.ContainsKey($_) }).Count -eq 0) 'Revert removes all run-specific rules'
    Assert-Defense ($global:DefenseFixture.Profiles.Domain.Enabled -eq 'False' -and $global:DefenseFixture.Profiles.Domain.Inbound -eq 'Allow' -and $global:DefenseFixture.Profiles.Domain.Outbound -eq 'Block') 'Revert restores distinct Domain profile values'
    Assert-Defense ($global:DefenseFixture.Profiles.Domain.LogBlocked -eq 'True') 'Revert preserves unrelated profile settings'
    Assert-Defense ($global:DefenseFixture.Profiles.Private.Enabled -eq 'False' -and $global:DefenseFixture.Profiles.Private.Inbound -eq 'Allow' -and $global:DefenseFixture.Profiles.Private.Outbound -eq 'Block') 'Revert restores explicit Private profile values'
    Assert-Defense ($global:DefenseFixture.MissingRuleQueries -gt 0) 'Apply and revert suppress representative missing-name ObjectNotFound errors'
    Assert-Defense ($global:DefenseFixture.Profiles.Public.Enabled -eq 'True' -and $global:DefenseFixture.Profiles.Public.Inbound -eq 'Block' -and $global:DefenseFixture.Profiles.Public.Outbound -eq 'Allow') 'Revert preserves unchanged profile values'

    & "$fixture\Set-PacketFirewall.ps1" -Role Wkst -OutputDirectory "$fixture\runs" -Force
    $pending = Get-ChildItem "$fixture\runs" -Directory | Where-Object { (Get-Content "$($_.FullName)\state.json" -Raw | ConvertFrom-Json).Status -eq 'Pending' }
    $rejected=$false
    try { & "$fixture\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $pending.FullName -Action Commit -Force } catch { $rejected=$_.Exception.Message -like '*-ScoringVerified*' }
    Assert-Defense $rejected 'Commit requires external-check acknowledgement'
    $committedNames = @((Get-Content "$($pending.FullName)\state.json" -Raw | ConvertFrom-Json).RuleNames)
    & "$fixture\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $pending.FullName -Action Commit -ScoringVerified -Force
    Assert-Defense ($global:DefenseFixture.Tasks.Count -eq 0) 'Commit removes rollback task'
    Assert-Defense ((Get-Content "$($pending.FullName)\state.json" -Raw | ConvertFrom-Json).Status -eq 'Committed') 'Commit persists terminal state'

    & "$fixture\Set-PacketFirewall.ps1" -Role Wkst -OutputDirectory "$fixture\runs" -Force
    $pending = Get-ChildItem "$fixture\runs" -Directory | Where-Object { (Get-Content "$($_.FullName)\state.json" -Raw | ConvertFrom-Json).Status -eq 'Pending' }
    $newNames = @((Get-Content "$($pending.FullName)\state.json" -Raw | ConvertFrom-Json).RuleNames)
    & "$fixture\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $pending.FullName -Action Revert -Force
    Assert-Defense (@($committedNames | Where-Object { $global:DefenseFixture.Rules.ContainsKey($_) }).Count -eq $committedNames.Count) 'Revert retains previously committed rules'
    Assert-Defense (@($newNames | Where-Object { $global:DefenseFixture.Rules.ContainsKey($_) }).Count -eq 0) 'Revert removes only the later run'
    $global:DefenseFixture.CreateCount=0
    $global:DefenseFixture.FailCreateAt=2
    $global:DefenseFixture.Profiles.Domain.Inbound='Allow'
    $global:DefenseFixture.ProfileChangeOnCreateFailure=$true
    $ruleCount = $global:DefenseFixture.Rules.Count
    $rejected=$false
    try { & "$fixture\Set-PacketFirewall.ps1" -Role Wkst -OutputDirectory "$fixture\runs" -Force } catch { $rejected=$_.Exception.Message -like '*Simulated rule failure*' }
    Assert-Defense $rejected 'Rule failure is propagated'
    Assert-Defense ($global:DefenseFixture.Imports -eq 0 -and @($committedNames | Where-Object { $global:DefenseFixture.Rules.ContainsKey($_) }).Count -eq $committedNames.Count) 'Rule failure preserves earlier policy without import'
    Assert-Defense ($global:DefenseFixture.Rules.Count -eq $ruleCount) 'Partial apply removes its created rules'
    Assert-Defense ($global:DefenseFixture.Profiles.Domain.Inbound -eq 'Block') 'Early apply failure preserves independently changed profile'
    Assert-Defense ($global:DefenseFixture.Tasks.Count -eq 0) 'Recovered failure removes its timer'
    $global:DefenseFixture.FailCreateAt=0
    $global:DefenseFixture.ProfileChangeOnCreateFailure=$false

    $global:DefenseFixture.Profiles.Domain.Enabled='False'
    $global:DefenseFixture.Profiles.Domain.Inbound='Allow'
    & "$fixture\Set-PacketFirewall.ps1" -Role Wkst -OutputDirectory "$fixture\runs" -Force
    $pending = Get-ChildItem "$fixture\runs" -Directory | Where-Object { (Get-Content "$($_.FullName)\state.json" -Raw | ConvertFrom-Json).Status -eq 'Pending' }
    $global:DefenseFixture.Profiles.Domain.Inbound='NotConfigured'
    $rejected=$false
    try { & "$fixture\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $pending.FullName -Action Revert -Force }
    catch { $rejected=$_.Exception.Message -like '*changed independently*' }
    Assert-Defense ($rejected -and $global:DefenseFixture.Profiles.Domain.Inbound -eq 'NotConfigured') 'Conflicting profile change is not overwritten'
    Assert-Defense ($global:DefenseFixture.Tasks.Count -eq 1) 'Profile conflict leaves watchdog armed'
    $global:DefenseFixture.Profiles.Domain.Inbound='Block'
    $global:DefenseFixture.FailProfile=$true
    $rejected=$false
    try { & "$fixture\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $pending.FullName -Action Revert -Force }
    catch { $rejected=$_.Exception.Message -like '*Simulated profile failure*' }
    Assert-Defense ($rejected -and $global:DefenseFixture.Tasks.Count -eq 1) 'Failed profile restore leaves watchdog armed'
    $global:DefenseFixture.FailProfile=$false
    & "$fixture\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $pending.FullName -Action Revert -Force
    Assert-Defense ($global:DefenseFixture.Profiles.Domain.Enabled -eq 'False' -and $global:DefenseFixture.Profiles.Domain.Inbound -eq 'Allow') 'Retry restores profile after conflict and failure'

    & "$fixture\Set-PacketFirewall.ps1" -Role Wkst -OutputDirectory "$fixture\runs" -Force
    $pending = Get-ChildItem "$fixture\runs" -Directory | Where-Object { (Get-Content "$($_.FullName)\state.json" -Raw | ConvertFrom-Json).Status -eq 'Pending' }
    $newNames = @((Get-Content "$($pending.FullName)\state.json" -Raw | ConvertFrom-Json).RuleNames)
    $global:DefenseFixture.FailRuleQuery=$true
    $rejected=$false
    try { & "$fixture\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $pending.FullName -Action Revert -Force }
    catch { $rejected=$_.Exception.Message -like '*Simulated firewall query failure*' }
    Assert-Defense ($rejected -and $global:DefenseFixture.Tasks.Count -eq 1) 'Firewall query failure leaves watchdog armed'
    $global:DefenseFixture.FailRuleQuery=$false
    $global:DefenseFixture.RemoveCount=0
    $global:DefenseFixture.FailRemoveAt=2
    $rejected=$false
    try { & "$fixture\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $pending.FullName -Action Revert -Force }
    catch { $rejected=$_.Exception.Message -like '*Simulated rule removal failure*' }
    Assert-Defense ($rejected -and $global:DefenseFixture.Tasks.Count -eq 1) 'Partial rule removal leaves watchdog armed'
    $global:DefenseFixture.FailRemoveAt=0
    & "$fixture\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $pending.FullName -Action Revert -Force
    Assert-Defense (@($newNames | Where-Object { $global:DefenseFixture.Rules.ContainsKey($_) }).Count -eq 0 -and $global:DefenseFixture.Rules.ContainsKey('Teammate-Service')) 'Retry finishes removal without touching teammate rule'

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
    $originalNames = @($state.RuleNames)
    $state.RuleNames = @('Existing-Admin')
    $state | ConvertTo-Json -Depth 6 | Set-Content "$($pending.FullName)\state.json" -Encoding UTF8
    $rejected=$false
    try { & "$fixture\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $pending.FullName -Action Revert -Force }
    catch { $rejected=$_.Exception.Message -like '*rule list*' }
    Assert-Defense ($rejected -and $global:DefenseFixture.Rules.ContainsKey('Existing-Admin')) 'Tampered run rule list refused'
    $state.RuleNames = $originalNames
    $state | ConvertTo-Json -Depth 6 | Set-Content "$($pending.FullName)\state.json" -Encoding UTF8
    & "$fixture\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $pending.FullName -Action Revert -Force
    Assert-Defense ($global:DefenseFixture.Tasks.Count -eq 0) 'Watchdog action remains usable after failed confirmation'

    $block=[pscustomobject]@{Name='Existing-Block';DisplayName='site block';Group='site';Enabled=$false;Action='Block';Direction='Inbound'}
    $global:DefenseFixture.Rules[$block.Name]=$block
    $report = & "$fixture\Set-PacketFirewall.ps1" -Role Wkst -OutputDirectory "$fixture\runs" -AuditOnly
    Assert-Defense ($report.ExistingExplicitBlocks.Count -eq 0) 'Audit ignores disabled block rules'
    $block.Enabled=$true
    $report = & "$fixture\Set-PacketFirewall.ps1" -Role Wkst -OutputDirectory "$fixture\runs" -AuditOnly
    Assert-Defense ($report.ExistingExplicitBlocks.Count -eq 1) 'Audit reports active block rules'
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

    $global:DefenseFixture.Profiles.Private=@{Enabled='NotConfigured';Inbound='NotConfigured';Outbound='NotConfigured'}
    $global:DefenseFixture.Profiles.Domain=@{Enabled='False';Inbound='Allow';Outbound='Block'}
    & "$fixture\Set-PacketFirewall.ps1" -Role Wkst -OutputDirectory "$fixture\runs" -Force
    $pending = Get-ChildItem "$fixture\runs" -Directory | Where-Object { (Get-Content "$($_.FullName)\state.json" -Raw | ConvertFrom-Json).Status -eq 'Pending' }
    $newNames = @((Get-Content "$($pending.FullName)\state.json" -Raw | ConvertFrom-Json).RuleNames)
    foreach ($attempt in 1..2) {
        $failure = ''
        try { & "$fixture\Invoke-PacketFirewallRecovery.ps1" -RunDirectory $pending.FullName -Action Revert -Force }
        catch { $failure = $_.Exception.Message }
        Assert-Defense ($failure -like '*cannot restore NotConfigured in PersistentStore*' -and
            $failure -like '*Private.Enabled*' -and $failure -like '*Private.DefaultInboundAction*' -and
            $failure -like '*Private.DefaultOutboundAction*') "Unsupported restore reports every affected field on attempt $attempt"
        Assert-Defense (@($newNames | Where-Object { $global:DefenseFixture.Rules.ContainsKey($_) }).Count -eq 0) "Unsupported restore still removes run rules on attempt $attempt"
        Assert-Defense ($global:DefenseFixture.Tasks.Count -eq 1 -and
            (Get-Content "$($pending.FullName)\state.json" -Raw | ConvertFrom-Json).Status -eq 'Pending') "Incomplete recovery retains pending state and watchdog on attempt $attempt"
    }
    Assert-Defense ($global:DefenseFixture.Profiles.Domain.Enabled -eq 'False' -and
        $global:DefenseFixture.Profiles.Domain.Inbound -eq 'Allow' -and
        $global:DefenseFixture.Profiles.Domain.Outbound -eq 'Block') 'Unsupported fields do not prevent supported profile restores'
    Assert-Defense ($global:DefenseFixture.Profiles.Private.Enabled -eq 'True' -and
        $global:DefenseFixture.Profiles.Private.Inbound -eq 'Block' -and
        $global:DefenseFixture.Profiles.Private.Outbound -eq 'Allow') 'Unsupported fields remain at applied values without an unsafe substitute'
    Assert-Defense ($global:DefenseFixture.Rules.ContainsKey('Teammate-Service') -and
        @($committedNames | Where-Object { $global:DefenseFixture.Rules.ContainsKey($_) }).Count -eq $committedNames.Count -and
        $global:DefenseFixture.Imports -eq 0) 'Incomplete recovery preserves teammate and committed rules without full import'

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
