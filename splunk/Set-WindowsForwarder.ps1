#requires -Version 5.1
<#
.SYNOPSIS
Configures an installed Splunk Universal Forwarder for the packet's Windows hosts.
.DESCRIPTION
PowerShell 5.1/7, x64 Windows. Only the SplunkForwarder service is restarted.
An optional signed MSI is launched interactively: passwords never enter this script.
AuditOnly (alias PlanOnly) writes nothing. Configuration backups are ACL-restricted.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][ValidateSet('AD', 'MSSQL', 'Wkst')][string]$Role,
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9.-]*$')][string]$Indexer = '172.20.240.20',
    [ValidateRange(1, 65535)][int]$Port = 9997,
    [string]$SplunkHome = 'C:\Program Files\SplunkUniversalForwarder',
    [string]$InstallerPath,
    [ValidatePattern('^[a-fA-F0-9]{64}$')][string]$InstallerSha256,
    [string[]]$SqlLogPath = @(),
    [string]$OutputDirectory = "$env:ProgramData\CCDC\Splunk",
    [Alias('PlanOnly')][switch]$AuditOnly,
    [switch]$AllowPlaintext,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\WindowsForwarder.Common.ps1"

if (-not [Environment]::Is64BitProcess) { throw 'Use x64 PowerShell, not an x86 shell.' }
if (-not $AuditOnly -and -not $WhatIfPreference -and -not (Test-CCDCForwarderAdministrator)) {
    throw 'Apply requires an elevated PowerShell. Use -AuditOnly for read-only inspection.'
}
$app = Join-Path $SplunkHome 'etc\apps\ccdc_windows_forwarder'
$exe = Join-Path $SplunkHome 'bin\splunk.exe'
$service = Get-Service -Name SplunkForwarder -ErrorAction SilentlyContinue
Write-Host "Role=$Role; receiver=${Indexer}:$Port; host=$env:COMPUTERNAME"
Write-Warning 'This setup uses unencrypted Splunk TCP. Use only on the approved competition network; apply requires -AllowPlaintext.'

if (-not (Test-Path -LiteralPath $exe) -or -not $service) {
    if ($AuditOnly -or $WhatIfPreference) {
        Write-Warning 'Universal Forwarder is not installed. Stage the approved x64 MSI and use -InstallerPath during apply.'
        return
    }
    if (-not $InstallerPath) { throw 'Universal Forwarder missing. Supply -InstallerPath to a vendor-signed x64 MSI, or install it first.' }
    if (-not $AllowPlaintext) { throw 'Review the transport warning and explicitly supply -AllowPlaintext.' }
    $msi = (Resolve-Path -LiteralPath $InstallerPath).Path
    if ([IO.Path]::GetExtension($msi) -ine '.msi' -or $msi.Contains('"')) { throw 'InstallerPath must be an MSI path without quote characters.' }
    $signature = Get-AuthenticodeSignature -LiteralPath $msi
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(?i)\bSplunk\b') {
        throw 'Installer must have a valid Splunk Authenticode signature.'
    }
    if ($InstallerSha256 -and (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash -ine $InstallerSha256) {
        throw 'Installer SHA256 does not match the approved hash.'
    }
    if ($Force) { $ConfirmPreference = 'None' }
    if (-not $PSCmdlet.ShouldProcess($msi, 'Launch interactive Universal Forwarder installation')) { return }
    Write-Host "Install to '$SplunkHome'. Choose appropriate event-log read privileges (Local System for the lab is simplest)."
    Write-Host 'Use a unique UF administrator password in the installer; do not enter domain/scoring credentials.'
    $process = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList "/i `"$msi`" /norestart" -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010)) { throw "MSI installation failed/cancelled: exit $($process.ExitCode)." }
    if ($process.ExitCode -eq 3010) { Write-Warning 'Installer requests a reboot. Schedule it separately; this script never reboots.' }
    $service = Get-Service -Name SplunkForwarder -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $exe)) { throw "Install path differs from -SplunkHome ($SplunkHome)." }
}

$computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
if (($Role -eq 'AD') -ne ([int]$computer.DomainRole -ge 4)) {
    throw "Role '$Role' does not match this computer's DC status. Select AD only on a domain controller."
}
if ($Role -eq 'MSSQL' -and -not @(Get-Service -Name 'MSSQLSERVER', 'MSSQL$*' -ErrorAction SilentlyContinue).Count) {
    throw 'MSSQL role selected but no SQL Server database-engine service was found.'
}
$svcInfo = Get-CimInstance Win32_Service -Filter "Name='SplunkForwarder'" -ErrorAction Stop
Write-Host "Forwarder service identity=$($svcInfo.StartName); state=$($service.Status)"
Write-Warning 'Verify this service identity can read Security and each collected channel/file. The script does not change service accounts or ACLs on SQL logs.'

$channelNames = Get-CCDCForwarderChannels -Role $Role
$available = New-Object 'System.Collections.Generic.List[string]'
$disabled = New-Object 'System.Collections.Generic.List[string]'
foreach ($channel in $channelNames) {
    # Missing optional providers (e.g. Sysmon) are reported, never installed implicitly.
    # Windows PowerShell can turn native stderr into terminating errors under Stop.
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $channelInfo = & "$env:SystemRoot\System32\wevtutil.exe" gl $channel /f:xml 2>&1
        $channelExit = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previousPreference }
    if ($channelExit -ne 0) {
        if ($channel -in @('Security', 'System', 'Application', 'Directory Service')) {
            throw "Required channel '$channel' cannot be read: $($channelInfo -join ' ')"
        }
        Write-Warning "Optional channel unavailable, not collected: $channel"
        continue
    }
    [xml]$xml = $channelInfo -join "`n"
    $enabledNode = $xml.SelectSingleNode("/*/@enabled")
    if ($null -eq $enabledNode) { throw "Cannot determine enabled state for '$channel'." }
    $available.Add($channel)
    if ($enabledNode.Value -notin @('true', 'false')) { throw "Invalid enabled state for '$channel'." }
    if ($enabledNode.Value -ieq 'false') { $disabled.Add($channel) }
}

$logs = @()
if ($Role -eq 'MSSQL') {
    $logs = @(Get-CCDCForwarderSqlLogs -ExplicitPath $SqlLogPath)
    if (-not $logs.Count) { Write-Warning 'No SQL ERRORLOG file discovered; Application events will still be collected. Supply -SqlLogPath for nonstandard paths.' }
}
elseif ($SqlLogPath.Count) { throw '-SqlLogPath is valid only for the MSSQL role.' }

$desiredInputs = New-CCDCForwarderInputs -Channels $available.ToArray() -SqlLogs $logs
$desiredOutputs = New-CCDCForwarderOutputs -Indexer $Indexer -Port $Port
$desiredProps = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'mssql-props.conf'))
# Refuse to silently replace a site's existing forwarding destination.
$effective = Invoke-CCDCForwarderCli -Exe $exe -Arguments @('btool', 'outputs', 'list')
$oldGroup = Get-CCDCConfValue -Text $effective -Section 'tcpout' -Key 'defaultGroup'
if ($oldGroup -and $oldGroup -ne 'ccdc_windows_indexer') {
    throw "Existing defaultGroup '$oldGroup' is not managed by this script. Review 'splunk btool outputs list --debug' and migrate it explicitly first."
}
$local = Join-Path $app 'local'
$inputsPath = Join-Path $local 'inputs.conf'
$outputsPath = Join-Path $local 'outputs.conf'
$propsPath = Join-Path $local 'props.conf'
foreach ($path in @($app, $local, $inputsPath, $outputsPath, $propsPath)) {
    if ((Test-Path -LiteralPath $path) -and
        ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Refusing to overwrite a managed junction/symlink: $path"
    }
}
$needsConfig = -not ((Test-CCDCForwarderFile -Path $inputsPath -Content $desiredInputs) -and
    (Test-CCDCForwarderFile -Path $outputsPath -Content $desiredOutputs) -and
    (Test-CCDCForwarderFile -Path $propsPath -Content $desiredProps))
$connected = Test-CCDCForwarderPort -ComputerName $Indexer -Port $Port
Write-Host "Receiver TCP reachable=$connected; config change needed=$needsConfig; startup=$($svcInfo.StartMode); disabled channels=$($disabled -join ', ')"
if (-not $connected) {
    Write-Warning 'Receiver is unreachable. Configure Debian first and check routing/firewalls. A TCP test does not prove event receipt.'
}
if ($AuditOnly) {
    Write-Output ([pscustomobject]@{
        Role = $Role; Receiver = "${Indexer}:$Port"; TcpReachable = $connected
        Channels = $available.ToArray(); DisabledChannels = $disabled.ToArray()
        SqlLogs = $logs; ConfigChangeNeeded = $needsConfig; ServiceStatus = [string]$service.Status
        StartupChangeNeeded = $svcInfo.StartMode -ne 'Auto'
    })
    return
}
if ($Force) { $ConfirmPreference = 'None' }
if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Configure Windows forwarding and restart only SplunkForwarder if needed')) { return }
if (-not $AllowPlaintext) { throw 'Review the transport warning and explicitly supply -AllowPlaintext.' }
if (-not $connected) { throw 'Receiver is not reachable; refusing configuration changes. Start the Debian receiver first.' }

$backup = Join-Path $OutputDirectory ("forwarder-{0}-{1}" -f (Get-Date -Format 'yyyyMMdd-HHmmss'), [guid]::NewGuid().ToString('N'))
New-CCDCForwarderPrivateDirectory -Path $backup
$hadApp = Test-Path -LiteralPath $app
$wasRunning = $service.Status -eq 'Running'
$enabledByUs = New-Object 'System.Collections.Generic.List[string]'
if ($hadApp) { Copy-Item -LiteralPath $app -Destination (Join-Path $backup 'app') -Recurse -Force }
$serviceTouched = $false
$startupTouched = $false
$run = [ordered]@{
    Computer = $env:COMPUTERNAME; Role = $Role; Receiver = "${Indexer}:$Port"
    Channels = $available.ToArray(); SqlLogs = $logs; PreviousStartMode = $svcInfo.StartMode
    Status = 'Applying'; Error = $null
}
$runPath = Join-Path $backup 'run.json'
try {
    $run | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $runPath -Encoding UTF8
    if ($needsConfig) {
        New-CCDCForwarderPrivateDirectory -Path $app -AllowServiceRead
        New-Item -ItemType Directory -Path $local -Force | Out-Null
        [IO.File]::WriteAllText($inputsPath, $desiredInputs, (New-Object Text.UTF8Encoding($false)))
        [IO.File]::WriteAllText($outputsPath, $desiredOutputs, (New-Object Text.UTF8Encoding($false)))
        [IO.File]::WriteAllText($propsPath, $desiredProps, (New-Object Text.UTF8Encoding($false)))
    }
    foreach ($channel in $disabled) {
        # Operational logs must be enabled at the source, not merely subscribed to by UF.
        & "$env:SystemRoot\System32\wevtutil.exe" sl $channel /e:true
        if ($LASTEXITCODE -ne 0) { throw "Could not enable event channel '$channel'." }
        $enabledByUs.Add($channel)
    }
    $mergedOutputs = Invoke-CCDCForwarderCli -Exe $exe -Arguments @('btool', 'outputs', 'list')
    if ((Get-CCDCConfValue $mergedOutputs 'tcpout' 'defaultGroup') -ne 'ccdc_windows_indexer' -or
        (Get-CCDCConfValue $mergedOutputs 'tcpout:ccdc_windows_indexer' 'server') -ne "${Indexer}:$Port") {
        throw 'A higher-precedence outputs.conf overrides this app. Inspect btool outputs list --debug.'
    }
    $mergedInputs = Invoke-CCDCForwarderCli -Exe $exe -Arguments @('btool', 'inputs', 'list')
    foreach ($channel in $available) {
        $section = "WinEventLog://$channel"
        $expectedIndex = if ($channel -like '*Sysmon*') { 'sysmon' } else { 'wineventlog' }
        if ((Get-CCDCConfValue $mergedInputs $section 'disabled') -notin @('0', 'false') -or
            (Get-CCDCConfValue $mergedInputs $section 'index') -ne $expectedIndex -or
            (Get-CCDCConfValue $mergedInputs $section 'renderXml') -notin @('1', 'true') -or
            (Get-CCDCConfValue $mergedInputs $section 'sourcetype') -ne "XmlWinEventLog:$channel") {
            throw "Effective event input overridden: $section. Inspect btool inputs list --debug."
        }
    }
    foreach ($log in $logs) {
        if ((Get-CCDCConfValue $mergedInputs "monitor://$log" 'index') -ne 'mssql' -or
            (Get-CCDCConfValue $mergedInputs "monitor://$log" 'disabled') -notin @('0', 'false')) {
            throw "Effective SQL monitor overridden: $log."
        }
    }
    if ($svcInfo.StartMode -ne 'Auto') {
        Set-Service -Name SplunkForwarder -StartupType Automatic -ErrorAction Stop
        $startupTouched = $true
    }
    if ($needsConfig -or $enabledByUs.Count -or -not $wasRunning) {
        $serviceTouched = $true
        if ($wasRunning) { Restart-Service -Name SplunkForwarder -ErrorAction Stop }
        else { Start-Service -Name SplunkForwarder -ErrorAction Stop }
        (Get-Service SplunkForwarder).WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
    }
    Write-Host "Configuration verified; SplunkForwarder running. Backup: $backup"
    Write-Host 'Now verify active forwarding and NEW events in Splunk using the README queries. Service/TCP success alone is not delivery proof.'
    $run.Status = 'ConfiguredDeliveryNotYetVerified'
    $run | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $runPath -Encoding UTF8
}
catch {
    $failure = $_
    Write-Warning "Apply failed: $($failure.Exception.Message). Restoring this app and channel states."
    try {
        if ($hadApp) {
            if (Test-Path -LiteralPath $app) { Remove-Item -LiteralPath $app -Recurse -Force }
            Copy-Item -LiteralPath (Join-Path $backup 'app') -Destination $app -Recurse -Force
        }
        elseif (Test-Path -LiteralPath $app) { Remove-Item -LiteralPath $app -Recurse -Force }
        foreach ($channel in $enabledByUs) {
            & "$env:SystemRoot\System32\wevtutil.exe" sl $channel /e:false
            if ($LASTEXITCODE -ne 0) { throw "Rollback could not disable '$channel'." }
        }
        if ($serviceTouched) {
            if ($wasRunning) { Restart-Service SplunkForwarder -ErrorAction Stop }
            else { Stop-Service SplunkForwarder -ErrorAction Stop }
        }
        if ($startupTouched) {
            $oldStartup = if ($svcInfo.StartMode -eq 'Disabled') { 'Disabled' } else { 'Manual' }
            Set-Service -Name SplunkForwarder -StartupType $oldStartup -ErrorAction Stop
        }
    }
    catch { Write-Error "ROLLBACK FAILED: $($_.Exception.Message). Restore from $backup manually." -ErrorAction Continue }
    $run.Status = 'FailedSeeRollbackOutput'
    $run.Error = $failure.Exception.Message
    try { $run | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $runPath -Encoding UTF8 }
    catch { Write-Error "Could not save failure report: $($_.Exception.Message)" -ErrorAction Continue }
    throw $failure
}
