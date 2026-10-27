# Pure rendering helpers are separated so tests never need an installed forwarder.
function Test-CCDCForwarderAdministrator {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CCDCForwarderChannels {
    param([ValidateSet('AD', 'MSSQL', 'Wkst')][string]$Role)
    $channels = @(
        'Security', 'System', 'Application',
        'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational',
        'Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-WMI-Activity/Operational',
        'Microsoft-Windows-Windows Defender/Operational',
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
        'Microsoft-Windows-Sysmon/Operational'
    )
    if ($Role -eq 'AD') { $channels += @('Directory Service', 'DNS Server', 'DFS Replication') }
    if ($Role -eq 'Wkst') {
        $channels += @('Microsoft-Windows-DeviceSetupManager/Admin', 'Microsoft-Windows-DriverFrameworks-UserMode/Operational')
    }
    $channels
}

function New-CCDCForwarderInputs {
    param([string[]]$Channels, [string[]]$SqlLogs = @())
    $sections = @(foreach ($channel in $Channels) {
        if ($channel -match '[\r\n\[\]]') { throw 'Invalid event channel name.' }
        $index = if ($channel -like '*Sysmon*') { 'sysmon' } else { 'wineventlog' }
        # XML keeps the original event fields. No event-code whitelist hides evidence.
        # Start with current events on first subscription to limit startup load.
        @"
[WinEventLog://$channel]
disabled = 0
renderXml = true
index = $index
sourcetype = XmlWinEventLog:$channel
start_from = newest
current_only = 0
checkpointInterval = 5
"@
    })
    foreach ($log in $SqlLogs) {
        if ($log -match '[\r\n\[\]]') { throw 'SQL log paths cannot contain INI delimiters or newlines.' }
        $sections += @"
[monitor://$log]
disabled = 0
index = mssql
sourcetype = ccdc:mssql:errorlog
"@
    }
    ($sections -join "`r`n`r`n") + "`r`n"
}

function New-CCDCForwarderOutputs {
    param([string]$Indexer, [int]$Port)
    if ($Indexer -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]*$' -or $Port -lt 1 -or $Port -gt 65535) {
        throw 'Invalid forwarding destination.'
    }
    # ACKs improve delivery reliability but do not encrypt or authenticate TCP.
    "[tcpout]`r`ndefaultGroup = ccdc_windows_indexer`r`n`r`n[tcpout:ccdc_windows_indexer]`r`nserver = ${Indexer}:$Port`r`nuseACK = true`r`n"
}

function Get-CCDCForwarderSqlLogs {
    param([string[]]$ExplicitPath = @())
    $paths = @($ExplicitPath)
    if (-not $paths.Count) {
        $instancesKey = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
        if (Test-Path -LiteralPath $instancesKey) {
            $instances = Get-ItemProperty -LiteralPath $instancesKey -ErrorAction Stop
            foreach ($instance in $instances.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }) {
                $key = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$($instance.Value)\MSSQLServer\Parameters"
                $parameters = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
                foreach ($arg in $parameters.PSObject.Properties | Where-Object { $_.Name -like 'SQLArg*' }) {
                    if ([string]$arg.Value -match '^-e(.+)$') { $paths += $Matches[1].Trim('"') }
                }
            }
        }
    }
    foreach ($path in $paths | Select-Object -Unique) {
        if (-not [IO.Path]::IsPathRooted($path) -or $path -match '[\r\n\[\]*?]') {
            throw "SQL log must be an absolute, literal file path: $path"
        }
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "SQL error log does not exist or is inaccessible: $path" }
        (Get-Item -LiteralPath $path -ErrorAction Stop).FullName
    }
}

function Get-CCDCConfValue {
    param([string]$Text, [string]$Section, [string]$Key)
    $inside = $false
    foreach ($line in $Text -split '\r?\n') {
        if ($line -match '^\[([^\]]+)\]\s*$') { $inside = $Matches[1] -eq $Section; continue }
        if ($inside -and $line -match ('^\s*' + [regex]::Escape($Key) + '\s*=\s*(.*?)\s*$')) { return $Matches[1] }
    }
    return $null
}

function Invoke-CCDCForwarderCli {
    param([string]$Exe, [string[]]$Arguments)
    $text = & $Exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Splunk CLI failed ($($Arguments -join ' ')): $($text -join ' ')" }
    $text -join "`n"
}

function Test-CCDCForwarderFile {
    param([string]$Path, [string]$Content)
    (Test-Path -LiteralPath $Path) -and ([IO.File]::ReadAllText($Path) -ceq $Content)
}

function Test-CCDCForwarderPort {
    param([string]$ComputerName, [int]$Port)
    $client = New-Object Net.Sockets.TcpClient
    try {
        $pending = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $pending.AsyncWaitHandle.WaitOne(5000)) { return $false }
        $client.EndConnect($pending)
        return $true
    }
    catch [Net.Sockets.SocketException] { return $false }
    finally { $client.Dispose() }
}

function New-CCDCForwarderPrivateDirectory {
    param([string]$Path, [switch]$AllowServiceRead)
    New-Item -Path $Path -ItemType Directory -Force | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    # Existing least-privilege UF identities still need read access to the app.
    if ($AllowServiceRead) {
        $read = New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier('S-1-5-11')),
            'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($read)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}
