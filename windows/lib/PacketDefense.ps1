# Pure policy helpers and restricted run-directory handling for packet defenses.
function Test-PacketAdministrator {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-PacketLocalPath {
    param([string]$Path)
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path -match '["\r\n]') {
        throw 'Use an absolute local-drive path without quotes or newlines.'
    }
    $item = [IO.Path]::GetFullPath($Path)
    while ($item) {
        if ((Test-Path -LiteralPath $item) -and
            ((Get-Item -LiteralPath $item -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Refusing reparse-point path: $item"
        }
        $parent = Split-Path -Path $item -Parent
        if ($parent -eq $item) { break }
        $item = $parent
    }
}

function New-PacketPrivateDirectory {
    param([string]$Path)
    Assert-PacketLocalPath $Path
    New-Item -Path $Path -ItemType Directory -ErrorAction Stop | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier($sid)),
            'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

function Assert-PacketPorts {
    param([string[]]$Ports)
    foreach ($port in $Ports) {
        if ($port -notmatch '^([0-9]{1,5})(?:-([0-9]{1,5}))?$') { throw "Invalid port/range: $port" }
        $first = [int]$Matches[1]
        $last = if ($Matches[2]) { [int]$Matches[2] } else { $first }
        if ($first -lt 1 -or $last -gt 65535 -or $last -lt $first) { throw "Invalid port/range: $port" }
    }
}

function Get-PacketFirewallPlan {
    param(
        [ValidateSet('AD', 'MSSQL', 'Wkst')][string]$Role,
        [int[]]$ListeningTcp = @(),
        [string[]]$AdditionalTcpPorts = @(),
        [string[]]$AdditionalUdpPorts = @(),
        [string]$Indexer = '172.20.240.20',
        [int]$IndexerPort = 9997
    )
    $address = $null
    if (-not [Net.IPAddress]::TryParse($Indexer, [ref]$address)) { throw '-Indexer must be an IPv4 or IPv6 address, not a DNS name.' }
    if ($IndexerPort -lt 1 -or $IndexerPort -gt 65535) { throw 'Invalid indexer TCP port.' }
    Assert-PacketPorts $AdditionalTcpPorts
    Assert-PacketPorts $AdditionalUdpPorts
    $tcp = @()
    # DHCP replies remain possible even if an existing profile was disabled.
    $udp = @('68', '546')
    if ($Role -eq 'AD') {
        $tcp = @('53', '88', '135', '139', '389', '445', '464', '636', '3268', '3269',
            '5722', '5985', '5986', '49152-65535')
        $udp += @('53', '88', '123', '137', '138', '389', '464')
    }
    if ($Role -eq 'MSSQL') {
        $tcp = @('139', '445', '1433', '3389')
        $udp += @('137', '138', '1434')
    }
    # Do not silently strand currently listening administration on any profile.
    $tcp += @($ListeningTcp | Where-Object { $_ -in @(3389, 5985, 5986) } | ForEach-Object { "$_" })
    $tcp += $AdditionalTcpPorts
    $udp += $AdditionalUdpPorts
    foreach ($protocol in @('TCP', 'UDP')) {
        $ports = if ($protocol -eq 'TCP') { $tcp } else { $udp }
        foreach ($port in $ports | Sort-Object -Unique) {
            [pscustomobject]@{
                Name = "CCDC-Packet-$Role-$protocol-$port"; Direction = 'Inbound'
                Protocol = $protocol; Port = $port; Remote = 'Any'; IcmpType = $null
            }
        }
    }
    foreach ($protocol in @('ICMPv4', 'ICMPv6')) {
        [pscustomobject]@{
            Name = "CCDC-Packet-$Role-$protocol"; Direction = 'Inbound'
            Protocol = $protocol; Port = $null; Remote = 'Any'; IcmpType = 'Any'
        }
    }
    [pscustomobject]@{
        Name = "CCDC-Packet-$Role-Splunk"; Direction = 'Outbound'
        Protocol = 'TCP'; Port = "$IndexerPort"; Remote = $address.ToString(); IcmpType = $null
    }
}

function Assert-PacketDecoyPorts {
    param([int[]]$Ports, [int[]]$Occupied = @())
    if (-not $Ports.Count) { throw 'No default decoy ports. Supply explicit approved unused -Ports.' }
    if ($Ports.Count -gt 8 -or @($Ports | Select-Object -Unique).Count -ne $Ports.Count) {
        throw 'Use 1..8 distinct decoy ports.'
    }
    $protected = @(53, 88, 123, 135, 137, 138, 139, 389, 445, 464, 636, 1433, 1434,
        3268, 3269, 3389, 5722, 5985, 5986, 8000, 8089, 9997)
    foreach ($port in $Ports) {
        if ($port -lt 1024 -or $port -ge 49152 -or $port -in $protected) {
            throw "Protected, privileged or dynamic-RPC port cannot be a decoy: $port"
        }
        if ($port -in $Occupied) { throw "Port $port already has a TCP listener; refusing to replace it." }
    }
}
