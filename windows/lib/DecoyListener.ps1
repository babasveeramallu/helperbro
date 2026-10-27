function Invoke-PacketDecoyLoop {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Net.Sockets.TcpListener[]]$Listeners,
        [ValidateRange(1, 7200)][int]$DurationSeconds,
        [ValidateRange(1, 120)][int]$MaxConnectionEventsPerMinute = 30,
        [Parameter(Mandatory)][scriptblock]$Emit
    )
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $windowStart = 0.0
    $recorded = 0
    $suppressed = 0L
    $aborted = 0L
    try {
        while ($clock.Elapsed.TotalSeconds -lt $DurationSeconds) {
            if (($clock.Elapsed.TotalSeconds - $windowStart) -ge 60) {
                if ($suppressed -or $aborted) {
                    & $Emit 9102 ([pscustomobject]@{
                        Kind = 'RateLimited'; SuppressedConnections = $suppressed
                        AbortedConnections = $aborted
                        Utc = [DateTime]::UtcNow.ToString('o')
                    })
                }
                $windowStart = $clock.Elapsed.TotalSeconds
                $recorded = 0
                $suppressed = 0L
                $aborted = 0L
            }
            foreach ($listener in $Listeners) {
                # Bound work per tick and keep no clients, payloads or per-IP map.
                for ($batch = 0; $batch -lt 4 -and $listener.Pending(); $batch++) {
                    $client = $null
                    $record = $null
                    try {
                        $client = $listener.AcceptTcpClient()
                        $remote = $client.Client.RemoteEndPoint
                        $local = $client.Client.LocalEndPoint
                        $record = [pscustomobject]@{
                            Kind = 'Connection'; RemoteAddress = $remote.Address.ToString()
                            RemotePort = $remote.Port; LocalAddress = $local.Address.ToString()
                            LocalPort = $local.Port; Utc = [DateTime]::UtcNow.ToString('o')
                        }
                    }
                    catch [Net.Sockets.SocketException] {
                        if ($_.Exception.SocketErrorCode -notin @(
                            [Net.Sockets.SocketError]::ConnectionReset, [Net.Sockets.SocketError]::ConnectionAborted)) { throw }
                        $aborted++
                    }
                    finally { if ($client) { $client.Close() } }
                    if ($null -eq $record) { continue }
                    # Never wait for payload bytes, parse attacker input or reply.
                    if ($recorded -lt $MaxConnectionEventsPerMinute) {
                        & $Emit 9101 $record
                        $recorded++
                    }
                    else { $suppressed++ }
                }
            }
            Start-Sleep -Milliseconds 100
        }
        if ($suppressed -or $aborted) {
            & $Emit 9102 ([pscustomobject]@{
                Kind = 'RateLimited'; SuppressedConnections = $suppressed
                AbortedConnections = $aborted
                Utc = [DateTime]::UtcNow.ToString('o')
            })
        }
    }
    finally {
        $clock.Stop()
        foreach ($listener in $Listeners) { $listener.Stop() }
    }
}
