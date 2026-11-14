#Requires -Version 5.1
# Adapted from Labyrinth core/probe/Probe.ps1. See ../../LICENSE.
#
# A probe only checks that a service answers as expected; it never logs in.
# It uses .NET sockets, Resolve-DnsName and, for HTTPS, curl.exe when the
# host has it. When nothing can run a probe, the result is "unknown", which
# is never counted as a regression.
#
# Each probe gives one line: "<result> <detail>", result pass, fail or unknown.

# Invoke-LabTcpExchange: connect; optionally send text; return the first
# line (-FirstLine, then say -Quit, QUIT by default) or up to 64 KiB of the reply.
# $null means the exchange failed or exceeded its time or size limit.
function Invoke-LabTcpExchange {
    param(
        [Parameter(Mandatory)] [string] $Target,
        [Parameter(Mandatory)] [int] $Port,
        [Parameter(Mandatory)] [int] $Timeout,
        [string] $Send = '',
        [switch] $FirstLine,
        [string] $Quit = 'QUIT',
        [switch] $ConnectOnly
    )
    $client = $null
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        $address = $null
        if ([Net.IPAddress]::TryParse($Target, [ref]$address) -and $address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
            $client = New-Object Net.Sockets.TcpClient -ArgumentList ([Net.Sockets.AddressFamily]::InterNetworkV6)
        } else {
            $client = New-Object Net.Sockets.TcpClient
        }
        if (-not $client.ConnectAsync($Target, $Port).Wait($Timeout * 1000)) { return $null }
        if ($ConnectOnly) { return '' }
        $stream = $client.GetStream()
        if ($Send -ne '') {
            $bytes = [Text.Encoding]::ASCII.GetBytes($Send)
            $remaining = $Timeout * 1000 - [int]$timer.ElapsedMilliseconds
            if ($remaining -le 0 -or -not $stream.WriteAsync($bytes, 0, $bytes.Length).Wait($remaining)) { return $null }
        }
        $ms = New-Object IO.MemoryStream
        $buf = New-Object byte[] 8192
        try {
            while ($ms.Length -lt 65536) {
                $remaining = $Timeout * 1000 - [int]$timer.ElapsedMilliseconds
                if ($remaining -le 0) { return $null }
                $read = $stream.ReadAsync($buf, 0, [Math]::Min($buf.Length, 65536 - [int]$ms.Length))
                if (-not $read.Wait($remaining)) { return $null }
                $n = $read.Result
                if ($n -le 0) { break }
                $ms.Write($buf, 0, $n)
                if ($FirstLine) {
                    $text = [Text.Encoding]::UTF8.GetString($ms.ToArray())
                    $end = $text.IndexOf("`n")
                    if ($end -ge 0) {
                        $closing = [Text.Encoding]::ASCII.GetBytes("$Quit`r`n")
                        $remaining = $Timeout * 1000 - [int]$timer.ElapsedMilliseconds
                        if ($remaining -gt 0) {
                            try { [void]$stream.WriteAsync($closing, 0, $closing.Length).Wait($remaining) } catch { $null = $_ }
                        }
                        return $text.Substring(0, $end).TrimEnd("`r")
                    }
                }
            }
            if ($FirstLine -or $ms.Length -ge 65536) { return $null }
            return [Text.Encoding]::UTF8.GetString($ms.ToArray())
        } finally { $ms.Dispose() }
    } catch {
        return $null
    } finally {
        if ($client) { $client.Close() }
    }
}
function Get-LabHttpResult {
    param([string] $Code, [string] $Body, [string] $Expect)
    if ($Code -notmatch '^[23][0-9][0-9]$') { return "fail status $Code" }
    if ($Expect -ne '-' -and -not $Body.Contains($Expect)) { return "fail status $Code but the expected text is missing" }
    return "pass status $Code"
}

# Invoke-LabProbe -Proto P -Target HOST -Port N -Expect E -Timeout S [-Path /x]:
# probe one service. -Path (default /) only matters to http and https; a
# redirect is never followed.
function Invoke-LabProbe {
    param(
        [Parameter(Mandatory)] [string] $Proto,
        [Parameter(Mandatory)] [string] $Target,
        [Parameter(Mandatory)] [int] $Port,
        [Parameter(Mandatory)] [string] $Expect,
        [int] $Timeout = 5,
        [string] $Path = '/'
    )
    $hostPart = if ($Target.Contains(':')) { "[$Target]" } else { $Target }
    switch ($Proto) {
        'http' {
            $authority = if ($Port -eq 80) { $hostPart } else { "${hostPart}:$Port" }
            $out = Invoke-LabTcpExchange -Target $Target -Port $Port -Timeout $Timeout `
                -Send "GET $Path HTTP/1.0`r`nHost: $authority`r`nConnection: close`r`n`r`n"
            if (-not $out) { return 'fail no HTTP response' }
            if ($out -notmatch '^HTTP/[0-9.]+ ([0-9]{3})') { return 'fail not an HTTP response' }
            $code = $Matches[1]
            $separator = $out.IndexOf("`r`n`r`n")
            $separatorLength = 4
            if ($separator -lt 0) { $separator = $out.IndexOf("`n`n"); $separatorLength = 2 }
            if ($separator -lt 0) { return 'fail incomplete HTTP headers' }
            return Get-LabHttpResult $code ($out.Substring($separator + $separatorLength)) $Expect
        }
        'https' {
            $tool = Get-Command curl.exe -CommandType Application -ErrorAction SilentlyContinue  # lab-guard: allow network -- only checks whether curl.exe is installed
            if (-not $tool) { return 'unknown no tool on this host can probe https' }
            $saved = $ErrorActionPreference
            $savedEncoding = [Console]::OutputEncoding
            $ErrorActionPreference = 'Continue'
            try {
                [Console]::OutputEncoding = [Text.Encoding]::UTF8
                $out = @(& $tool.Source -q -sS --globoff --noproxy '*' --max-time $Timeout --max-filesize 65536 -w '\n%{http_code}' -- "https://${hostPart}:$Port$Path" 2>$null)
                $rc = $LASTEXITCODE
            } finally {
                [Console]::OutputEncoding = $savedEncoding
                $ErrorActionPreference = $saved
            }
            if ($rc -ne 0 -or $out.Count -eq 0) { return "fail the https client exited $rc" }
            return Get-LabHttpResult $out[-1] (($out | Select-Object -SkipLast 1) -join "`n") $Expect
        }
        'dns' {
            if ($Port -ne 53) { return 'unknown Windows can only query DNS on port 53' }
            if (-not (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) { return 'unknown no Resolve-DnsName on this host' }
            $qname, $answer = $Expect -split '=', 2
            $expectedAddress = $null
            if (-not [Net.IPAddress]::TryParse($answer, [ref]$expectedAddress)) { return 'fail invalid DNS address' }
            $type = if ($answer.Contains(':')) { 'AAAA' } else { 'A' }
            try {
                $records = @(Resolve-DnsName -Name $qname -Server $Target -Type $type -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop)
            } catch {
                return "fail no answer from $Target"
            }
            foreach ($r in $records) {
                $p = $r.PSObject.Properties['IPAddress']
                $actualAddress = $null
                if ($p -and [Net.IPAddress]::TryParse([string]$p.Value, [ref]$actualAddress) -and $actualAddress.Equals($expectedAddress)) {
                    return "pass $qname answered $answer"
                }
            }
            return "fail $qname did not answer $answer"
        }
        'tcp' {
            if ($Expect -eq '-') {
                if ($null -ne (Invoke-LabTcpExchange -Target $Target -Port $Port -Timeout $Timeout -ConnectOnly)) { return 'pass connected' }
                return 'fail no connection'
            }
        }
    }
    $prefix = @{ smtp = '220'; pop3 = '+OK'; imap = '* OK'; ftp = '220'; tcp = '' }
    if (-not $prefix.ContainsKey($Proto)) { return "unknown unsupported protocol $Proto" }
    $banner = Invoke-LabTcpExchange -Target $Target -Port $Port -Timeout $Timeout -FirstLine -Quit $(if ($Proto -eq 'imap') { 'a1 LOGOUT' } else { 'QUIT' })
    if (-not $banner) { return 'fail no banner' }
    if ($prefix[$Proto] -ne '' -and -not $banner.StartsWith($prefix[$Proto])) { return 'fail unexpected banner' }
    if ($Expect -ne '-' -and -not $banner.Contains($Expect)) { return 'fail the banner lacks the expected text' }
    return 'pass banner received'
}
