#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('ccdc-probe-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $fixture 'windows'), (Join-Path $fixture 'vendor\labyrinth\core\probe') -Force | Out-Null
$job = $null
try {
    Copy-Item (Join-Path $PSScriptRoot 'Invoke-ServiceProbe.ps1') (Join-Path $fixture 'windows')
    $module = Join-Path $PSScriptRoot '..\vendor\labyrinth\core\probe\Probe.ps1'
    Copy-Item $module (Join-Path $fixture 'vendor\labyrinth\core\probe')
    Add-Content -LiteralPath (Join-Path $fixture 'vendor\labyrinth\core\probe\Probe.ps1') -Value @'
function Invoke-LabProbe {
    param($Proto,$Target,$Port,$Expect,$Path,$Timeout)
    switch ($Target) {
        'pass.test' { 'pass mocked' }
        'fail.test' { 'fail mocked' }
        'unknown.test' { 'unknown mocked' }
        default { throw 'Unexpected network request' }
    }
}
'@
    $shell = (Get-Process -Id $PID).Path
    $probe = Join-Path $fixture 'windows\Invoke-ServiceProbe.ps1'
    foreach ($case in @(
        @{ Name='pass'; Target='pass.test'; Code=0; Text='pass mocked' }
        @{ Name='fail'; Target='fail.test'; Code=1; Text='fail mocked' }
        @{ Name='unknown'; Target='unknown.test'; Code=2; Text='unknown mocked' }
        @{ Name='invalid target'; Target='-bad'; Code=1; Text='Invalid target' }
    )) {
        $ErrorActionPreference = 'Continue'
        try {
            $out = & $shell -NoProfile -File $probe -Protocol tcp -Target $case.Target -Port 1234 2>&1 | Out-String
            $code = $LASTEXITCODE
        } finally { $ErrorActionPreference = 'Stop' }
        if ($code -ne $case.Code -or $out -notmatch [regex]::Escape($case.Text)) {
            throw "FAIL $($case.Name): exit=$code output=$out"
        }
        Write-Host "PASS $($case.Name)"
    }
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $shell -NoProfile -File $probe -Protocol dns -Target pass.test -Port 53 -Expect malformed 2>&1 | Out-String
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = 'Stop' }
    if ($code -eq 0 -or $out -notmatch 'DNS requires') { throw "FAIL invalid DNS: $out" }
    $out = & $shell -NoProfile -File $probe -Protocol dns -Target pass.test -Port 53 -Expect 'example.test=192.0.2.10' 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or $out -notmatch 'pass mocked') { throw "FAIL valid DNS: $out" }
    foreach ($case in @(
        @{ Name='zero port'; Args=@('-Protocol','tcp','-Target','pass.test','-Port','0'); Text='Port' }
        @{ Name='port above range'; Args=@('-Protocol','tcp','-Target','pass.test','-Port','65536'); Text='Port' }
        @{ Name='zero timeout'; Args=@('-Protocol','tcp','-Target','pass.test','-Port','1','-Timeout','0'); Text='Timeout' }
        @{ Name='timeout above range'; Args=@('-Protocol','tcp','-Target','pass.test','-Port','1','-Timeout','31'); Text='Timeout' }
        @{ Name='unsupported protocol'; Args=@('-Protocol','ssh','-Target','pass.test','-Port','22'); Text='Protocol' }
        @{ Name='invalid path'; Args=@('-Protocol','http','-Target','pass.test','-Port','80','-Path','health'); Text='Invalid HTTP path' }
        @{ Name='injected expectation'; Args=@('-Protocol','tcp','-Target','pass.test','-Port','1','-Expect',"ok`r`ninjected"); Text='Invalid expected text' }
        @{ Name='invalid DNS address'; Args=@('-Protocol','dns','-Target','pass.test','-Port','53','-Expect','example.test=999.1.1.1'); Text='DNS requires' }
    )) {
        $ErrorActionPreference = 'Continue'
        try {
            $out = & $shell -NoProfile -File $probe @($case.Args) 2>&1 | Out-String
            $code = $LASTEXITCODE
        } finally { $ErrorActionPreference = 'Stop' }
        if ($code -eq 0 -or $out -notmatch [regex]::Escape($case.Text)) { throw "FAIL $($case.Name): exit=$code output=$out" }
    }
    foreach ($port in @(1, 65535)) {
        $out = & $shell -NoProfile -File $probe -Protocol tcp -Target pass.test -Port $port -Timeout 30 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0 -or $out -notmatch 'pass mocked') { throw "FAIL valid port ${port}: $out" }
    }
    . $module
    function Invoke-LabTcpExchange {
        param($Target,$Port,$Timeout,$Send,[switch]$FirstLine,$Quit,[switch]$ConnectOnly)
        if ($FirstLine) { return '220 mail.example.test' }
        $script:ProbeRequest = $Send
        return "HTTP/1.0 200 OK`r`n`r`nWelcome"
    }
    function Resolve-DnsName {
        param($Name,$Server,$Type,[switch]$DnsOnly,[switch]$QuickTimeout,$ErrorAction)
        [pscustomobject]@{ IPAddress = '192.0.2.10' }
    }
    if ((Invoke-LabProbe -Proto http -Target example.test -Port 80 -Expect Welcome) -ne 'pass status 200') { throw 'FAIL HTTP response' }
    if ((Invoke-LabProbe -Proto http -Target example.test -Port 80 -Expect Missing) -notlike 'fail *') { throw 'FAIL HTTP content' }
    if ((Invoke-LabProbe -Proto http -Target '::1' -Port 8080 -Expect Welcome) -ne 'pass status 200' -or
        $script:ProbeRequest -notmatch 'Host: \[::1\]:8080') { throw 'FAIL HTTP host header' }
    if ((Invoke-LabProbe -Proto smtp -Target example.test -Port 25 -Expect '-') -ne 'pass banner received') { throw 'FAIL SMTP banner' }
    if ((Invoke-LabProbe -Proto dns -Target example.test -Port 53 -Expect 'example.test=192.0.2.10') -notlike 'pass *') { throw 'FAIL DNS answer' }
    if ((Invoke-LabProbe -Proto dns -Target example.test -Port 53 -Expect 'example.test=192.0.2.11') -notlike 'fail *') { throw 'FAIL DNS mismatch' }
    if ((Invoke-LabProbe -Proto dns -Target example.test -Port 54 -Expect 'example.test=192.0.2.10') -notlike 'unknown *') { throw 'FAIL unsupported DNS port' }
    Write-Host 'PASS DNS validation and answers, HTTP response and SMTP banner'

    function Assert-ProbeResult($Name, $Actual, $Expected) {
        if ($Actual -cne $Expected) { throw "FAIL ${Name}: expected '$Expected', got '$Actual'" }
    }
    foreach ($case in @(
        @{ Code='199'; Expected='fail status 199' }
        @{ Code='200'; Expected='pass status 200' }
        @{ Code='299'; Expected='pass status 299' }
        @{ Code='300'; Expected='pass status 300' }
        @{ Code='399'; Expected='pass status 399' }
        @{ Code='400'; Expected='fail status 400' }
    )) {
        Assert-ProbeResult "HTTP status $($case.Code)" (Get-LabHttpResult $case.Code 'Welcome' '-') $case.Expected
    }
    Assert-ProbeResult 'HTTP missing text' (Get-LabHttpResult '200' 'Welcome' 'welcome') 'fail status 200 but the expected text is missing'

    function Invoke-LabTcpExchange {
        param($Target,$Port,$Timeout,$Send,[switch]$FirstLine,$Quit,[switch]$ConnectOnly)
        $script:ProbeRequest = $Send
        $script:ProbeQuit = $Quit
        if ($ConnectOnly) { return $script:ConnectResult }
        if ($FirstLine) { return $script:Banner }
        return $script:HttpResponse
    }
    $script:HttpResponse = $null
    Assert-ProbeResult 'empty HTTP' (Invoke-LabProbe -Proto http -Target example.test -Port 80 -Expect '-') 'fail no HTTP response'
    $script:HttpResponse = 'not HTTP'
    Assert-ProbeResult 'malformed HTTP' (Invoke-LabProbe -Proto http -Target example.test -Port 80 -Expect '-') 'fail not an HTTP response'
    $script:HttpResponse = "HTTP/1.0 302 Found`r`n`r`nMoved"
    Assert-ProbeResult 'redirect status' (Invoke-LabProbe -Proto http -Target example.test -Port 80 -Expect Moved -Path '/health') 'pass status 302'
    if ($script:ProbeRequest -cne "GET /health HTTP/1.0`r`nHost: example.test`r`nConnection: close`r`n`r`n") { throw 'FAIL HTTP request' }
    foreach ($case in @(
        @{ Proto='smtp'; Banner='220 ready'; Quit='QUIT' }
        @{ Proto='ftp'; Banner='220 ready'; Quit='QUIT' }
        @{ Proto='pop3'; Banner='+OK ready'; Quit='QUIT' }
        @{ Proto='imap'; Banner='* OK ready'; Quit='a1 LOGOUT' }
        @{ Proto='tcp'; Banner='custom ready'; Quit='QUIT' }
    )) {
        $script:Banner = $case.Banner
        Assert-ProbeResult "$($case.Proto) banner" (Invoke-LabProbe -Proto $case.Proto -Target example.test -Port 1234 -Expect ready) 'pass banner received'
        if ($script:ProbeQuit -cne $case.Quit) { throw "FAIL $($case.Proto) close command" }
        Assert-ProbeResult "$($case.Proto) missing text" (Invoke-LabProbe -Proto $case.Proto -Target example.test -Port 1234 -Expect missing) 'fail the banner lacks the expected text'
    }
    $script:Banner = '500 rejected'
    Assert-ProbeResult 'bad SMTP banner' (Invoke-LabProbe -Proto smtp -Target example.test -Port 25 -Expect '-') 'fail unexpected banner'
    $script:Banner = $null
    Assert-ProbeResult 'empty banner' (Invoke-LabProbe -Proto smtp -Target example.test -Port 25 -Expect '-') 'fail no banner'
    $script:ConnectResult = ''
    Assert-ProbeResult 'TCP connected' (Invoke-LabProbe -Proto tcp -Target example.test -Port 1234 -Expect '-') 'pass connected'
    $script:ConnectResult = $null
    Assert-ProbeResult 'TCP connection failure' (Invoke-LabProbe -Proto tcp -Target example.test -Port 1234 -Expect '-') 'fail no connection'
    Assert-ProbeResult 'unsupported protocol' (Invoke-LabProbe -Proto bogus -Target example.test -Port 1234 -Expect '-') 'unknown unsupported protocol bogus'
    function Resolve-DnsName {
        param($Name,$Server,$Type,[switch]$DnsOnly,[switch]$QuickTimeout,$ErrorAction)
        $script:DnsType = $Type
        if ($script:DnsFails) { throw 'DNS failure' }
        [pscustomobject]@{ IPAddress = '2001:db8::1' }
    }
    $script:DnsFails = $false
    Assert-ProbeResult 'IPv6 DNS' (Invoke-LabProbe -Proto dns -Target example.test -Port 53 -Expect 'example.test=2001:db8::1') 'pass example.test answered 2001:db8::1'
    if ($script:DnsType -ne 'AAAA') { throw 'FAIL DNS record type' }
    $script:DnsFails = $true
    Assert-ProbeResult 'DNS error' (Invoke-LabProbe -Proto dns -Target example.test -Port 53 -Expect 'example.test=2001:db8::1') 'fail no answer from example.test'
    function Get-Command {
        param($Name, $CommandType, $ErrorAction)
        if ($Name -in @('curl.exe', 'Resolve-DnsName')) { return $null }
        Microsoft.PowerShell.Core\Get-Command @PSBoundParameters
    }
    Assert-ProbeResult 'missing HTTPS client' (Invoke-LabProbe -Proto https -Target example.test -Port 443 -Expect '-') 'unknown no tool on this host can probe https'
    Assert-ProbeResult 'missing DNS client' (Invoke-LabProbe -Proto dns -Target example.test -Port 53 -Expect 'example.test=192.0.2.10') 'unknown no Resolve-DnsName on this host'
    Remove-Item Function:\Get-Command
    Write-Host 'PASS HTTP boundaries, protocol banners, TCP and DNS errors'

    . $module
    foreach ($mode in @('complete', 'stall')) {
        $ready = Join-Path $fixture "$mode.ready"
        $job = Start-Job -ArgumentList $ready, $mode -ScriptBlock {
            param($Ready, $Mode)
            $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
            try {
                $listener.Start()
                [IO.File]::WriteAllText($Ready, [string]$listener.LocalEndpoint.Port)
                $client = $listener.AcceptTcpClient()
                try {
                    $client.ReceiveTimeout = 3000
                    $reader = New-Object IO.StreamReader($client.GetStream())
                    while (($line = $reader.ReadLine()) -ne '' -and $null -ne $line) {}
                    $bytes = [Text.Encoding]::ASCII.GetBytes("HTTP/1.0 200 OK`r`n`r`nWelcome")
                    $client.GetStream().Write($bytes, 0, $bytes.Length)
                    if ($Mode -eq 'stall') { Start-Sleep -Seconds 5 }
                } finally { $client.Close() }
            } finally { $listener.Stop() }
        }
        $deadline = (Get-Date).AddSeconds(15)
        while (-not (Test-Path -LiteralPath $ready) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 100 }
        if (-not (Test-Path -LiteralPath $ready)) { throw "FAIL $mode server did not start" }
        $port = [int](Get-Content -LiteralPath $ready)
        $result = Invoke-LabProbe -Proto http -Target '127.0.0.1' -Port $port -Expect Welcome -Timeout 2
        if (($mode -eq 'complete' -and $result -ne 'pass status 200') -or
            ($mode -eq 'stall' -and $result -notlike 'fail *')) { throw "FAIL $mode loopback: $result" }
        Stop-Job -Job $job
        Remove-Job -Job $job
        $job = $null
        Write-Host "PASS $mode loopback"
    }
} finally {
    if ($job) { Stop-Job -Job $job; Remove-Job -Job $job }
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
