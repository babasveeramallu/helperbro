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
