function Set-CCDCAccountPolicy {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][bool]$IsDomainJoined,
        [Parameter(Mandatory)][string]$ReportDirectory,
        [switch]$EnableAccountLockout,
        [ValidateRange(1,999)][int]$LockoutThreshold = 5,
        [ValidateRange(1,99999)][int]$LockoutDurationMinutes = 30,
        [ValidateRange(1,99999)][int]$LockoutObservationWindowMinutes = 30
    )
    if (-not $EnableAccountLockout -and @('LockoutThreshold','LockoutDurationMinutes','LockoutObservationWindowMinutes' |
        Where-Object { $PSBoundParameters.ContainsKey($_) }).Count) {
        throw 'Lockout parameters require -EnableAccountLockout.'
    }
    if ($EnableAccountLockout -and $LockoutObservationWindowMinutes -gt $LockoutDurationMinutes) {
        throw 'Lockout observation window cannot exceed lockout duration; no policy changed.'
    }
    $maxAge = New-TimeSpan -Days 60
    if ($EnableAccountLockout) {
        Write-Log FLAG "Account lockout opted in: threshold=$LockoutThreshold duration=$LockoutDurationMinutes minutes window=$LockoutObservationWindowMinutes minutes. Attackers can deliberately lock service/scoring accounts and deny service."
    } else { Write-Log INFO 'Account lockout not selected; existing threshold, duration and observation window will be preserved.' }
    if ($IsDomainJoined) {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) { throw 'Domain-joined host needs RSAT ActiveDirectory tools to set the domain policy; local net accounts would not enforce domain users.' }
        Import-Module ActiveDirectory -ErrorAction Stop
        $domain = Get-ADDomain -ErrorAction Stop
        $before = Get-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -ErrorAction Stop
        Write-Log INFO "Domain policy target=$($domain.DNSRoot); current min=$($before.MinPasswordLength) history=$($before.PasswordHistoryCount) maxAge=$($before.MaxPasswordAge) lockThreshold=$($before.LockoutThreshold)"
        if ($PSCmdlet.ShouldProcess("Default domain policy $($domain.DNSRoot)", "Set password policy; configure lockout=$EnableAccountLockout")) {
            $parameters = @{
                Identity=$domain.DNSRoot; MinPasswordLength=8; ComplexityEnabled=$true
                PasswordHistoryCount=5; MaxPasswordAge=$maxAge; ErrorAction='Stop'
            }
            if ($EnableAccountLockout) {
                $parameters.LockoutThreshold=$LockoutThreshold
                $parameters.LockoutDuration=New-TimeSpan -Minutes $LockoutDurationMinutes
                $parameters.LockoutObservationWindow=New-TimeSpan -Minutes $LockoutObservationWindowMinutes
            }
            Set-ADDefaultDomainPasswordPolicy @parameters
            $after = Get-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -ErrorAction Stop
            if ($after.MinPasswordLength -ne 8 -or -not $after.ComplexityEnabled -or $after.PasswordHistoryCount -ne 5 -or $after.MaxPasswordAge.TotalDays -ne 60) { throw 'Domain policy verification failed.' }
            $expectedThreshold = if ($EnableAccountLockout) { $LockoutThreshold } else { $before.LockoutThreshold }
            $expectedDuration = if ($EnableAccountLockout) { New-TimeSpan -Minutes $LockoutDurationMinutes } else { $before.LockoutDuration }
            $expectedWindow = if ($EnableAccountLockout) { New-TimeSpan -Minutes $LockoutObservationWindowMinutes } else { $before.LockoutObservationWindow }
            if ($after.LockoutThreshold -ne $expectedThreshold -or $after.LockoutDuration -ne $expectedDuration -or $after.LockoutObservationWindow -ne $expectedWindow) { throw 'Domain lockout policy verification failed.' }
            Write-Log CHANGE "Set and verified default domain password policy for $($domain.DNSRoot)."
        }
        return
    }

    $net = Get-Command net.exe -ErrorAction SilentlyContinue
    $secedit = Get-Command secedit.exe -ErrorAction SilentlyContinue
    if (-not $net -or -not $secedit) { throw 'Standalone policy requires net.exe and secedit.exe; no account policy changed.' }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $template = Join-Path $ReportDirectory "account-policy-$stamp.inf"
    $backup = Join-Path $ReportDirectory "account-policy-before-$stamp.inf"
    $db = Join-Path $ReportDirectory "account-policy-$stamp.sdb"
    & $secedit.Source /export /cfg $template /areas SECURITYPOLICY | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $template)) { throw 'secedit export failed; no account policy changed.' }
    Copy-Item -LiteralPath $template -Destination $backup -Force
    $text = Get-Content -LiteralPath $template -Raw
    if ($text -notmatch '(?m)^\[System Access\]\s*$') { throw 'Exported security template has no [System Access] section; refusing edit.' }
    $settings = [ordered]@{ MinimumPasswordLength = 8; PasswordHistorySize = 5; MaximumPasswordAge = 60; PasswordComplexity = 1 }
    $section = [regex]::Match($text, '(?ms)^\[System Access\]\r?\n.*?(?=^\[|\z)').Value
    $expectedLockout = @{}
    foreach ($key in @('LockoutBadCount','ResetLockoutCount','LockoutDuration')) {
        $match = [regex]::Match($section, "(?m)^\s*$key\s*=\s*(-?\d+)\s*$")
        if ($match.Success) { $expectedLockout[$key] = [int]$match.Groups[1].Value }
    }
    if ($EnableAccountLockout) {
        $settings.LockoutBadCount=$LockoutThreshold
        $settings.ResetLockoutCount=$LockoutObservationWindowMinutes
        $settings.LockoutDuration=$LockoutDurationMinutes
        foreach ($key in @('LockoutBadCount','ResetLockoutCount','LockoutDuration')) { $expectedLockout[$key]=$settings[$key] }
    }
    foreach ($key in $settings.Keys) {
        $line = "$key = $($settings[$key])"
        if ($section -match "(?m)^\s*$key\s*=.*$") { $section = [regex]::Replace($section, "(?m)^\s*$key\s*=.*$", $line) }
        else { $section = $section.TrimEnd("`r", "`n") + "`r`n$line`r`n" }
    }
    $text = [regex]::Replace($text, '(?ms)^\[System Access\]\r?\n.*?(?=^\[|\z)', [System.Text.RegularExpressions.MatchEvaluator]{ param($match) $section }, 1)
    Set-Content -LiteralPath $template -Value $text -Encoding Unicode
    if ($PSCmdlet.ShouldProcess('Local security policy', 'Apply secedit password complexity/history')) {
        & $secedit.Source /configure /db $db /cfg $template /areas SECURITYPOLICY /quiet | Out-Null
        if ($LASTEXITCODE -ne 0) {
            & $secedit.Source /configure /db (Join-Path $ReportDirectory "rollback-$stamp.sdb") /cfg $backup /areas SECURITYPOLICY /quiet | Out-Null
            throw "secedit configuration failed; attempted restore from $backup."
        }
        $netArguments = @('accounts','/minpwlen:8','/uniquepw:5','/maxpwage:60')
        if ($EnableAccountLockout) {
            $netArguments += @("/lockoutthreshold:$LockoutThreshold","/lockoutduration:$LockoutDurationMinutes","/lockoutwindow:$LockoutObservationWindowMinutes")
        }
        $netOutput = & $net.Source @netArguments 2>&1
        if ($LASTEXITCODE -ne 0) {
            & $secedit.Source /configure /db (Join-Path $ReportDirectory "rollback-$stamp.sdb") /cfg $backup /areas SECURITYPOLICY /quiet | Out-Null
            throw "net accounts failed: $netOutput; attempted secedit restore from $backup."
        }
        Write-Log CHANGE 'Applied local net accounts and secedit policy.'
        $netVerify = (& $net.Source accounts 2>&1 | ForEach-Object { "$_" }) -join [Environment]::NewLine
        $verifyTemplate = Join-Path $ReportDirectory "account-policy-verify-$stamp.inf"
        & $secedit.Source /export /cfg $verifyTemplate /areas SECURITYPOLICY | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'secedit verification export failed; inspect the current account policy.' }
        $verifyText = Get-Content -LiteralPath $verifyTemplate -Raw
        Write-Log INFO "net accounts verification:`n$netVerify"
        $lockoutMatches = $true
        $verifySection = [regex]::Match($verifyText, '(?ms)^\[System Access\]\r?\n.*?(?=^\[|\z)').Value
        foreach ($key in $expectedLockout.Keys) {
            $match = [regex]::Match($verifySection, "(?m)^\s*$key\s*=\s*(-?\d+)\s*$")
            if (-not $match.Success -or [int]$match.Groups[1].Value -ne $expectedLockout[$key]) { $lockoutMatches=$false }
        }
        if (-not $lockoutMatches -or $netVerify -notmatch 'Minimum password length:\s+8' -or $netVerify -notmatch 'Maximum password age \(days\):\s+60' -or $netVerify -notmatch 'Length of password history maintained:\s+5' -or $verifyText -notmatch '(?m)^PasswordComplexity\s*=\s*1') {
            & $secedit.Source /configure /db (Join-Path $ReportDirectory "rollback-verify-$stamp.sdb") /cfg $backup /areas SECURITYPOLICY /quiet | Out-Null
            throw "Local account policy verification failed; attempted restore from $backup. Inspect secedit export and net accounts output."
        }
        Write-Log CHANGE "Verified local password complexity/history and lockout settings (lockout opted in=$EnableAccountLockout)."
    }
}

