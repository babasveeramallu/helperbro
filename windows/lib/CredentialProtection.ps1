function Protect-CCDCCredential {
    param([Parameter(Mandatory)][securestring]$Password)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Credential protection requires Windows DPAPI.'
    }
    'dpapi:' + (ConvertFrom-SecureString -SecureString $Password)
}

function Unprotect-CCDCCredential {
    param([Parameter(Mandatory)][string]$Text)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Credential protection requires Windows DPAPI.'
    }
    if (-not $Text.StartsWith('dpapi:')) {
        throw 'Credential is not DPAPI-protected. Older credential files are insecure; handle and remove them securely.'
    }
    try {
        ConvertTo-SecureString -String $Text.Substring(6) -ErrorAction Stop
    } catch {
        throw 'Cannot decrypt credential with this Windows user profile on this machine.'
    }
}
