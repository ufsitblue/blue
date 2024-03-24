param(
    [Parameter(Mandatory=$false)]
    [String]$Hosts = '',

    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Cred = $Global:Cred,

    [Parameter(Mandatory=$false)]
    [Int]$Timeout = 3000,

    [Parameter(Mandatory=$false)]
    [Switch]$Purge
)
function Test-Port {
    Param(
        [string]$Ip,
        [int]$Port = 445,
        [int]$Timeout = 3000,
        [switch]$Verbose
    )

    $ErrorActionPreference = "SilentlyContinue"

    $tcpclient = New-Object System.Net.Sockets.TcpClient
    $iar = $tcpclient.BeginConnect($ip,$port,$null,$null)
    $wait = $iar.AsyncWaitHandle.WaitOne($timeout,$false)
    if (!$wait)
    {
        # Close the connection and report timeout
        $tcpclient.Close()
        if($verbose){Write-Host "[ERROR] $($IP):$Port Connection Timeout " -ForegroundColor Red}
        return $false
    } 
    else {
        # Close the connection and report the error if there is one
        $error.Clear()
        $tcpclient.EndConnect($iar) | out-Null
        if(!$?){if($verbose){write-host $error[0] -ForegroundColor Red};$failed = $true}
        $tcpclient.Close()
    }

    if ($failed) {
        return $false
    }
    else {
        return $true
    }
}


if (!$Purge -and $Hosts -ne '' -and $Cred -ne $null) {
    try {
        $Computers = Get-Content $Hosts
    }
    catch {
        Write-Host "[ERROR] Failed to get computers from file" -ForegroundColor Red
        exit
    }
    
    $DriveLetters = @()
    $DriveLetters = 65..90 | %{[char]$_}
    $i = 25
    
    foreach ($Computer in $Computers) {
        if ($i -ge 0) {
            if (Test-Port -Ip $Computer -Timeout $Timeout -Verbose) {
                Write-Host "[INFO] $Computer SMB is online... Copying" -ForegroundColor Green
                New-PSDrive -Name $DriveLetters[$i] -PSProvider FileSystem -Root \\$Computer\C$ -Persist -Credential $Cred
                Robocopy.exe .\bins \\$Computer\C$\Windows\System32\ /COMPRESS /MT:16 /R:1 /W:1 /UNILOG+:robo.log /TEE /s /xx
            }
            else {
                Write-Host "[ERROR] Failed to move bins to $Computer" -ForegroundColor Red
                Write-Output "$Computer [ERROR] Failed to move bins" | Out-File .\robo_fail.log -Append
            }
            $i--
        }
    }
    Write-Host "[INFO] Done... Listing Errors" -ForegroundColor Green
    Get-Content .\robo.log | ? {$_ -match "ERROR"} | % {Write-Host $_ -ForegroundColor Red}
}
elseif ($Purge) {
    Get-PSDrive | ? {$_.DisplayRoot -ne $null} | Remove-PSDrive
    Write-Host "[INFO] Purged all drives" -ForegroundColor Yellow
}
elseif ($Hosts -eq '') {
    Write-Host "[ERROR] No hosts file specified" -ForegroundColor Red
}
elseif ($Cred -eq $null) {
    Write-Host "[ERROR] No credentials specified" -ForegroundColor Red
}
else {
    Write-Host "[ERROR] Unknown error" -ForegroundColor Red
}
