$Error.Clear()
$ErrorActionPreference = "Continue"

function Write-ColorOutput($ForegroundColor, $Message) {
    $originalColor = $host.UI.RawUI.ForegroundColor  # Save the current color

    $host.UI.RawUI.ForegroundColor = $ForegroundColor  # Set the new color

    if ($null -ne $Message) {
        Write-Output $Message
    }
    else {
        $input | Write-Output
    }

    $host.UI.RawUI.ForegroundColor = $originalColor  # Restore the original color
}

Write-ColorOutput Green "------------- SMB -------------"

$osVersion = (Get-WmiObject -class Win32_OperatingSystem).Caption

# Get and display computer system information
Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select-Object Name, Domain

# Get and display network adapter information
Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IpAddress -ne $null} | ForEach-Object {$_.ServiceName + "`n-----------`n" + $_.IPAddress + "`n"}

# Manage shares
net share C$ /delete | Out-Null
net share ADMIN$ /delete | Out-Null
net share

# Security Signature - ADD TO THIS
reg add "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f | Out-Null

# Hardening - ADD TO THIS
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v RejectUnencryptedAccess /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AnnounceServer /t REG_DWORD /d 0 /f | Out-Null

#region Patch EternalBlue

try{
    if ((Read-Host "Type `"blue`" to leave SMB1 enabled:") -eq "blue") {
        Write-Output "SMB1 is required. Downloading EternalBlue patch..."
        try {
            # FIX FOR COMPATIBILIY
            $patchURL = switch -Regex ($osVersion) {
                '(?i)Vista'  { "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.0-kb4012598-x64_6a186ba2b2b98b2144b50f88baf33a5fa53b5d76.msu" }
                'Windows 7'  { "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.1-kb4012212-x64_2decefaa02e2058dcd965702509a992d8c4e92b3.msu" }
                'Windows 8'  { "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8.1-kb4012213-x64_5b24b9ca5a123a844ed793e0f2be974148520349.msu" }
                '2008 R2'    { "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.1-kb4012212-x64_2decefaa02e2058dcd965702509a992d8c4e92b3.msu" }
                '2008'       { "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.0-kb4012598-x64_6a186ba2b2b98b2144b50f88baf33a5fa53b5d76.msu" }
                '2012 R2'    { "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8.1-kb4012213-x64_5b24b9ca5a123a844ed793e0f2be974148520349.msu" }
                '2012'       { "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8-rt-kb4012214-x64_b14951d29cb4fd880948f5204d54721e64c9942b.msu"}
                default { throw "Unsupported OS version: $osVersion" }
            }

            $path = "$env:TEMP\eternalblue_patch.msu"
            Write-Output "Grabbing the patch file. Downloading it to $path"

            $wc = New-Object net.webclient
            $wc.Downloadfile($patchURL, $path)

            # Install the patch
            Start-Process -Wait -FilePath "wusa.exe" -ArgumentList "$path /quiet /norestart"

            # Cleanup
            Remove-Item -Path $path -Force

            #Reenable SMB1 if was disabled earlier
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 1 /f | Out-Null
            reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v SMB1 /t REG_DWORD /d 1 /f | Out-Null

            Write-ColorOutput Green "EternalBlue patched! Good luck!"

        } catch {
            Write-ColorOutput Red "$_.Exception.Message"
            break
        }
    }
    else{
        throw "Disabling SMB1"
    }
}
catch{
    Write-ColorOutput Green "$($_.Exception.Message)"

    # Disable SMB1
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v SMB1 /t REG_DWORD /d 0 /f | Out-Null

    # Minimum SMB version
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB2 /t REG_DWORD /d 2 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v SMB2 /t REG_DWORD /d 2 /f | Out-Null

    Write-ColorOutput Green "SMB1 disabled"
}
#endregion

Write-Output "$Env:ComputerName SMB secured."