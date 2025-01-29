$Error.Clear()
$ErrorActionPreference = "Continue"


Write-Output "#########################"
Write-Output "#                       #"
Write-Output "#         Hard          #"
Write-Output "#                       #"
Write-Output "#########################"


Write-Output "#########################"
Write-Output "#    Hostname/Domain    #"
Write-Output "#########################"
Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select-Object Name, Domain
Write-Output "#########################"
Write-Output "#          IP           #"
Write-Output "#########################"
Get-WmiObject Win32_NetworkAdapterConfiguration | ? {$_.IpAddress -ne $null} | % {$_.ServiceName + "`n" + $_.IPAddress + "`n"}

$DC = $false
if (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'") {
    $DC = $true
    Import-Module ActiveDirectory
}

# Disable storage of the LM hash for passwords less than 15 characters
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLmHash /t REG_DWORD /d 1 /f | Out-Null
# https://learn.microsoft.com/en-us/troubleshoot/windows-client/windows-security/enable-ntlm-2-authentication
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f | Out-Null
# Disable storage of plaintext creds in WDigest
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null
# Enable remote UAC for Local accounts
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f | Out-Null
# Enable LSASS Protection
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f | Out-Null
# Enable LSASSS process auditing
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 8 /f | Out-Null
Write-Output "$Env:ComputerName [INFO] PTH Mitigation complete"
######### Defender #########

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 3 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DisableBlockAtFirstSeen /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v MpCloudBlockLevel /t REG_DWORD /d 6 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v "ForceDefenderPassiveMode" /t REG_DWORD /d 0 /f | Out-Null
Write-Output "$Env:ComputerName [INFO] Set Defender options" 

try {
    # Block Office applications from injecting code into other processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block Office applications from creating executable content
    Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block all Office applications from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EfC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block JavaScript or VBScript from launching downloaded executable content
    Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block execution of potentially obfuscated scripts
    Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block executable content from email client and webmail
    Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block Win32 API calls from Office macro
    Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block process creations originating from PSExec and WMI commands
    Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block untrusted and unsigned processes that run from USB
    Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Use advanced protection against ransomware
    Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block executable files from running unless they meet a prevalence, age, or trusted list criterion
    Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block credential stealing from the Windows local security authority subsystem (lsass.exe)
    Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block Office communication application from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49E8-8B27-EB1D0A1CE869 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block Adobe Reader from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block persistence through WMI event subscription
    Add-MpPreference -AttackSurfaceReductionRules_Ids E6DB77E5-3DF2-4CF1-B95A-636979351E5B -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    Write-Output "$Env:ComputerName [INFO] Defender Attack Surface Reduction rules enabled" 
    ForEach ($ExcludedASR in (Get-MpPreference).AttackSurfaceReductionOnlyExclusions) {
        Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $ExcludedASR | Out-Null
    }
}
catch {
    Write-Output "$Env:ComputerName [INFO] Old defender version detected, skipping ASR rules" 
}
ForEach ($ExcludedExt in (Get-MpPreference).ExclusionExtension) {
    Remove-MpPreference -ExclusionExtension $ExcludedExt | Out-Null
}
ForEach ($ExcludedIp in (Get-MpPreference).ExclusionIpAddress) {
    Remove-MpPreference -ExclusionIpAddress $ExcludedIp | Out-Null
}
ForEach ($ExcludedDir in (Get-MpPreference).ExclusionPath) {
    Remove-MpPreference -ExclusionPath $ExcludedDir | Out-Null
}
ForEach ($ExcludedProc in (Get-MpPreference).ExclusionProcess) {
    Remove-MpPreference -ExclusionProcess $ExcludedProc | Out-Null
}
Write-Output "$Env:ComputerName [INFO] Defender exclusions removed" 
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 5 /f | Out-Null

######### Service Lockdown #########
# RDP NLA
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-TCP" /v UserAuthentication /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f | Out-Null

if ($DC) {
    # Add-ADGroupMember -Identity "Protected Users" -Members "Domain Users"
    # CVE-2020-1472 (Zerologon)
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f | Out-Null
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "vulnerablechannelallowlist" -Force | Out-Null
    # CVE-2021-42278 & CVE-2021-42287 (noPac)
    Set-ADDomain -Identity $env:USERDNSDOMAIN -Replace @{"ms-DS-MachineAccountQuota"="0"} | Out-Null
}

if ($IIS) {
    <#
    if (!($Exchange)) {
        foreach ($app in (Get-ChildItem IIS:\AppPools)) {
            C:\Windows\System32\inetsrv\appcmd.exe set config -section:system.applicationHost/applicationPools "/[name='$($app.name)'].processModel.identityType:`"ApplicationPoolIdentity`"" /commit:apphost
        }            
        foreach ($site in (Get-ChildItem IIS:\Sites)) {
            C:\Windows\System32\inetsrv\appcmd.exe set config $site.name -section:system.webServer/directoryBrowse /enabled:"False"
            C:\Windows\System32\inetsrv\appcmd.exe set config $site.name -section:system.webServer/serverRuntime /authenticatedUserOverride:"UseAuthenticatedUser"  /commit:apphost
        }
    }
    #>
    foreach ($site in (Get-ChildItem IIS:\Sites)) {
        C:\Windows\System32\inetsrv\appcmd.exe set config $site.name -section:system.webServer/directoryBrowse /enabled:"False"
    } 
}

net stop spooler | Out-Null
sc.exe config spooler start=disabled | Out-Null
Write-Output "$Env:ComputerName [INFO] Services locked down" 

# CVE-2021-34527 (PrintNightmare)
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v RegisterSpoolerRemoteRpcEndPoint /t REG_DWORD /d 2 /f | Out-Null
# Network security: LDAP client signing requirements
# reg add "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 2 /f | Out-Null
# reg add "HKCU\Software\Policies\Microsoft\Windows\System" /v DisableCMD /t REG_DWORD /d 1 /f | Out-Null
# Disable BITS transfers
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v EnableBITSMaxBandwidth /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v MaxDownloadTime /t REG_DWORD /d 1 /f | Out-Null
Write-Output "$Env:ComputerName [INFO] BITS locked down"
# UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f | Out-Null
Write-Output "$Env:ComputerName [INFO] UAC enabled"

######### Constrained Language Mode #########
[System.Environment]::SetEnvironmentVariable('__PSLockDownPolicy','4','Machine')

$Error | Out-File $env:USERPROFILE\Desktop\hard.txt -Append -Encoding utf8