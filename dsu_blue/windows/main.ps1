

    net start mpssvc

    netsh advfirewall firewall set multicastbroadcastresponse disable
    netsh advfirewall firewall set multicastbroadcastresponse mode=disable profile=all

    netsh advfirewall set Domainprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
    netsh advfirewall set Domainprofile logging maxfilesize 20000
    netsh advfirewall set Privateprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
    netsh advfirewall set Privateprofile logging maxfilesize 20000
    netsh advfirewall set Publicprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
    netsh advfirewall set Publicprofile logging maxfilesize 20000
    netsh advfirewall set Publicprofile logging droppedconnections enable
    netsh advfirewall set Publicprofile logging allowedconnections enable
    netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
    netsh advfirewall set currentprofile logging maxfilesize 4096
    netsh advfirewall set currentprofile logging droppedconnections enable
    netsh advfirewall set currentprofile logging allowedconnections enable



    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

    reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V CreateEncryptedOnlyTickets /T REG_DWORD /D 1 /F 
    reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /V fDisableEncryption /T REG_DWORD /D 0 /F

    reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V fAllowFullControl /T REG_DWORD /D 0 /F
    reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V fAllowToGetHelp /T REG_DWORD /D 0 /F 
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /V AllowRemoteRPC /T REG_DWORD /D 0 /F 


    reg ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fResetBroken /t REG_DWORD /d 1 /F

    sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi 
    sc.exe config mrxsmb10 start= disabled
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart  
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force 


    Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 1 -Force

    net share C:\ /delete
    net share C:\Windows /delete

    #Remove all exclusions
    Set-MpPreference -ExclusionPath '<' -ExclusionProcess '<' -ExclusionExtension '<'
    Remove-MpPreference -ExclusionPath '<' -ExclusionProcess '<' -ExclusionExtension '<'

    #Select Default Action Array Action 3 = Remove
    Set-MpPreference -ThreatIDDefaultAction_Ids "0000000000" -ThreatIDDefaultAction_Actions "3"
    #Signature Scanning?
    Set-MpPreference -SignatureScheduleDay Everyday -SignatureScheduleTime 120 -CheckForSignaturesBeforeRunningScan $true -DisableArchiveScanning $false -DisableAutoExclusions $false -DisableBehaviorMonitoring $false -DisableBlockAtFirstSeen $false -DisableCatchupFullScan $false -DisableCatchupQuickScan $false -DisableEmailScanning $false -DisableIOAVProtection $false -DisableIntrusionPreventionSystem $false -DisablePrivacyMode $false -DisableRealtimeMonitoring $false -DisableRemovableDriveScanning $false -DisableRestorePoint $false -DisableScanningMappedNetworkDrivesForFullScan $false -DisableScanningNetworkFiles $false -DisableScriptScanning $false -HighThreatDefaultAction Remove -LowThreatDefaultAction Quarantine -MAPSReporting 0 -ModerateThreatDefaultAction Quarantine -PUAProtection Enabled -QuarantinePurgeItemsAfterDelay 1 -RandomizeScheduleTaskTimes $false -RealTimeScanDirection 0 -RemediationScheduleDay 0 -RemediationScheduleTime 100 -ReportingAdditionalActionTimeOut 5 -ReportingCriticalFailureTimeOut 6 -ReportingNonCriticalTimeOut 7 -ScanAvgCPULoadFactor 50 -ScanOnlyIfIdleEnabled $false -ScanPurgeItemsAfterDelay 15 -ScanScheduleDay 0 -ScanScheduleQuickScanTime 200 -ScanScheduleTime 200 -SevereThreatDefaultAction Remove -SignatureAuGracePeriod 30 -SignatureUpdateCatchupInterval 1 -SignatureUpdateInterval 1 -SubmitSamplesConsent 2 -UILockdown $false -UnknownThreatDefaultAction Quarantine -Force

    #Start Defender
    start-service WinDefend
    #Set Defender Policies
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableGenericRePorts" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingOverrideSpynetReporting" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d 0 /f

    reg ADD "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 5 /F

    #Start Windows Update Service and set startup type to auto
    Set-Service -Name wuauserv -StartupType Automatic -Status Running

    #Windows Update registry keys
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
    reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
    reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
    reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
    reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V IncludeRecommendedUpdates /T REG_DWORD /D 1 /F
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V ScheduledInstallTime /T REG_DWORD /D 22 /F

    #Automatic Updates for non-domain computers
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferFeatureUpdates" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferQualityUpdates" /t REG_DWORD /d 0 /f

    #Delete netlogon fullsecurechannelprotection then add a new key with it enabled
    Remove-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'FullSecureChannelProtection' -Force
    New-Item -path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'FullSecureChannelProtection' -Value 1 -ItemType "DWORD" -Force 

    #Disable the print spooler and make it never start
    Get-Service -Name Spooler | Stop-Service -Force
    Set-Service -Name Spooler -StartupType Disabled -Status Stopped

    #dism = Deployment Image Servicing and Management
    #disable insecure and unnecessary features
    dism /online /disable-feature /featurename:TFTP /NoRestart
    dism /online /disable-feature /featurename:TelnetClient /NoRestart
    dism /online /disable-feature /featurename:TelnetServer /NoRestart
    dism /online /disable-feature /featurename:"SMB1Protocol" /NoRestart
    
    #Disables editing registry remotely
    Get-Service -Name RemoteRegistry | Stop-Service -Force
    Set-Service -Name RemoteRegistry -StartupType Disabled -Status Stopped -Confirm $false
    
    #Disable Powershell Remoting
    Disable-PSRemoting -Force
    Get-Service -Name WinRM | Stop-Service -Force
    Set-Service -Name WinRM -StartupType Disabled -Status Stopped -Confirm $false

    #Removing all listeners for WS-Management service
    Remove-Item -Path WSMan:\Localhost\listener\listener* -Recurse
    #Require interactie logon for true admin connections (RDP, SSH, etc.)
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system -Name LocalAccountTokenFilterPolicy -Value 0

    #Remove all startup or shutdown scripts
    remove-item -Force 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*'
    remove-item -Force 'C:\autoexec.bat'
    remove-item -Force "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*"
    remove-item -Force "C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup"
    remove-item -Force "C:\Windows\System32\GroupPolicy\Machine\Scripts\Shutdown"
    remove-item -Force "C:\Windows\System32\GroupPolicy\User\Scripts\Logon"
    remove-item -Force "C:\Windows\System32\GroupPolicy\User\Scripts\Logoff"
    reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\Run /VA /F
    reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce /VA /F 
    reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /VA /F
    reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce /VA /F

    #Remove all custom password filters
    REG delete "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Notification Packages"  /f

    #Remove sticky keys
    reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /f
    TAKEOWN /F C:\Windows\System32\sethc.exe /A
    ICACLS C:\Windows\System32\sethc.exe /grant administrators:F
    del C:\Windows\System32\sethc.exe -Force

    #Delete utility manager (backdoor)
    TAKEOWN /F C:\Windows\System32\Utilman.exe /A
    ICACLS C:\Windows\System32\Utilman.exe /grant administrators:F
    del C:\Windows\System32\Utilman.exe -Force

    #Delete on screen keyboard (backdoor)
    TAKEOWN /F C:\Windows\System32\osk.exe /A
    ICACLS C:\Windows\System32\osk.exe /grant administrators:F
    del C:\Windows\System32\osk.exe -Force

    #Delete narrator (backdoor)
    TAKEOWN /F C:\Windows\System32\Narrator.exe /A
    ICACLS C:\Windows\System32\Narrator.exe /grant administrators:F
    del C:\Windows\System32\Narrator.exe -Force

    #Delete magnify (backdoor)
    TAKEOWN /F C:\Windows\System32\Magnify.exe /A
    ICACLS C:\Windows\System32\Magnify.exe /grant administrators:F
    del C:\Windows\System32\Magnify.exe -Force

    #Delete ScheduledTasks
    Get-ScheduledTask | Unregister-ScheduledTask -Confirm:$false
    
    #Disable Guest user
    net user Guest /active:no

    #Set Account Security Parameters
    net accounts /FORCELOGOFF:30 /MINPWLEN:8 /MAXPWAGE:30 /MINPWAGE:2 /UNIQUEPW:24 /lockoutwindow:30 /lockoutduration:30 /lockoutthreshold:30

    #Sets the current domain functional level to Windows2016Domain
    Set-ADDomainMode -identity $env:USERDNSDOMAIN -DomainMode Windows2016Domain
    #Get forest name
    $Forest = Get-ADForest
    #Sets the current forest functional level to Windows2016Forest
    Set-ADForestMode -Identity $Forest -Server $Forest.SchemaMaster -ForestMode Windows2016Forest 

    #Set Data Execution Prevention (DEP) to be always on
    bcdedit.exe /set "{current}" nx AlwaysOn

    #Make sure DEP is allowed (Triple Negative)
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d 0 /f

    #Only privileged groups can add or delete printer drivers
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f

    #Don't execute autorun commands
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f

    #Don't allow empty password login
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f

    #Only local sessions can control the CD/Floppy
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
    
    #Don't automatically logon as admin remotely
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f

    #Set audit policies
    #Enable logging for EVERYTHING
    auditpol /set /category:* /success:enable
    auditpol /set /category:* /failure:enable
    auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
    auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
    auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
    auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
    auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable
    auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
    auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
    auditpol /set /subcategory:"IPsec Main Mode" /success:enable /failure:enable
    auditpol /set /subcategory:"IPsec Quick Mode" /success:enable /failure:enable
    auditpol /set /subcategory:"IPsec Extended Mode" /success:enable /failure:enable
    auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
    auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
    auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:enable
    auditpol /set /subcategory:"User / Device Claims" /success:enable /failure:enable
    auditpol /set /subcategory:"Group Membership" /success:enable /failure:enable
    auditpol /set /subcategory:"File System" /success:enable /failure:enable
    auditpol /set /subcategory:"Registry" /success:enable /failure:enable
    auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable
    auditpol /set /subcategory:"SAM" /success:enable /failure:enable
    auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
    auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
    auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
    auditpol /set /subcategory:"File Share" /success:enable /failure:enable
    auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
    auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
    auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
    auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
    auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
    auditpol /set /subcategory:"Central Policy Staging" /success:enable /failure:enable
    auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
    auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:enable /failure:enable
    auditpol /set /subcategory:"Other Privilege Use Events" /success:enable /failure:enable
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
    auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
    auditpol /set /subcategory:"DPAPI Activity" /success:enable /failure:enable
    auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable
    auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:enable
    auditpol /set /subcategory:"Token Right Adjusted Events" /success:enable /failure:enable
    auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
    auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
    auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
    auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
    auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable
    auditpol /set /subcategory:"Other Policy Change Events" /success:enable /failure:enable
    auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
    auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
    auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
    auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable
    auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable
    auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable
    auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
    auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
    auditpol /set /subcategory:"Directory Service Replication" /success:enable /failure:enable
    auditpol /set /subcategory:"Detailed Directory Service Replication" /success:enable /failure:enable
    auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
    auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
    auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable
    auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable

    #Flush DNS Lookup Cache
    ipconfig /flushdns

    #Enable UAC popups if software trys to make changes
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f

    #Require admin authentication for operations that requires elevation of privileges
    reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V ConsentPromptBehaviorAdmin /T REG_DWORD /D 1 /F
    #Does not allow user to run elevates privileges
    reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V ConsentPromptBehaviorUser /T REG_DWORD /D 0 /F
    #Built-in administrator account is placed into Admin Approval Mode, admin approval is required for administrative tasks
    reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V FilterAdministratorToken /T REG_DWORD /D 1 /F
    #https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/932a34b5-48e7-44c0-b6d2-a57aadef1799
    #WHY?
    reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V EnableVirtualization /T REG_DWORD /D 1 /F 

    #Disable camera on lockscreen
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization /v NoLockScreenCamera /T REG_DWORD /D 1 /F
    #Sideshow will never start
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization /v NoLockScreenSlideshow /T REG_DWORD /D 1 /F
    #Don't allow speech services
    reg add HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization /v AllowInputPersonalization /T REG_DWORD /D 0 /F

    #Disable Multiple Avenues for Backdoors
    reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
    reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 122 /f
    reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f

    #Don't allow Windows Search and Cortana to search cloud sources (OneDrive, SharePoint, etc.)
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 0 /f
    #Disable Cortana
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
    #Disable Cortana when locked
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f
    #Disable location permissions for windows search
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
    #Don't let windows search the web
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
    #Don't let windows search the web
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f


    

    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
    reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /V HideFileExt /T REG_DWORD /D 0 /F
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\HideFileExt" /v "CheckedValue" /t REG_DWORD /d 0 /f
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /F




    if ((Get-WindowsFeature Web-Server).InstallState -eq "Installed") {

        Foreach($item in (Get-ChildItem IIS:\AppPools)) { $tempPath="IIS:\AppPools\"; $tempPath+=$item.name; Set-ItemProperty -Path $tempPath -name processModel.identityType -value 4}

        Foreach($item in (Get-ChildItem IIS:\Sites)) { $tempPath="IIS:\Sites\"; $tempPath+=$item.name; Set-WebConfigurationProperty -filter /system.webServer/directoryBrowse -name enabled -PSPath $tempPath -value False}

        Set-WebConfiguration //System.WebServer/Security/Authentication/anonymousAuthentication -metadata overrideMode -value Allow -PSPath IIS:/

        Foreach($item in (Get-ChildItem IIS:\Sites)) { $tempPath="IIS:\Sites\"; $tempPath+=$item.name; Set-WebConfiguration -filter /system.webServer/security/authentication/anonymousAuthentication $tempPath -value 0}

        Set-WebConfiguration //System.WebServer/Security/Authentication/anonymousAuthentication -metadata overrideMode -value Deny-PSPath IIS:/

        $sysDrive=$Env:Path.Substring(0,3); $tempPath=((Get-WebConfiguration "//httperrors/error").prefixLanguageFilePath | Select-Object -First 1) ; $sysDrive+=$tempPath.Substring($tempPath.IndexOf('\')+1); Get-ChildItem -Path $sysDrive -Include *.* -File -Recurse | foreach { $_.Delete()}

    } 


    if (Get-Command "php.exe" -ErrorAction SilentlyContinue) {
        $Loc = php -i | find /i "configuration file" | Select-String -Pattern 'C:.*?php.ini'
        $path = ($Loc -Split "=> ")[1]
        $phpFile = "[PHP]`r`nengine = On`r`nshort_open_tag = Off`r`nprecision = 14`r`noutput_buffering = 4096`r`nzlib.output_compression = Off`r`nimplicit_flush = Off`r`nunserialize_callback_func =`r`nserialize_precision = -1`r`ndisable_functions = proc_open, popen, disk_free_space, diskfreespace, set_time_limit, leak, tmpfile, exec, system, shell_exec, passthru, show_source, system, phpinfo, pcntl_exec`r`ndisable_classes =`r`nzend.enable_gc = On`r`nexpose_php = Off`r`nmax_execution_time = 30`r`nmax_input_time = 60`r`nmemory_limit = 128M`r`nerror_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT`r`ndisplay_errors = Off`r`ndisplay_startup_errors = Off`r`nlog_errors = On`r`nlog_errors_max_len = 1024`r`nignore_repeated_errors = Off`r`nignore_repeated_source = Off`r`nvariables_order = 'GPCS'`r`nrequest_order = 'GP'`r`nregister_argc_argv = Off`r`nauto_globals_jit = On`r`npost_max_size = 8M`r`nauto_prepend_file =`r`nauto_append_file =`r`ndefault_mimetype = 'text/html'`r`ndefault_charset = 'UTF-8'`r`ndoc_root =`r`nuser_dir =`r`nenable_dl = Off`r`nfile_uploads = Off`r`nupload_max_filesize = 2M`r`nmax_file_uploads = 20`r`nallow_url_fopen = Off`r`nallow_url_include = Off`r`ndefault_socket_timeout = 60`r`n[CLI Server]`r`ncli_server.color = On`r`n[Pdo_mysql]`r`npdo_mysql.default_socket=`r`n[mail function]`r`nmail.add_x_header = Off`r`n[ODBC]`r`nodbc.allow_persistent = On`r`nodbc.check_persistent = On`r`nodbc.max_persistent = -1`r`nodbc.max_links = -1`r`nodbc.defaultlrl = 4096`r`nodbc.defaultbinmode = 1`r`n[Interbase]`r`nibase.allow_persistent = 1`r`nibase.max_persistent = -1`r`nibase.max_links = -1`r`nibase.timestampformat = '%Y-%m-%d %H:%M:%S'`r`nibase.dateformat = '%Y-%m-%d'`r`nibase.timeformat = '%H:%M:%S'`r`n[MySQLi]`r`nmysqli.max_persistent = -1`r`nmysqli.allow_persistent = On`r`nmysqli.max_links = -1`r`nmysqli.default_port = 3306`r`nmysqli.default_socket =`r`nmysqli.default_host =`r`nmysqli.default_user =`r`nmysqli.default_pw =`r`nmysqli.reconnect = Off`r`n[mysqlnd]`r`nmysqlnd.collect_statistics = On`r`nmysqlnd.collect_memory_statistics = Off`r`n[PostgreSQL]`r`npgsql.allow_persistent = On`r`npgsql.auto_reset_persistent = Off`r`npgsql.max_persistent = -1`r`npgsql.max_links = -1`r`npgsql.ignore_notice = 0`r`npgsql.log_notice = 0`r`n[bcmath]`r`nbcmath.scale = 0`r`n[Session]`r`nsession.save_handler = files`r`nsession.use_strict_mode = 1`r`nsession.use_cookies = 1`r`nsession.use_only_cookies = 1`r`nsession.name = PHPSESSID`r`nsession.auto_start = 0`r`nsession.cookie_lifetime = 14400`r`nsession.cookie_path = /`r`nsession.cookie_domain =`r`nsession.cookie_httponly = 1`r`nsession.cookie_samesite = Strict`r`nsession.serialize_handler = php`r`nsession.gc_probability = 1`r`nsession.gc_divisor = 1000`r`nsession.gc_maxlifetime = 1440`r`nsession.referer_check =`r`nsession.cache_limiter = nocache`r`nsession.cache_expire = 60`r`nsession.use_trans_sid = 0`r`nsession.sid_length = 128`r`nsession.trans_sid_tags = 'a=href,area=href,frame=src,form='`r`nsession.sid_bits_per_character = 6`r`n[Assertion]`r`nzend.assertions = -1`r`n[Tidy]`r`ntidy.clean_output = Off`r`n[ldap]`r`nldap.max_links = -1`r`n"
        $phpFile | Out-File -FilePath $path
    }




    start-process powershell.exe -argument '-nologo -noprofile -executionpolicy bypass -command [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Set-MpPreference -ThreatIDDefaultAction_Ids "2147597781" -ThreatIDDefaultAction_Actions "6"; Invoke-WebRequest -Uri https://github.com/ION28/BLUESPAWN/releases/download/v0.5.1-alpha/BLUESPAWN-client-x64.exe -OutFile BLUESPAWN-client-x64.exe; & .\BLUESPAWN-client-x64.exe --monitor -a Normal --log=console,xml'


    start-process powershell.exe -argument '-nologo -noprofile -executionpolicy bypass -command [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri https://download.comodo.com/cce/download/setups/cce_public_x64.zip?track=5890 -OutFile cce_public_x64.zip; Expand-Archive cce_public_x64.zip; .\cce_public_x64\cce_2.5.242177.201_x64\cce_x64\cce.exe -u; read-host "CCE Continue When Updated"; .\cce_public_x64\cce_2.5.242177.201_x64\cce_x64\cce.exe -s \"m;f;r\" -d "c"; read-host "CCE Finished"'



    sc.exe config trustedinstaller start= auto
    DISM /Online /Cleanup-Image /RestoreHealth
    sfc /scannow
