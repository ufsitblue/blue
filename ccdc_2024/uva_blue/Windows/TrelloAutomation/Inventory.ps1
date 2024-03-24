#Hostname and IP
Write-Output "#### Hostname ####" 
Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select-Object Name, Domain

Write-Output "#### IP ####" 
Get-WmiObject Win32_NetworkAdapterConfiguration | ? {$_.IpAddress -ne $null} | % {$_.ServiceName + "`n" + $_.IPAddress + "`n"}
$DC = Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'"
if ($DC) {
    Write-Output "#### DC Detected ####" 
}
if (Get-Service -Name W3SVC) {
    $IIS = $true
    Import-Module WebAdministration
    Write-Output "#### IIS Detected ####" 
}

Write-Output "#### Current Admin ####" 
whoami.exe

Write-Output "#### OS ####" 
(Get-WMIObject win32_operatingsystem).caption

Write-Output "#### DNS Servers ####" 
Get-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Select-Object -expand ifindex) | Where-Object ServerAddresses -inotmatch "::" | Select-Object -expand ServerAddresses


if ($IIS) {
    Write-Output "#### IIS Site Bindings ####"
    $websites = Get-ChildItem IIS:\Sites | Sort-Object name

    foreach ($site in $websites) {
        Write-Output "Website Name: $($site.Name)"
        $bindings = Get-WebBinding -Name $site.name
        foreach ($binding in $bindings) {
            Write-Output "    Binding Information:"
            Write-Output "        Protocol: $($binding.protocol)"
            Write-Output "        IP Address: $($binding.bindingInformation.split(":")[0])"
            Write-Output "        Port: $($binding.bindingInformation.split(":")[1])"
            Write-Output "        Hostname: $($binding.hostHeader)"
        }
        Write-Output ""
    }
}


#Network Connections
#$NetworkConnections = Get-NetTCPConnection -State Listen,Established | where-object {($_.RemotePort -ne 443) -and ($_.LocalPort -ne 5985) -and ($_.LocalAddress -inotmatch '::' )}| sort-object state,localport | Select-Object localaddress,localport,remoteaddress,remoteport,@{'Name' = 'ProcessName';'Expression'={(Get-Process -Id $_.OwningProcess).Name}}
#New-TrelloCardChecklist -Card $Card -Name Connections -Item $NetworkConnections

#RunKeys
Write-Output "#### Registry Startups ####" 
$regPath = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx", 
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", 
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", 
            "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\AlternateShell", 
            "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells\AvailableShells", 
            "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components", 
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce", 
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce", 
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices", 
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices", 
            "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit", 
            "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell", 
            "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows")
foreach ($item in $regPath) {
    try{
        $reg = Get-ItemProperty -Path $item -ErrorAction SilentlyContinue
        Write-Output "[Registry Startups] $item" 
        $reg | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Select-Object -Expand Name | ForEach-Object {
            if ($_.StartsWith("PS") -or $_.StartsWith("VM")) {
                # Write-Output "[Startups: Registry Values] Default value detected"
            }
            else {
                Write-Output "[$_] $($reg.$_)" 
            }
        }
    }
    catch{
        Write-Output "[Registry Startup] $item Not Found" 
    }
}

#Scheduled Tasks
Write-Output "#### Scheduled Tasks ####" 
$tasks = Get-ScheduledTask | Where-Object { $_.Author -like '*\*' -and $_.Author -notlike '*.exe*' -and $_.Author -notlike '*.dll*' } 
foreach ($task in $tasks) {
    $author = $task.Author
    $taskname = $task.TaskName
    $taskpath = $task.TaskPath
    $taskfile = (Get-ScheduledTask $taskname).actions.Execute
    $taskargs = (Get-ScheduledTask $taskname).actions.Arguments
    Write-Output "[Scheduled Task] Path: "$taskpath$taskname" Author: "$author" Running file: "$taskfile" Arguments: "$taskargs"" 
}

#SMB Shares
Write-Output "#### SMB Shares ####" 
Get-WmiObject -Class Win32_Share | Select-Object Name,Path

#Installed Programs

Write-Output "#### Installed Programs ####" 
$InstalledSoftware = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
foreach($obj in $InstalledSoftware) {
    if (!($null -eq $obj.GetValue('DisplayName'))) {
    Write-Output $obj.GetValue('DisplayName')  
    Write-Output " - "  
    Write-Output $obj.GetValue('DisplayVersion') 
    }
}

$InstalledSoftware = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
foreach($obj in $InstalledSoftware) {
    Write-Output $obj.GetValue('DisplayName')  
    Write-Output " - "  
    Write-Output $obj.GetValue('DisplayVersion')
}

#Users and Groups
Write-Output "#### Group Membership ####" 
if ($DC) {
    $Groups = Get-AdGroup -Filter 'SamAccountName -NotLike "Domain Users"' | Select-Object -ExpandProperty Name
    $Groups | ForEach-Object {
        $Users = Get-ADGroupMember -Identity $_ | Select-Object -ExpandProperty Name
        if ($Users.Count -gt 0) {
            $Users = $Users | Out-String
            Write-Output "Group: $_" 
            Write-Output "$Users" 
            
        }
    }
} else {
    $Groups = net localgroup | Where-Object {$_ -AND $_ -notmatch "command completed successfully"} | Select-Object -skip 2
    $Groups = $Groups -replace '\*',''
    $Groups | ForEach-Object {
        # TODO: Test to make sure $_ references correct var
        $Users = net localgroup $_ | Where-Object {$_ -AND $_ -notmatch "command completed successfully"} | Select-Object -skip 4
        if ($Users.Count -gt 0) {
            $Users = $Users | Out-String
            Write-Output "Group: $_" 
            Write-Output "$Users" 
        }
    }
}
Write-Output "#### ALL Users ####" 
    Get-WmiObject win32_useraccount | ForEach-Object {$_.Name}
#Windows Features
Write-Output "#### Features ####" 
Get-WindowsOptionalFeature -Online | Where-Object state | Select-Object FeatureName
