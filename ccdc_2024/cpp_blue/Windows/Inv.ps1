Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force

#Hostname and IP
Write-Output "#### Start Hostname ####" 
Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select-Object Name, Domain
Write-Output "#### End Hostname ####" 

Write-Output "#### Start IP ####" 
Get-WmiObject Win32_NetworkAdapterConfiguration | ? {$_.IpAddress -ne $null} | % {$_.IPAddress} | Where-Object { [System.Net.IPAddress]::Parse($_).AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }
Write-Output "#### End IP ####"

$DC = Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'"
if ($DC) {
    Write-Output "`n#### DC Detected ####"

    Write-Output "`n#### Start DNS Records ####"
    try {
        Get-DnsServerResourceRecord -ZoneName $($(Get-ADDomain).DNSRoot) | ? {$_.RecordType -notmatch "SRV|NS|SOA" -and $_.HostName -notmatch "@|DomainDnsZones|ForestDnsZones"} | Format-Table
    }
    catch {
        Write-Output "[ERROR] Failed to get DNS records, DC likely too old"
    }
    Write-Output "#### End DNS Records ####"
}

if (Get-Service -Name W3SVC -ErrorAction SilentlyContinue) {
    $IIS = $true
    Import-Module WebAdministration
    Write-Output "#### IIS Detected ####" 
}

Write-Output "`n#### Current Admin ####" 
whoami.exe

Write-Output "`n#### OS ####" 
(Get-WMIObject win32_operatingsystem).caption

Write-Output "`n#### Start DNS Servers ####" 
$dnsAddresses = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | 
    Where-Object { $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' } | 
    ForEach-Object { $_.GetIPProperties().DnsAddresses }

$dnsAddresses | Select-Object -ExpandProperty IPAddressToString
Write-Output "#### End DNS Servers ####" 


if ($IIS) {
    Write-Output "`n#### Start IIS Site Bindings ####"
    $websites = Get-ChildItem IIS:\Sites | Sort-Object name

    foreach ($site in $websites) {
        Write-Output "Website Name: $($site.Name)"
        Write-Output "Website Path: $($site.physicalPath)"
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
    Write-Output "#### End IIS Site Bindings ####"
}

#RunKeys
Write-Output "`n#### Start Registry Startups ####" 
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
                Write-Output "   [$_] $($reg.$_)" 
            }
        }
    }
    catch{
        Write-Output "[Registry Startup] $item Not Found" 
    }
}
Write-Output "#### End Registry Startups ####" 

#Scheduled Tasks
Write-Output "`n#### Start Scheduled Tasks ####" 
$scheduledTasksXml = schtasks /query /xml ONE
$tasks = [xml]$scheduledTasksXml
$taskList = @()
for ($i = 0; $i -lt $tasks.Tasks.'#comment'.Count; $i++) {
    $taskList += [PSCustomObject] @{
        TaskName = $tasks.Tasks.'#comment'[$i]
        Task = $tasks.Tasks.Task[$i]
    }
}
$filteredTasks = $taskList | Where-Object {
    ($_.Task.RegistrationInfo.Author -notlike '*.exe*') -and
    ($_.Task.RegistrationInfo.Author -notlike '*.dll*')
}
$filteredTasks | ForEach-Object {
    $taskName = $_.TaskName
    $fields = schtasks /query /tn $taskName.trim() /fo LIST /v | Select-String @('TaskName:', 'Author: ', 'Task to Run:')
    $fields | Out-String
}
Write-Output "#### End Scheduled Tasks ####" 

#SMB Shares
Write-Output "#### Start SMB Shares ####" 
Get-WmiObject -Class Win32_Share | Select-Object Name,Path
Write-Output "#### End SMB Shares ####" 

#Installed Programs

Write-Output "`n#### Start Installed Programs ####" 
$programs = foreach ($UKey in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
    foreach ($Product in (Get-ItemProperty $UKey -ErrorAction SilentlyContinue)) {
        if($Product.DisplayName -and $Product.SystemComponent -ne 1) {
            $Product.DisplayName
        }
    }
}
$programs = $programs | sort.exe
Write-Output $programs
Write-Output "#### End Installed Programs ####" 

#Users and Groups
Write-Output "`n#### Start Group Membership ####" 
if ($DC) {
    $Groups = Get-ADGroup -Filter 'SamAccountName -NotLike "Domain Users"' | Select-Object -ExpandProperty Name
    $Groups | ForEach-Object {
        $Users = Get-ADGroupMember -Identity $_ | Select-Object -ExpandProperty Name
        if ($Users.Count -gt 0) {
            $Users = $Users | % { "   Member: $_"}
            Write-Output "Group: $_" $Users
        }
    }
} else {
    # Get a list of all local groups
    $localGroups = [ADSI]"WinNT://localhost"

    # Iterate through each group
    $localGroups.psbase.Children | Where-Object { $_.SchemaClassName -eq 'group' } | ForEach-Object {

        $groupName = $_.Name[0]
        Write-Output "Group: $groupName"
        
        # List members of the current group
        $_.Members() | ForEach-Object {
            $memberPath = ([ADSI]$_).Path.Substring(8)
            Write-Output "    Member: $memberPath"
        }
    }
}
Write-Output "#### End Group Membership ####" 

Write-Output "`n#### Start ALL Users ####" 
    Get-WmiObject win32_useraccount | ForEach-Object {$_.Name}
Write-Output "`n#### End ALL Users ####" 

#Windows Features
Write-Output "`n#### Start Features ####" 
dism /online /get-features /Format:Table | Select-String Enabled | %{ $_.ToString().Split(" ")[0].Trim()} | sort.exe
Write-Output "#### End Features ####" 