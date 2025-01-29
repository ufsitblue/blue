function Invoke-InventoryProcessing {
    param (
        [Parameter(Mandatory=$true)]
        [string]$InventoryFolder,
        [Parameter(Mandatory=$true)]
        [string]$Extension
    )

    $hosts = @{}

    $files = Get-ChildItem -Path $InventoryFolder -Filter "*.$Extension"

    $files | ForEach-Object {
        $dc = $false
        $iisData = $null
        $smbData = @()
        (Get-Content $_.FullName -Raw) -replace '(\r?\n\s*){2,}', "`r`n`r`n" | Set-Content $_.FullName
        $data = Get-Content $_.FullName
        
        # Parse Host Data
        $hostData = Get-Data -startLine "#### Start Hostname ####" -endLine "#### End Hostname ####" -text $data
        $hostname = ($hostData[1] -split ": ")[1]
        $domain = ($hostData[2] -split ": ")[1]
        
        # Parse IPs
        $ipData = Get-Data -startLine "#### Start IP ####" -endLine "#### End IP ####" -text $data
        
        # Parse DNS Servers
        $dnsData = Get-Data -startLine "#### Start DNS Servers ####" -endLine "#### End DNS Servers ####" -text $data
        
        # Parse Server Details
        if ($data.Contains("#### IIS Detected ####")) {
            $iisData = Get-Data -startLine "#### Start IIS Site Bindings ####" -endLine "#### End IIS Site Bindings ####" -text $data
        }
        if ($data.Contains("#### DC Detected ####")) {
            $dc = $true
        }

        # Parse User Data
        $userData = Get-Data -startLine "#### Start ALL Users ####" -endLine "#### End ALL Users ####" -text $data
        $userData = $userData -ne 'WDAGUtilityAccount'
        $userData = $userData -ne 'DefaultAccount'
        
        # Parse Group Membership
        $currentGroup = $null
        $groupsWithMembers = @{}
        $groupData = Get-Data -startLine "#### Start Group Membership ####" -endLine "#### End Group Membership ####" -text $data
        $groupData -split "`n" | ForEach-Object {
            $line = $_.Trim()
            if ($line -match "^Group: (.+)$") {
                $currentGroup = $matches[1]
            } elseif ($line -match "^Member: (.+)$") {
                if (-not $groupsWithMembers.ContainsKey($currentGroup)) {
                    $groupsWithMembers[$currentGroup] = @()
                }
                $groupsWithMembers[$currentGroup] += $matches[1]
            }
        }

        # Parse Features
        $featureData = Get-Data -startLine "#### Start Features ####" -endLine "#### End Features ####" -text $data

        # Parse Registry Startups
        $regData = Get-Data -startLine "#### Start Registry Startups ####" -endLine "#### End Registry Startups ####" -text $data

        $registryStartups = @()
        $currentPath = $null

        foreach ($line in $regData -split "`n") {
            if ($line.StartsWith("[Registry Startups]")) {
                # This is a registry path line
                if ($null -ne $currentPath) {
                    # Add the previous path object to the array
                    $registryStartups += $currentPath
                }
                $path = ($line -split '] ')[1]
                $currentPath = @{ Path = $path; Keys = @() }
            } else {
                # This is a registry key line
                $keyName, $keyValue = $line.Trim().Trim('[') -split '] '
                $key = @{ Name = $keyName; Value = $keyValue }
                $currentPath.Keys += $key
            }
        }
        # Add the last path object to the array
        if ($null -ne $currentPath) {
            $registryStartups += $currentPath
        }

        $regData = $registryStartups


        # Parse Scheduled Tasks
        $taskData = Get-Data -startLine "#### Start Scheduled Tasks ####" -endLine "#### End Scheduled Tasks ####" -text $data

        # Parse SMB Shares
        $temp = Get-Data -startLine "#### Start SMB Shares ####" -endLine "#### End SMB Shares ####" -text $data
        for ($i = 0; $i -lt $temp.Count; $i += 5) {
            $share = [PSCustomObject] @{
                Name = $temp[$i].split(":")[1].Trim()
                Path = $temp[$i + 1].split(":", 2)[1].Trim()
            }
            $smbData += $share
        }

        # Parse Installed Programs
        $programData = Get-Data -startLine "#### Start Installed Programs ####" -endLine "#### End Installed Programs ####" -text $data

        $hostObject = [PSCustomObject] @{
            dc = $dc
            hostname = $hostname
            domain = $domain
            ip = $ipData
            dns = $dnsData
            iis = $iisData 
            users = $userData
            groups = $groupsWithMembers
            features = $featureData
            registry = $regData
            tasks = $taskData
            smb = $smbData
            programs = $programData
        }

        $SMBRemoveOne = {
            param($shareName)
            try {
                Invoke-Command -ComputerName $this.hostname -ScriptBlock {net share /delete $args[0] } -ArgumentList $shareName
                $smbData = $this.smb
                $smbData = $smbData | Where-Object {$_.Name -ne $shareName}
                $this.smb = $smbData
             } catch {
                Write-Host "Failed to Remove $shareName" -ForegroundColor Red 
            }
        }

        $SMBRemoveAll = {
            try {
                $this.smb.Name | ForEach-Object {
                    Invoke-Command -ComputerName $this.hostname -ScriptBlock {net share /delete $args[0] } -ArgumentList $_
                    $smbData = $this.smb
                    $smbData = $smbData | Where-Object {$_.Name -ne $_}
                    $this.smb = $smbData
                }
            } catch {
                Write-Host "Failed to Remove $shareName" -ForegroundColor Red 
            }
        }

        $RemoveUser = {
            param($username)
            try {
                Invoke-Command -ComputerName $this.hostname -ScriptBlock {net user $args[0] /delete} -ArgumentList $username
                $userData = $this.users
                $userData = $userData | Where-Object {$_ -ne $username}
                $this.users = $userData
            } catch {
                Write-Host "Failed to Remove $username" -ForegroundColor Red 
            }
        }

        $RemoveRegistryKey = {
            param($key, $value)
            try {
                Invoke-Command -ComputerName $this.hostname -ScriptBlock {reg delete $args[0] /v $value /f} -ArgumentList $key,$value
            } catch {
                Write-Host "Failed to Remove $key" -ForegroundColor Red 
            }
        }

        Add-Member -InputObject $hostObject -MemberType ScriptMethod -Name RemoveSMBShare -Value $SMBRemoveOne
        Add-Member -InputObject $hostObject -MemberType ScriptMethod -Name RemoveAllSMBShares -Value $SMBRemoveAll
        Add-Member -InputObject $hostObject -MemberType ScriptMethod -Name RemoveUser -Value $RemoveUser
        Add-Member -InputObject $hostObject -MemberType ScriptMethod -Name RemoveRegistryKey -Value $RemoveRegistryKey

        $hosts.Add($hostname, $hostObject)
    }
    return $hosts
}

function Get-Data($startLine, $endLine, $text){
    # Split the text into lines
    $lines = $text -split "\r?\n"
        
    # Find the indices of the identifying lines
    $startIndex = [Array]::IndexOf($lines, $startLine)
    $endIndex = [Array]::IndexOf($lines, $endLine)
    
    # Extract the lines between the identifying lines
    $capturedLines = $lines[($startIndex + 1)..($endIndex - 1)]
    
    # Output the captured lines
    $capturedLines
}

function Invoke-HostSearch {
    param(
        [pscustomobject]$HostData,
        [string[]]$Hostname,
        [string[]]$Group,
        [switch]$ListGroups,
        [switch]$ListUsers,
        [switch]$ListTasks,
        [switch]$ListRegistry,
        [switch]$ListFeatures,
        [switch]$ListIIS,
        [switch]$ListIPs,
        [switch]$ListPrograms,
        [switch]$ListSMB
    )

    if (!$Global:HostData -and !$HostData) {
        Write-Error "No Host Data Provided"
        return
    }
 
    if ($Global:HostData -and !$HostData) {
        $HostData = $Global:HostData
    }
       
    if ($Hostname) { 
        $hosts = $Hostname 
    } else { 
        $hosts = $HostData.Keys 
    }

    foreach ($h in $hosts) {
        if ($Group) {
            foreach ($g in $Group) {
                Write-Host $HostData.$h.Hostname "$g Members" -ForegroundColor Red
                Write-Output $HostData.$h.Groups.$g
                Write-Output ""
            }
        }

        if ($ListGroups) {
            Invoke-OutputData -HostData $HostData -Hostname $Hostname -Data "Groups"
        }

        if ($ListUsers) {
            Invoke-OutputData -HostData $HostData -Hostname $Hostname -Data "Users"
        }

        if ($ListTasks) {
            Invoke-OutputData -HostData $HostData -Hostname $Hostname -Data "Tasks"
        }

        if ($ListRegistry) {
            Invoke-OutputData -HostData $HostData -Hostname $Hostname -Data "Registry"
        }

        if ($ListFeatures) {
            Invoke-OutputData -HostData $HostData -Hostname $Hostname -Data "Features"
        }

        if ($ListIIS) {
            Invoke-OutputData -HostData $HostData -Hostname $Hostname -Data "IIS"
        }

        if ($ListIPs) {
            Invoke-OutputData -HostData $HostData -Hostname $Hostname -Data "IP"
        }

        if ($ListSMB) {
            Invoke-OutputData -HostData $HostData -Hostname $Hostname -Data "SMB"
        }

        if ($ListPrograms) {
            Invoke-OutputData -HostData $HostData -Hostname $Hostname -Data "Programs"
        }
    }
}

function Invoke-OutputData($HostData, $Hostname, $Data) {
    Write-Host $HostData.$h.Hostname "$data" -ForegroundColor Red
    Write-Output $HostData.$h.$data
    Write-Output ""

}

function Invoke-CompareInventory {
    param(
        [Parameter(Mandatory=$true)]
        [pscustomobject]$NewHostData,
        [Parameter(Mandatory=$true)]
        [pscustomobject]$OldHostData,
        [string[]]$Hostname,
        [string[]]$Group,
        [switch]$Groups,
        [switch]$Users,
        [switch]$Tasks,
        [switch]$Registry,
        [switch]$Features,
        [switch]$IIS,
        [switch]$IPs,
        [switch]$Programs,
        [switch]$SMB
    )

    if ($Hostname) { 
        $hosts = $Hostname 
    } else { 
        $hosts = $NewHostData.Keys 
    }

    foreach ($h in $hosts) {

        # Compare Group Membership
        if ($Group) {
            foreach ($g in $Group) {
                Write-Host $NewHostData.$h.Hostname "Comparing $g Members" -ForegroundColor Red
                $NewMembers = Compare-Object -ReferenceObject $OldHostData.$h.Groups.$g -DifferenceObject $NewHostData.$h.Groups.$g | Where-Object {$_.SideIndicator -like '=>'} | Select-Object -ExpandProperty InputObject
                $RemovedMembers = Compare-Object -ReferenceObject $OldHostData.$h.Groups.$g -DifferenceObject $NewHostData.$h.Groups.$g | Where-Object {$_.SideIndicator -like '<='} | Select-Object -ExpandProperty InputObject
                if ($NewMembers) {Write-Output "New $g Members: " $NewMembers}
                if ($RemovedMembers) {Write-Output "Removed $g Members: " $RemovedMembers}
                Write-Output ""
            }
        }

        # Compare Group Objects
        if ($Groups) {
            Invoke-OutputDifference -Old $OldHostData -New $NewHostData -Hostname $h -Data "Groups"
        }

        # Compare Users
        if ($Users) {
            Invoke-OutputDifference -Old $OldHostData -New $NewHostData -Hostname $h -Data "Users"
        }

        # Compare Scheduled Tasks
        if ($Tasks) {
            Invoke-OutputDifference -Old $OldHostData -New $NewHostData -Hostname $h -Data "Tasks"
        }

        # Compare Registry Startups
        if ($Registry) {
            Write-Host $NewHostData.$h.Hostname "Comparing Registry Startups" -ForegroundColor Red
            $diff = $NewHostData.$h.registry | Where-Object { $_.keys.value -eq (Compare-Object -ReferenceObject $OldHostData.$h.registry.keys.value -DifferenceObject $NewHostData.$h.registry.keys.value | Select-Object -ExpandProperty InputObject)}
            $RemovedReg = Compare-Object -ReferenceObject $OldHostData.$h.Registry -DifferenceObject $NewHostData.$h.Registry | Where-Object {$_.SideIndicator -like '<='} | Select-Object -ExpandProperty InputObject
            if ($diff) {
                Foreach ($key in $diff) {
                    Write-Output "New Registry Startups: $($key.path -replace ':')"
                    Write-Output "   Value: $($key.keys.name)"
                    Write-Output "   Data: $($key.keys.value)"
                }
            }
            if ($RemovedReg) {Write-Output "Removed Registry Startups: " $RemovedReg}
            Write-Output ""
        }

        # Compare Features
        if ($Features) {
            Invoke-OutputDifference -Old $OldHostData -New $NewHostData -Hostname $h -Data "Features"
        }

        # Compare IIS
        if ($IIS) {
            Invoke-OutputDifference -Old $OldHostData -New $NewHostData -Hostname $h -Data "IIS"
        }

        # Compare IPs
        if ($IPs) {
            Invoke-OutputDifference -Old $OldHostData -New $NewHostData -Hostname $h -Data "IP"
        }

        # Compare SMB
        if ($SMB) {
            Write-Host $NewHostData.$h.Hostname "Comparing SMB" -ForegroundColor Red
            $NewSMB = Compare-Object -ReferenceObject $OldHostData.$h.SMB -DifferenceObject $NewHostData.$h.SMB -Property  Name | Where-Object {$_.SideIndicator -like '=>'} | Select-Object -ExpandProperty Name
            $RemovedSMB = Compare-Object -ReferenceObject $OldHostData.$h.SMB -DifferenceObject $NewHostData.$h.SMB -Property Name | Where-Object {$_.SideIndicator -like '<='} | Select-Object -ExpandProperty Name
            if ($NewSMB) {Write-Output "New Share: " $NewSMB}
            if ($RemovedSMB) {Write-Output "Removed Share: " $RemovedSMB}
            Write-Output ""
        }

        # Compare Programs
        if ($Programs) {
            Invoke-OutputDifference -Old $OldHostData -New $NewHostData -Hostname $h -Data "Programs"
        }
    }
}

function Invoke-OutputDifference($Old, $New, $Hostname, $Data) {
    Write-Host $NewHostData.$Hostname.Hostname "Comparing $Data" -ForegroundColor Red
    $NewData = Compare-Object -ReferenceObject $Old.$Hostname.$Data -DifferenceObject $NewHostData.$Hostname.$Data | Where-Object {$_.SideIndicator -like '=>'} | Select-Object -ExpandProperty InputObject
    $RemovedData = Compare-Object -ReferenceObject $Old.$Hostname.$Data -DifferenceObject $NewHostData.$Hostname.$Data | Where-Object {$_.SideIndicator -like '<='} | Select-Object -ExpandProperty InputObject
    $NewData = $NewData | %{ $_ = "   " + $_; $_ }
    $RemovedData = $RemovedData | %{ $_ = "   " + $_; $_ }
    if ($NewData) {Write-Output "New $Data`: " $NewData}
    if ($RemovedData) {Write-Output "Removed $Data`: " $RemovedData}
    Write-Output ""
}