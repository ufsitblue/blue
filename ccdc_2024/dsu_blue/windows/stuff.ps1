

(Get-ADGroupMember "Domain Admins").samaccountname
arp -a

get-itemproperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\run"
get-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
get-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"
get-childitem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\"


get-itemproperty  "HKCU:\Software\Microsoft\Internet Explorer\TypedURLs"

schtasks /query /FO table /NH
get-hotfix | Where-Object {$_.Description -ne ""} | select Description,HotFixID,InstalledBy
Get-WmiObject win32_service | Select-Object Name, DisplayName, PathName, StartName, StartMode, State, TotalSessions, Description
ipconfig -displaydns
type $env:windir\system32\drivers\etc\hosts
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDates
Get-History
netsh firewall show state
netsh firewall show config
Get-ChildItem ENV: | Select Name, Value

$wmivar =get-wmiobject -namespace root -Class __Namespace | select Name
$wminames = Foreach($i in $wmivar.Name){gwmi -namespace root\$i -Class __EventConsumer; gwmi -namespace root\$i -Class __EventFilter; gwmi -namespace root\$i -Class __FilterToCOnsumerBinding }


net user adm-Cwelu Thisisapassword1! /add /Y
net localgroup administrators adm-cwelu /add 

$date = "9/21/2022"
$file = (Get-ChildItem -Path "C:\" -recurse | ? {$_.LastWriteTime -like "$date*"}).name
$open = get-content $file

$files = get-childitem -path "C:\users\administrator" -include *.txt -recurse | foreach {get-content $_.FullName}

$date = "10/21/2022"
$file = (Get-ChildItem -Path "C:\users\administrator" -recurse | ? {$_.LastWriteTime -like "$date*"}).name

$files = get-childitem -path "C:\" -include *.txt -recurse | foreach {if(get-content $_.FullName | select-string "Creed Bratton"){ write-host $_.FullName}  }
$shares = get-smbshare
$permissions = (get-acl $shares.path[3]).access
$permissions | ? {(($_.IsInherited -like "False") -and ($_.FileSystemRights -like "FullControl"))}

$ADPERMS = get-adorganizationalunit -filter * | %{(get-acl "AD:$($_.distinguishedname)").access} | ? {($_.IsInherited -like "False")} | ft ActivedirectoryRights, objecttype, IdentityReference

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


$SysIntFolder = "C:\sysint"
mkdir $sysIntFolder
$Page = (Invoke-WebRequest -Uri "https://live.sysinternals.com/tools").Content
$MatchedItems = ([regex]"<A HREF.*?<\/A>").Matches($Page)
foreach($Match in $MatchedItems.Value){
    if($Match -match ">(.*?\..*?)<"){
    if(($Matches[1] -like "sysmon*") -or ($Matches[1] -like "Procmon*") -or ($Matches[1] -like "autoruns*") -or ($Matches[1] -like "tcpview*")){
                         Invoke-WebRequest -Uri ("https://live.sysinternals.com/tools/" + $Matches[1]) -OutFile (Join-Path -Path $SysIntFolder -ChildPath $Matches[1])
                                 $matches[1]
                    }
                    } 
}



cd $sysintfolder
Invoke-WebRequest -Uri https://github.com/palantir/windows-event-forwarding/archive/refs/heads/master.zip -OutFile WEF.zip
Invoke-WebRequest -Uri https://github.com/SwiftOnSecurity/sysmon-config/archive/refs/heads/master.zip -OutFile swift.zip

#Rename-Item sysmon.exe -NewName winmntr.exe
#./winmntr.exe -i sysmonconfig-export.xml -d TopDrive -h sha256 -accepteula

$test = get-childitem *
foreach($i in $test.name){ cmd /c wecutil cs $i }


Add-Type -AssemblyName System.Web

Function GetRandom {
$minLength = 42 ## characters
$maxLength = 48 ## characters
$length = get-random -Minimum $minlength -Maximum $maxLength
$nonAlphaChars = get-random -Minimum 12 -Maximum 16
$password = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
return $password
}

$OU = "CN=Users,DC=TRYOUTS,DC=local"
$list = (get-aduser -filter {(SmartCardLogonRequired -ne $TRUE -and Enabled -eq $True)} -SearchBase $OU -properties Name).samaccountname

Foreach($i in $list){
$New = . GetRandom
set-adaccountPassword -identity $i -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $New -Force)
write-output  "$($i) has been updated"}
                                                                                                                                                                                                                                                                                           }
                                                                                                                                                                                                                                                                                                            }
                                                                                                                                                                                                                                                                                                                        }
                                                                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                                                                    }


#cd $sysintfolder
#Rename-Item sysmon.exe -NewName winmmntr.exe
#winmntr.exe -i sysmonaudit.xml -d TopDrive -h sha256 -accepteula

$test = get-childitem C:\sysint\WEF\windows-event-forwarding-master\wef-subscriptions\
foreach($i in $test.name){
cmd /c wecutil cs $i }



$powershell = Get-WinEvent -FilterHashtable @{LogName="ForwardedEvents";Id=4104,4103} -MaxEvents 2000 | ForEach-Object {
    $Xml = ([xml]$_.ToXml()).Event
        $event = [ordered]@{
                EventDate = [DateTime]$Xml.System.TimeCreated.SystemTime
                EventID = $xml.system.eventID
                Computer  = $Xml.System.Computer
               }
               $Xml.EventData.ChildNodes | ForEach-Object { $event[$_.Name] = $_.'#text' }
               [PsCustomObject]$event
           }

$powershell | export-csv C:\users\$env:username\Desktop\powershell.csv
$powershell | ? {($_.scriptblocktext -like "*-enc*" -or $_.scriptblocktext -like "*base64*" -or $_.scriptblocktext -like "*invoke-expression*" )}

$powershell2 = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Powershell/operational";Id=4104,4103} -MaxEvents 2000 -oldest | ForEach-Object {
    $Xml = ([xml]$_.ToXml()).Event
        $event = [ordered]@{
                EventDate = [DateTime]$Xml.System.TimeCreated.SystemTime
                EventID = $xml.system.eventID
                Computer  = $Xml.System.Computer
               }
               $Xml.EventData.ChildNodes | ForEach-Object { $event[$_.Name] = $_.'#text' }
               [PsCustomObject]$event
           }



$Security = Get-WinEvent -FilterHashtable @{LogName="Security";Id=4624,4625,4768,4673,4672,4720,4732,4728,4688,5136,5140, 5142} -MaxEvents 20000 -oldest | ForEach-Object {
    $Xml = ([xml]$_.ToXml()).Event
        $event = [ordered]@{
                EventDate = [DateTime]$Xml.System.TimeCreated.SystemTime
                EventID = $xml.system.eventID
                Computer  = $Xml.System.Computer
               }
               $Xml.EventData.ChildNodes | ForEach-Object { $event[$_.Name] = $_.'#text' }
               [PsCustomObject]$event
           }

$security | export-csv C:\users\$env:username\Desktop\security3.csv -append


$security | where-object {$_.ipaddress -eq "192.168.1.208" -and $_.logontype -ne "3"}





$security  | ? {$_.eventid -eq 4624 -or $_.eventid -eq 4625 -or $_.eventid -eq 4678 } | export-csv C:\users\$env:username\Desktop\logon.csv -append
$security  | ? {$_.eventid -eq 4673 -or $_.eventid -eq 4672} | export-csv C:\users\$env:username\Desktop\seprivileges.csv -append
$security  | ? {$_.eventid -eq 4720 -or $_.eventid -eq 4732 -or $_.eventid -eq 4728} | export-csv C:\users\$env:username\Desktop\groupmodification.csv -append
$security  | ? {$_.eventid -eq 4688} | export-csv C:\users\$env:username\Desktop\processes.csv -append
$security  | ? {$_.eventid -eq 5136} | export-csv C:\users\$env:username\Desktop\objectmodification.csv -append
$security  | ? {$_.eventid -eq 5140 -or $_.eventid -eq 5142} | export-csv C:\users\$env:username\Desktop\networkshares.csv -append


$sysmon = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/operational"} -MaxEvents 20000 -oldest | ForEach-Object {
    $Xml = ([xml]$_.ToXml()).Event
        $event = [ordered]@{
                EventDate = [DateTime]$Xml.System.TimeCreated.SystemTime
                EventID = $xml.system.eventID
                Computer  = $Xml.System.Computer
               }
               $Xml.EventData.ChildNodes | ForEach-Object { $event[$_.Name] = $_.'#text' }
               [PsCustomObject]$event
           }

$sysmon | export-csv C:\users\$env:username\Desktop\sysmon.csv -append