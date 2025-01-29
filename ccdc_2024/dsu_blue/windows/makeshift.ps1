Function Watchdog(){
$powershell = Get-WinEvent -FilterHashtable @{LogName="ForwardedEvents";Id=4104;Level=5} -MaxEvents 20 | ForEach-Object {
    $Xml = ([xml]$_.ToXml()).Event
        $event = [ordered]@{
                EventDate = [DateTime]$Xml.System.TimeCreated.SystemTime
                EventID = $xml.system.eventID
                Computer  = $Xml.System.Computer
               }
               $Xml.EventData.ChildNodes | ForEach-Object { $event[$_.Name] = $_.'#text' }
               [PsCustomObject]$event
           }


foreach($log in $powershell){
if($log.scriptblocktext -like "*NOLOOPSHERE3344*"){continue}
elseIf($log.scriptblocktext -like "*-enc*" -or $Log.scriptblocktext -like "*base64*" -or $log.scriptblocktext -like "*invoke-expression*" -or $log.scriptblocktext -like "*invoke-command*" ){
$var = "Malicious script Identified on $($log.Computer)"
$system = $log.computer
$date = get-date -format "HH:mm:ss"
$date+":"+$var | out-file C:\users\adm-ts\Desktop\test.txt -append
RemoteCall $system
}
}
}
watchdog
Function RemoteCall($computer){
$script= {
$check = Get-NetTCPConnection | Where-Object {$_.state -eq "Established"}
$var = "NOLOOPSHERE3344"
$check | out-file "C:\programdata\diagnostics.log" -append
}
$scriptString = $script.Tostring()
$scriptBytes = [System.Text.Encoding]::Unicode.GetBytes($scriptString)
$scriptEncoded = [convert]::Tobase64string($scriptBytes)
$command = "Powershell.exe -encodedCommand $ScriptEncoded -exec bypass -NoLogo -noninteractive -noprofile"
invoke-wmimethod -computername $computer -Namespace root\cimv2 -Class Win32_process -name Create -ArgumentList $command
}