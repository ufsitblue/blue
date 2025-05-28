# Tyler Sternod 10/3/2022

$DesktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
Function Baseline{

$netstat = netstat -naob | findstr ESTABLISHED
$normal = foreach($I in $netstat){
$regex = ‘\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\S+’
if($value = ($I |  Select-String -Pattern $regex -allmatches).Matches.Value){
if($value -like "127.0.0.1*"){}
else{
$value
}
}
else{}
}
return $normal
}

$baseline = Baseline
$abnormal = @()
Function Main{
while($TRUE){
$new = Baseline
$validate = Compare-Object $new $baseline
start-sleep 2

foreach($i in $validate){
$OLD = $abnormal | where-object {$_ -like $i.inputobject}
if($OLD){continue}
else{
if($i.sideindicator -eq '<='){
$abnormal +=$i.InputObject
write-host $i.InputObject -ForegroundColor Red
$i.InputObject | out-file $($DesktopPath+"\netstat.log") -append
}
}
}
}
}



Function Baseline2{

$netstat = Get-NetTCPConnection | where-object {$_.state -eq "Established"}
$normal = foreach($I in $netstat){
if($i.remoteAddress -like "127.0.0.1*"){}
elseif($i.remoteAddress -like "::1*"){}
else{
[pscustomobject]@{
IP = $i.remoteaddress
port = $i.remotePort
PID = $i.OwningProcess
}
}
}
return $normal
}








$DesktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
Function Baseline2{

$netstat = Get-NetTCPConnection | where-object {$_.state -eq "Established"}
$normal = foreach($I in $netstat){
if($i.remoteAddress -like "127.0.0.1*"){}
elseif($i.remoteAddress -like "::1*"){}
else{
[pscustomobject]@{
IP = $i.remoteaddress
port = $i.remotePort
PID = $i.OwningProcess
}
}
}
return $normal
}
#captures current established connections and compares all subsequent calls.
$baseline = Baseline2
$baseline | out-file $($DesktopPath+"\baseline.txt")
#$baseline = get-content $($DesktopPath+"\baseline.txt")
$abnormal = @()
Function Main2{
while($TRUE){
$new = Baseline2
$validate = Compare-Object $new $baseline
start-sleep 2
foreach($i in $validate){
$OLD = $abnormal | where-object {$_ -like $i.inputobject}
if($OLD){continue}
else{
if($i.sideindicator -eq '<='){
$abnormal +=$i.InputObject
$proc = (get-process -id $i.InputObject.PID).processName
$IP = $i.InputObject.ip
write-host "$proc | $IP" -ForegroundColor Red
$i.InputObject | export-csv $($DesktopPath+"\netstat.csv") -append
$Kill = read-host -prompt "Kill $proc ?"
IF($Kill -eq "Y"){Stop-Process -id $i.InputObject.PID }
else{$kill = $null}
$FWUP = read-host -prompt "Create firewall rule for $IP ?"
if($FWUP -eq "Y"){
New-NetFirewallRule -DisplayName "Block INBRedteam" -Direction Inbound -Action Block -RemoteAddress $IP
New-NetFirewallRule -DisplayName "Block OUTBRedteam" -Direction outbound -Action Block -RemoteAddress $IP
}
else{$FWUP = $NULL}
}
}
}
}
}

. Main2