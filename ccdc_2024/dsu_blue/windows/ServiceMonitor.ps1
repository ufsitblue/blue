# ------- Tyler's Saucy Service Monitor -------
while($true){
	$Cmp = Get-Service | Where-Object {$_.Status -eq "Running"}
while ($true) {
	$Cmp2 = Get-Service | Where-Object {$_.Status -eq "Running"}
	$diff = Compare-Object -ReferenceObject $Cmp -DifferenceObject $Cmp2 -Property Name
	if($diff -ne $null){
		$tmp = Get-WmiObject win32_service | ?{$_.Name -like $diff.Name} | select Name, DisplayName, State, PathName
		if(($tmp.State -eq "Stopped" )){break}
	  	Write-Output '!!!!!!!!!!A SERVICE HAS STARTED!!!!!!!!!!'
	  	Write-Output ('Display Name: ' + $tmp.DisplayName)
	  	Write-Output ('Name: ' + $tmp.Name)
	  	Write-Output ('State: '+ $tmp.State)
	  	Write-Output ('Path: ' + $tmp.PathName)
	  	Write-Output '!!!!!!!!!!A SERVICE HAS STARTED!!!!!!!!!!'
	  	Write-Output 'Kill? y/n'
	  	$Return = Read-Host
		if (($Return -eq "Y") -or ($Return -eq "y")){
			Stop-Service -Name $diff.Name -Force -NoWait  
			Write-Output 'Kerblam! Service has been eliminated...'
			Write-Output 'Might want to search for some bad guys around here'
			}
		elseif (($Return -eq "N") -or ($Return -eq "n")){
			Write-Output 'Letting that service slide...for now...'
			break
	}}
	sleep -Seconds 1
}}
