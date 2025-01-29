$ErrorActionPreference = "Continue"
$Computers = Get-ADComputer -filter * -Properties * | Where-Object OperatingSystem -Like "*Windows*" | Select-Object -ExpandProperty DNSHostname
$Denied = @()
foreach ($Computer in $Computers) {
    $session = New-PSSession -ComputerName $Computer 
    if ($session) {
        $session | Remove-PSSession
        Write-Host "[INFO] WinRM enabled: $Computer" -ForegroundColor Green
    }
    else {
        $Denied += $Computer
        Write-Host "[ERROR] Failed: $Computer" -ForegroundColor Red
    }
}
if ($Denied.Count -eq 0) {
    Write-Host "[INFO] All computers have WinRM enabled" -ForegroundColor Green
} else {
    Write-Host "[INFO] The following computers have WinRM disabled:" -ForegroundColor Red
    $Denied | Out-String
}