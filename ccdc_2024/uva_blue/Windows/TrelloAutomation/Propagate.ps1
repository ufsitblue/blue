$ErrorActionPreference = "Continue"
Copy-Item -Path "$env:ProgramFiles\blue-main\Windows\bins\" -Destination "C:\Windows\System32\bins\" -Recurse -Force

Get-ChildItem $env:ProgramFiles\blue-main\Windows -Recurse | Unblock-File

$Computers = Get-ADComputer -filter * -Properties * | Where-Object OperatingSystem -Like "*Windows*" | Select-Object -ExpandProperty Name
$Localhost = hostname

foreach ($Computer in $Computers) {
    if (!($Computer -eq $Localhost)) {
        Write-Host "[INFO] Preparing to WinRM to: $Computer" -ForegroundColor Green
        Robocopy.exe $env:ProgramFiles\blue-main\Windows\bins \\$Computer\ADMIN$\System32\bins
    }
    else {
        Write-Host "[ERROR] Failed to copy to $Computer" -ForegroundColor Red
    }
}
