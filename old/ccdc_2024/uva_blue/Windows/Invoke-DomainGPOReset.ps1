# Create report
Get-GPOReport -All -ReportType Html -Path "C:\All-GPOs.html"

# Prompt user to decide which GPOs to disalbe
$DomainGPO = Get-GPO -All
foreach ($GPO in $DomainGPO) {
    $Ans = Read-Host "Reset $($GPO.DisplayName) (y/N)?"
    if ($Ans.ToLower() -eq "y") {
        $GPO.gpostatus = "AllSettingsDisabled"
    }
}
gpupdate.exe /force