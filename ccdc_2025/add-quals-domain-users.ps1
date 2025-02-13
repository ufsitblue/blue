$defaultPassword = "Congratulations21"
$ouPath = "CN=Users,DC=nerv,DC=ccdc" # change to match your AD domain

# admin Users
$adminUsers = @(
    "blackteam_adm",
    "jeremy.rover",
    "emily.chen",
    "john.taylor",
    "anna.wilson",
    "maxwell.starling",
    "william.wilson",
    "laura.harris",
    "matthew.taylor",
    "jack.harris",
    "melissa.chen",
	"alan.chen"
)

# regular Users
$regularUsers = @(
    "danielle.wilson",
    "ashley.lee",
    "alan.taylor",
    "dave.harris",
    "tom.harris",
    "christine.wilson",
    "tony.taylor",
    "tiffany.harris",
    "heather.chen",
    "mark.wilson",
    "amy.wilson",
    "jeff.taylor",
    "sarah.taylor",
    "alan.harris",
    "tiffany.wilson",
    "terry.chen",
    "amy.taylor",
    "chris.harris",
    "james.taylor",
    "rachel.harris",
    "kathleen.chen",
    "julie.wilson",
    "michael.chen",
    "emily.lee",
    "sharon.harris",
    "rachel.wilson",
	"terry.wilson"
)

Function Add-ADUser($username, $isAdmin) {
    $firstName = $username -replace "\..*", ""
    $lastName = $username -replace ".*\.", ""
    
    if ($username -eq "blackteam_adm") {
        $firstName = "Blackteam"
        $lastName = "Administrator"
    }

    $displayName = "$firstName $lastName"
    $password = ConvertTo-SecureString $defaultPassword -AsPlainText -Force

    New-ADUser -SamAccountName $username -UserPrincipalName "$username@nerv.ccdc" `
        -Name $displayName -GivenName $firstName -Surname $lastName -DisplayName $displayName `
        -Path $ouPath -AccountPassword $password -Enabled $true -PasswordNeverExpires $true -PassThru
    
    if ($isAdmin) {
        Add-ADGroupMember -Identity "Domain Admins" -Members $username
    }
}

foreach ($user in $adminUsers) {
    Add-ADUser -username $user -isAdmin $true
}

foreach ($user in $regularUsers) {
    Add-ADUser -username $user -isAdmin $false
}
