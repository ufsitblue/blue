# Change passwords.
# TODO: generate CSVs for the password changes according to the specified format (https://anonymfile.com/6Q6D/seccdc-24-team-packet.pdf)

# List of all scored admin/normal users.  Separated for ease of use later on
$AdminUsers=@("elara.boss" "sarah.lee" "lisa.brown" "michael.davis" "emily.chen" "tom.harris" "bob.johnson" "david.kim" "rachel.patel" "dave.grohl" "kate.skye" "leo.zenith" "jack.rover")
$NormalUsers=@("lucy.nova" "xavier.blackhole" "ophelia.redding" "marcus.atlas" "yara.nebula" "parker.posey" "maya.star" "zachary.comet" "quinn.jovi" "nina.eclipse" "alice.bowie" "ruby.rose" "owen.mars" "bob.dylan" "samantha.stephens" "parker.jupiter" "carol.rivers" "taurus.tucker" "rachel.venus" "emily.waters" "una.veda" "ruby.starlight" "frank.zappa" "ava.stardust" "samantha.aurora" "grace.slick" "benny.spacey" "sophia.constellation" "harry.potter" "celine.cosmos" "tessa.nova" "ivy.lee" "dave.marsden" "thomas.spacestation" "kate.bush" "emma.nova" "una.moonbase" "luna.lovegood" "frank.astro" "victor.meteor" "mars.patel" "grace.luna" "wendy.starship" "neptune.williams" "henry.orbit" "ivy.starling")

#Create Arrays to hold local and domain users information
$LocalUsers=@()
$DomainUsers=@()

function Generate-Password {
    $PasswordLength = 23
    $PasswordChars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ0123456789@#$%&!?:*-+="
    $Password = ""
    For ($i=0; $i -lt $PasswordLength; $i++) {
        $RandomChar = Get-Random -Maximum $PasswordChars.Length
        $Password += $PasswordChars[$RandomChar]
    }
    return $Password
}

foreach ($User in $AdminUsers) {
    $LocalUser = Get-LocalUser -Name $User -ErrorAction SilentlyContinue
    $DomainUser = Get-ADUser -Filter { SamAccountName -eq $User } -ErrorAction SilentlyContinue
    $NewPassword = Generate-Password
    
    if ($LocalUser) {    
        Set-LocalUser -Name $User -Password (ConvertTo-SecureString $NewPassword -AsPlainText -Force) | Out-Null
        $LocalUsers += [PSCustomObject]@{
            UserName = $User
            Password = $NewPassword
        }
    }
    if ($DomainUser) {
        Set-ADAccountPassword -Identity $User -NewPassword (ConvertTo-SecureString -AsPlainText $newPassword -Force)
        $DomainUsers += [PSCustomObject]@{
            UserName = $User
            Password = $NewPassword
        }
    }
}

foreach ($User in $NormalUsers) {
    $LocalUser = Get-LocalUser -Name $User -ErrorAction SilentlyContinue
    $DomainUser = Get-ADUser -Filter { SamAccountName -eq $User } -ErrorAction SilentlyContinue
    $NewPassword = Generate-Password
    
    if ($LocalUser) {    
        Set-LocalUser -Name $User -Password (ConvertTo-SecureString $NewPassword -AsPlainText -Force) | Out-Null
        $LocalUsers += [PSCustomObject]@{
            UserName = $User
            Password = $NewPassword
        }
    }
    if ($DomainUser) {
        Set-ADAccountPassword -Identity $User -NewPassword (ConvertTo-SecureString -AsPlainText $newPassword -Force)
        $DomainUsers += [PSCustomObject]@{
            UserName = $User
            Password = $NewPassword
        }
    }
}

Write-Output "Printing local users csv:"
$LocalUsers | ForEach-Object { "checkname,$($_.UserName),$($_.Password)" }
Write-Output "Remember to replace 'checkname' with the appropriate host-service"
Write-Output ""
Write-Output "Printing domain users csv:"
$DomainUsers | ForEach-Object { "checkname,$($_.UserName),$($_.Password)" }
Write-Output "Remember to replace 'checkname' with the appropriate host-service"
Write-Output "However, since we changed AD passwords, this file may need to be copied to many services"
