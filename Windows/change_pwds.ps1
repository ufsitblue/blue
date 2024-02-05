# Change passwords.
# TODO: generate CSVs for the password changes according to the specified format (https://anonymfile.com/6Q6D/seccdc-24-team-packet.pdf)

# List of all scored admin/normal users.  Separated for ease of use later on
$AdminUsers=@("elara.boss" "sarah.lee" "lisa.brown" "michael.davis" "emily.chen" "tom.harris" "bob.johnson" "david.kim" "rachel.patel" "dave.grohl" "kate.skye" "leo.zenith" "jack.rover")
$NormalUsers=@("lucy.nova" "xavier.blackhole" "ophelia.redding" "marcus.atlas" "yara.nebula" "parker.posey" "maya.star" "zachary.comet" "quinn.jovi" "nina.eclipse" "alice.bowie" "ruby.rose" "owen.mars" "bob.dylan" "samantha.stephens" "parker.jupiter" "carol.rivers" "taurus.tucker" "rachel.venus" "emily.waters" "una.veda" "ruby.starlight" "frank.zappa" "ava.stardust" "samantha.aurora" "grace.slick" "benny.spacey" "sophia.constellation" "harry.potter" "celine.cosmos" "tessa.nova" "ivy.lee" "dave.marsden" "thomas.spacestation" "kate.bush" "emma.nova" "una.moonbase" "luna.lovegood" "frank.astro" "victor.meteor" "mars.patel" "grace.luna" "wendy.starship" "neptune.williams" "henry.orbit" "ivy.starling")

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
    $NewPassword = Generate-Password
    Set-LocalUser -Name $user -Password (ConvertTo-SecureString $NewPassword -AsPlainText -Force)
    Write-Output "checkname,$User,$NewPassword"
}

foreach ($User in $NormalUsers) {
    $NewPassword = Generate-Password
    Set-LocalUser -Name $user -Password (ConvertTo-SecureString $NewPassword -AsPlainText -Force)
    Write-Output "checkname,$User,$NewPassword"
}

Write-Output "Finished changing passwords. Remember to copy the above to a file, replacing every 'checkname' with the correct host/service (i.e. StarDNS-DNS)"
Write-Output "Hint: use ctrl + f"
