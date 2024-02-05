# Change passwords.
# TODO: change user passwords in the competition doc. Right now, it's changing all users above UID 1000 (POTENTIALLY DANGEROUS)
# TODO: generate CSVs for the password changes according to the specified format (https://anonymfile.com/6Q6D/seccdc-24-team-packet.pdf)


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

Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.PasswordRequired -eq $true -and $_.PrincipalSource -eq "Local" } | ForEach-Object {
    $NewPassword = Generate-Password
    $_ | Set-LocalUser -Password (ConvertTo-SecureString $NewPassword -AsPlainText -Force)
    Write-Output "[+] Changed password for $($_.Name) to $NewPassword"
}

