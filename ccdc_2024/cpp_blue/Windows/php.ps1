$Error.Clear()
$ErrorActionPreference = "Continue"

Write-Output "#########################"
Write-Output "#                       #"
Write-Output "#          PHP          #"
Write-Output "#                       #"
Write-Output "#########################"


Write-Output "#########################"
Write-Output "#    Hostname/Domain    #"
Write-Output "#########################"
Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select-Object Name, Domain
Write-Output "#########################"
Write-Output "#          IP           #"
Write-Output "#########################"
Get-WmiObject Win32_NetworkAdapterConfiguration | ? {$_.IpAddress -ne $null} | % {$_.ServiceName + "`n" + $_.IPAddress + "`n"}
######### Disable PHP Functions #########
$php = Get-ChildItem C:\ php.exe -recurse -ErrorAction SilentlyContinue | ForEach-Object {& $_.FullName --ini | Out-String}
$ConfigFiles = @()
ForEach($OutputLine in $($php -split "`r`n")) {
    if ($OutputLine -match 'Loaded') {
        ForEach-Object {
            $ConfigFiles += ($OutputLine -split "\s{9}")[1]
        }
    }
}
$ConfigString_DisableFuncs = "disable_functions=exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source"
$COnfigString_FileUploads = "file_uploads=off"
Foreach ($ConfigFile in $ConfigFiles) {
    Add-Content $ConfigFile $ConfigString_DisableFuncs
    Add-Content $ConfigFile $ConfigString_FileUploads
    Write-Output "$Env:ComputerName [INFO] PHP functions disabled in $ConfigFile"
}

$Error | Out-File $env:USERPROFILE\Desktop\php.txt -Append -Encoding utf8