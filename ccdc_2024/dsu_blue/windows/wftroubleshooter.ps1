
<#
  .SYNOPSIS
  Insitu Localhost Firewall Troubleshooter Requires Administrative permissions to interact with local windows firewall log.

  .DESCRIPTION
  This Script locates the domain firewall log and parses it using two different regular expressions to output relevant data to a .csv

  .PARAMETER Destination
  Specify the directory you want to send the CSV to

  .PARAMETER Expression
    Specify whether you want ALL Firewall logs or only the Deny logs
  
  .INPUTS
  None. You cannot pipe objects wftroubleshooter.ps1.

  .OUTPUTS
  wf_<date>.csv.

  .EXAMPLE
  PS> .\wftroubleshooters.ps1 -destination "C:\IT_Programs\" -expression "ALL"

  .EXAMPLE
  PS> .\wftroubleshooters.ps1 -destination "C:\" -expression "DENY"
#>

# Tyler Sternod 10/3/2022

param(
  [string]$destination,
  [string]$expression
)

$ALL = "(?<date>\d{4}\-\d{2}\-\d{2}\s\d{2}\:\d{2}\:\d{2})\s(?<action>\w+)\s(?<protocol>.*?)\s+(?<sourceIP>.*?)\s(?<destinationIP>.*?)\s(?<sourceport>\d+)\s(?<destinationport>\d+)"
$DENY = "(?<date>\d{4}\-\d{2}\-\d{2}\s\d{2}\:\d{2}\:\d{2})\s(?<action>DROP)\s(?<protocol>.*?)\s+(?<sourceIP>.*?)\s(?<destinationIP>.*?)\s(?<sourceport>\d+)\s(?<destinationport>\d+)"

$path = "C:\windows\system32\LogFiles\Firewall\domainfw.log"

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
  write-host "Program needs to be ran as an administrator" -ForegroundColor Yellow
  write-host "Exiting.." -ForegroundColor Yellow
  start-sleep 2
  # Relaunch as an elevated process:
  #Start-Process powershell.exe "-File",('"{0}"' -f $MyInvocation.MyCommand.Path),"-destination $destination -expression $expression" -Verb RunAs
  exit
}

 Function PromptUser{
 write-host ""
 write-host ""
 write-host "                       WF Domain Profile Troubleshooter                                "
 write-host "_______________________________________________________________________________________"
 $prompt= Read-Host -Prompt 'Type "Yes" to specify an output directory or Ctrl C to escape'
 If ($prompt -eq "Yes" -or ($prompt -eq "Y") -or ($prompt -eq "yes")){
 . Initializer}
 else{
    write-host "$prompt is not a valid option"
    PromptUser}
    }

Function Initializer{
$outputQ = Read-host -prompt "Output directory: "
If( Test-Path $outputQ){
$outpath = $outputQ}
else{
$defaultoutpath = "C:\It_Programs\"
write-host "Error locating $outputQ Defaulting to $Defaultoutpath" -foregroundColor Yellow
$outpath = $defaultoutpath}
$Q = Read-host -Prompt 'Collect all logs?: Y/N'
If ($Q -eq "Yes" -or ($Q -eq "Y") -or ($Q -eq "yes")){
$expression = $ALL }
else{
write-host "Defaulting to Deny logs"
$expression = $DENY
}
}

function Select-CaptureGroup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.PowerShell.Commands.MatchInfo[]]$InputObject
    )
    
    begin {}
    
    process {
        foreach ($input in $InputObject) {
            $input.Matches | ForEach-Object {
                $groupedOutput = New-Object -TypeName "PSCustomObject"
                $_.Groups | Where-Object  Name -ne "0" | ForEach-Object {
                    Add-Member -InputObject $groupedOutput -MemberType NoteProperty -Name $_.Name -Value $_.Value
                }
                $groupedOutput
            }
        }
    }
    
    end {}

}


Function Parser($file, $expression, $destination){
write-host "Collecting Logs..."
foreach($line in $file){
$line | select-string -pattern $expression | select-CaptureGroup | export-csv $destination -append
}
}

Function LocatePath($path){
if(Test-path $path){
$path = $path}
elseif(Test-path "C:\windows\system32\LogFiles\Firewall\pfirewall.log"){
$path = "C:\windows\system32\LogFiles\Firewall\pfirewall.log"}
else
{
write-host "Error Locating DomainFirewall Profile consider updating Path variable, or confirm firewall logging is enabled" -ForegroundColor Red
start-sleep 2
exit}
$file = get-content $path
}


Function Main{
$date = (Get-Date).ToString("yyyyMMdd")
. LocatePath $path
if($Expression -and $destination){
write-host "Running Firewall Collector script without prompts.."
write-host ""
If($expression -eq "ALL"){
$expression = $all}
elseif($expression -eq "DENY"){
$expression = $deny}
else{Write-host "Invalid expression response, defaulting to DENY output" -ForegroundColor Yellow
$expression = $Deny
}
If(Test-Path $destination){
$destination = $destination + "WF_$env:COMPUTERNAME$date.csv"}
else{write-host "Error locating $Destination" -ForegroundColor Red
exit}
Parser $file $expression $destination}
else{
. PromptUser
$destination = $outpath + "WF_$env:COMPUTERNAME$date.csv"
#write-host "$expression"
write-host "___________________________________________" 
write-host "Saving to $destination" -ForegroundColor Green
write-host "___________________________________________" 
Parser $file $expression $destination
}
}
. main
