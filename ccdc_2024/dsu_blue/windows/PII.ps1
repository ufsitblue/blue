$stopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
$stopWatch.Start()

$format = @("\d{3}[)]?[-| |.]\d{3}[-| |.]\d{4}", "\d{3}[-| |.]\d{2}[-| |.]\d{4}", "\s[A|a]ve[\s|.]", "[A|a]venue", "\s[S|s]t[\s|.]", "[S|s]treet", "\s[B|b]lvd[\s|.]", "[B|b]oulevard", "\s[R|r]d[\s|.]", "[R|r]oad", "\s[D|d]r[\s|.]", "[D|d]rive", "[C|c]ourt", "\s[C|c]t[\s|.]", "[H|h]ighway", "\s[H|h]wy[\s|.]", "[L|l]ane", "[L|l]n[\s|.]", "[W|w]ay", "Interstate")
$ErrorActionPreference = "SilentlyContinue"

$os = (Get-CimInstance Win32_OperatingSystem).Version
if ($os -ge '10.0.17134') {
    $recBin = 'C:\$Recycle.Bin'
} elseif ($os -ge '6.2.9200' -and $os -lt '10.0.17134') {
    $recBin = 'C:\$Recycle.Bin'
} else {
    $recBin = 'C:\RECYCLER'
}
Write-Host "`nOS Version: $os`nRecycle Bin: $recBin" -ForegroundColor Blue

$netShares = Get-WmiObject Win32_Share | Where-Object { $_.Path -notlike 'C:\' -and $_.Path -notlike 'C:\Windows'-and $_.Path -notlike '' } | Select-Object -ExpandProperty Path
Write-Host "`nNetwork Shares:" -ForegroundColor Blue
if ($netShares.Count -eq 0) {
    Write-Host "No network shares available." -ForegroundColor Yellow
} else {
    foreach ($share in $netShares) {
        Write-Host $share -ForegroundColor Blue
    }
}

Write-Host "`nPII Files: (This may take a few minutes. Don't turn off your PC.)" -ForegroundColor Blue
$localPaths = @("C:\Users\*\Downloads", "C:\Users\*\Documents", "C:\Users\*\Desktop", "C:\inetpub", "C:\Users\*\Pictures", "C:\Windows\Temp", "$recBin")
$paths = $localPaths + $netShares | Select-Object -Unique
$printedFiles = @{}

foreach ($path in $paths)
{
   foreach ($num in $format)
   {
       Get-ChildItem -Recurse -Force -Path "$path" | Where-Object {($_.Name -ne 'desktop.ini') -and (findstr.exe /mprc:. $_.FullName 2>$null)} | 
       ForEach-Object {
           if ((Select-String -Path $_.FullName -Pattern $num).Matches -and !$printedFiles.ContainsKey($_.FullName)) {
               Write-Host "`"$((Select-String -Path $_.FullName -Pattern $num).Matches.Value)`" - $($_.FullName)" -ForegroundColor Red
               $printedFiles[$_.FullName] = $true
           }
       }
   }
   Write-Host "$path Completed." -ForegroundColor Green
}

$stopWatch.Stop()
$total = $stopWatch.Elapsed
$itemCount = $printedFiles.Count
if ($printedFiles.Count -gt 0) {
    Write-Host "`n`nFound $itemCount PII files in $total" -ForegroundColor Green
 } else {
    Write-Host "`n`nNo PII files found in $total" -ForegroundColor Red
 }
 
