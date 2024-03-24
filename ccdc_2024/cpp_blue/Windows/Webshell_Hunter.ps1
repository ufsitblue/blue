while ($true) {
    Get-WmiObject -Class Win32_Process -Filter "name ='cmd.exe' OR name ='powershell.exe'" | Select-Object ParentProcessId | ForEach-Object {
        Write-Host "[DEBUG] Parent PID: $($_.ParentProcessId)"
        $AllParentNames = Get-AllParentProcessNames($_.ParentProcessId)
        if (($AllParentNames -contains "w3wp.exe") -or ($AllParentNames -contains "httpd.exe")) {
            foreach ($ParentName in $AllParentNames) {
                Write-Host "$ParentName`n |_`t"
            }
            Write-Host "Webshell found! PID: $($_.ProcessId)"

        }
    }
}

function Get-AllParentProcessNames ($ParentId) {
    $ParentProcessNames = @()

    while ($ParentId -ne 0) {
        $ParentProcessNames += (Get-Process -Id $ParentId).Name
        $ParentId = (Get-WmiObject -Class Win32_Process -Filter "ProcessId = '$ParentId'").ParentProcessId
    }

    return $ParentProcessNames
}