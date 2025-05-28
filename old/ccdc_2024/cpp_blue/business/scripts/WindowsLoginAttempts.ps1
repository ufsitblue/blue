# Function to retrieve successful login attempts from the Windows event log
Function Get-SuccessfulLogins {
    param(
        [Parameter(Mandatory=$true)]
        [string]$logType
    )
    $events = Get-WinEvent -FilterHashtable @{
        LogName = $logType
        ID = 4624
    }
    return $events
}

# Fetch successful logins from the Security event log
$successfulLogins = Get-SuccessfulLogins -logType 'Security'

# Extract username from event details and count occurrences
$users = @{}
foreach ($event in $successfulLogins) {
    $userName = $event.Properties[5].Value
    if ($users.ContainsKey($userName)) {
        $users[$userName]++
    } else {
        $users[$userName] = 1
    }
}

# Sort users by login count and print the top 10
$sortedUsers = $users.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
Write-Host "Top 10 users with the most frequent logins:"
foreach ($user in $sortedUsers) {
    Write-Host "$($user.Name) : $($user.Value) logins"
}