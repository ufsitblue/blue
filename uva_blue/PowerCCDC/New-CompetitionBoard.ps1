function New-CompetitionBoard {
    param (
        [Parameter(Mandatory)]
        [String] $Board
    )

    if($null -ne (Get-TrelloBoard -Name $BoardName)) {
        Write-Host "A board with the name $BoardName already exists"
    }
    else {
    #Create Board
    New-TrelloBoard -Name $BoardName
    $BoardID = Get-TrelloBoard -Name $BoardName | Select-Object -Expand id

    #Create Lists
    $IncomingTicketsList = New-TrelloList -BoardID $BoardID -Name 'Incoming Tickets' -Position 1 | Select-Object -expand id
    New-TrelloList -BoardID $BoardID -Name 'Resolved Tickets' -Position 2 | Out-Null
    New-TrelloList -BoardID $BoardID -Name 'Linux' -Position 3 | Out-Null
    New-TrelloList -BoardID $BoardID -Name 'Windows' -Position 4 | Out-Null
    New-TrelloList -BoardID $BoardID -Name 'Networking' -Position 5 | Out-Null
    New-TrelloList -BoardID $BoardID -Name 'Business' -Position 6 | Out-Null
    New-TrelloList -BoardId $BoardID -Name 'Runners' -Position 7 | Out-Null

    #Create Cards for Incoming Tickets
    $BoxTemplateCard = New-TrelloCard -ListId $IncomingTicketsList -Name 'Box Template [DO NOT TOUCH]'
    New-TrelloCardChecklist -Card $BoxTemplateCard -Name Baselining -Item @('Inventory', 'Change Default Passwords', 'Configure Log Forwarding')

    return $BoardID

    }
}
