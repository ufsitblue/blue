function Invoke-Baseline {
    param (
        [Parameter(Mandatory)]
        [String] $Board,
        [Parameter(Mandatory)]
        [String] $System
    )
    if ($null -eq (Get-TrelloCard -board (Get-TrelloBoard -name $board) | Where-Object {$_.name -like "*$(hostname)*"})){
        Write-Host "A card containing $(hostname) does not exist, please use Invoke-Inventory to create a new card"
    } else{
        if ($System -eq 'Linux'){
            # Linux Baseline Scripts
            
        }
        if ($System -eq 'Windows'){
            # Windows Baseline Scripts
            Invoke-SecureBaseline
        }
        else{
            Write-Error 'System must be Windows or Linux'
        }
    }
}
