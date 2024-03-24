Get-VMHostAccount | Set-VMHostAccount -Password <Password>
Get-VMHostFirewallDefaultPolicy | Set-VMHostFirewallDefaultPolicy -AllowOutgoing $false -AllowIncoming $false
$ESXfw = (Get-EsxCLI).network.firewall
$ESXfw.set("false","false")
$ESXfw.ruleset.rule.list().Ruleset | Get-Unique | %{$esxfw.ruleset.set($false, $true, $_); $ESXfw.ruleset.allowedip.add("<LAPTOP IP>",$_)}
$ESXfw.ruleset.allowedip.list()
$ESXfw.set("false","true")
