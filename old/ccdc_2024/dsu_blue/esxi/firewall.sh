$f get
$f load
$f set -d false 
$f set -e true
$f ruleset set -a false -r sshServer &&
$f ruleset allowedip add -r sshServer -i IP; sleep 5; $f ruleset set -a true -r sshServer

for r in $($f ruleset list | tail -n +3 | cut -d" " -f1 | grep -v "vSphereClient"); do
    $f ruleset set -e true -r $r
    $f ruleset set -a false -r $r
done &

$f ruleset set -a true -r dhcp 
$f ruleset set -a true -r syslog 
