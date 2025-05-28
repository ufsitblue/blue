undo() {
  sleep $1
  printf "\033[01mBlackout over!\033[00m\n"
  pfctl -d
}

kldload pf
pfctl -d
pfctl -f rules
for ip in $(netstat -an | grep 'ESTABLISHED' | grep 'tcp4' | grep '22' | awk '{print $5}' | cut -d'.' -f1-4 | sort -u); do
  pfctl -t imps -T add "$ip"
done
pfctl -f rules
undo 300 &
pfctl -e
