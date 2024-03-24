#!/bin/bash
# @d_tranman/Nigel Gerald/Nigerald

commands=("jq" "tmux" "bash" "sshpass")

READY=1
for cmd in "${commands[@]}"; do
  if ! command -v "$cmd"  >/dev/null 2>&1 ; then
    READY=0
    echo "Missing $cmd"
  fi
done

if [ "$READY" -eq 0 ]; then
    exit 1
fi

if [ -z "$1" ]; then
    echo "Specify a name for the session"
    exit 1
fi

session_name="$1"
json_file="config.json"
count=0
windows=0
extrapanes=0

count=$(jq -c '.[]' config.json | wc -l)

windows=$((count / 4))
windows=$((windows+1))

echo "We are going to need $count ssh sessions"
echo "tmux session will have $windows windows"

tmux new-session -d -s $session_name
for ((counter = $windows; counter > 0; counter--)); do
  tmux split-window -h -t $session_name
  tmux split-window -v -t $session_name
  tmux split-window -v -t $session_name
  tmux select-layout -t $session_name tiled
  if [[ counter -gt 1 ]]; then
    tmux new-window -t $session_name
  fi
done

rm ~/.ssh/known_hosts

count=0
while IFS= read -r row; do
  ip=$(echo "$row" | jq -r '.IP')
  username=$(echo "$row" | jq -r '.Username')
  password=$(echo "$row" | jq -r '.Password')
  tmux send-keys -t $session_name:$((count / 4)).$((count % 4)) "sshpass -p '$password' ssh -o StrictHostKeyChecking=no -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss,ssh-rsa $username@$ip" C-m
  count=$((count+1))
done < <(jq -c '.[]' "$json_file")
count=$((count-1))
echo "Background your current session (or create a new tab/ssh connection) and attach to the session with:

tmux attach-session -t $session_name
"
echo "Copy paste the block below to create a funny command dispatcher:"

echo "
/bin/bash -c '
export session_name=\"$session_name\"
export count=$count
while IFS= read -e -p \"NIGERALD DISPATCHER>> \" command ; do
  history -s \"\$command\"
  for i in \`seq 0 1 \$count\`; do
    if [ \"\$command\" = \"exit\" ]; then
      exit 1
    fi
    tmux send-keys -t \$session_name:\$((i / 4)).\$((i % 4)) \"\$command\" C-m
  done
done
'
"
trap "" SIGINT SIGTSTP exit; 
while IFS= read -e -p "NIGERALD DISPATCHER>> " command ; do
  history -s "$command"
  for i in `seq 0 1 $count`; do
    if [ "$command" = "exit" ]; then
      exit 1
    fi
    tmux send-keys -t $session_name:$((i / 4)).$((i % 4)) "$command" C-m
  done
done
