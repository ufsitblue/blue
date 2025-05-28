# TMUX CONFIG
cat << 'EOF' > $HOME/.tmux.conf
bind -n C-x setw synchronize-panes
setw -g mode-keys vi 
bind -n C-g select-pane -t :.+ \; resize-pane -Z
setw -g window-status-current-format \
    '#{?pane_synchronized,#[bg=white],}#I:#W' 
set -g pane-border-status bottom 
bind T command-prompt -p \
    "New title:" 'select-pane -T "%%"' 
set -g mouse on 
EOF
