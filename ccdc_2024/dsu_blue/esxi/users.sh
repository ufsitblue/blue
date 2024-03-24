read p
# TODO: make p random password, and print with preprocessor directives
for u in $(cat /etc/passwd | cut -d ":" -f1 | grep -v "root"); do
    echo -e "$p\n$p" | passwd -s $u
done; unset p
