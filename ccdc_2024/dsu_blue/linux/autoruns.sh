# Proflies, be gone

mv /etc/prof{i,y}le.d 2>/dev/null
mv /etc/prof{i,y}le 2>/dev/null
for f in '.profile' '.bashrc' '.bash_login'; do
    find /home /root -name "$f" -exec rm {} \;
done
