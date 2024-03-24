echo "Note that new sliver binaries no longer include the string \"sliver\""
# Put all binaries larger than 1Mb into array
## TAKE NOTE OF EXCLUSION
mapfile -d $'\0' files < <(sudo find / -type f -executable -size +1M -print0 2>/dev/null)
# Check each file
for i in "${files[@]}";
do 
    # Does it contain the string "sliver"
    if [[ $(strings $i 2>/dev/null | grep 'sliver' 2>/dev/null) ]]; then   
        echo "Detected Potential Sliver Binary : $i"
    else
        continue
    fi
done
