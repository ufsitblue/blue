#!/bin/sh

rootdir="/home/"

ssn_pattern='[0-9]\{3\}-[0-9]\{2\}-[0-9]\{4\}'
# May not work with 374355011240344, 373116614411000?
ccn_pattern='[0-9]\{4\}-[0-9]\{4\}-[0-9]\{4\}-[0-9]\{4\}\|[0-9]\{16\}'

find "$rootdir" -type f \( -name "*.txt" -o -name "*.csv" \) -exec sh -c '
    file="$1"
    grep -Hn "$2" "$file" | while read -r line; do echo "$file:SSN:$line"; done
' sh '{}' "$ssn_pattern" \;

find "$rootdir" -type f \( -name "*.txt" -o -name "*.csv" \) -exec sh -c '
    file="$1"
    grep -Hn "$2" "$file" | while read -r line; do echo "$file:CCN:$line"; done
' sh '{}' "$ccn_pattern" \;