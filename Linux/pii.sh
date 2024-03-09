!/bin/sh

rootdir="/home/"
ssn_pattern='[0-9]\{3\}-[0-9]\{2\}-[0-9]\{4\}'

# Search for SSNs in various file types
find "$rootdir" -type f \( -name "*.jpg" -o -name "*.txt" -o -name "*.csv" -o -name "*.xlsx" -o -name "*.pdf" -o -name "*.docx" \) -exec sh -c '
    file="$1"
    if [ "${file##*.}" = "jpg" ]; then
        echo "$file is a JPG file. Skipping SSN search for image files."
    else
        grep -Hn "$2" "$file" | while read -r line; do echo "$file:SSN:$line"; done
    fi
' sh '{}' "$ssn_pattern" \;

# Summarize
echo "Summary:"
total_files=$(find "$rootdir" -type f \( -name "*.jpg" -o -name "*.txt" -o -name "*.csv" -o -name "*.xlsx" -o -name "*.pdf" -o -name "*.docx" \) | wc -l)
total_ssns=$(grep -r -E "$ssn_pattern" "$rootdir" | grep -v '\.jpg$' | wc -l)

echo "Total SSNs found: $total_ssns"
echo "Total files searched: $total_files"
