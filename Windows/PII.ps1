#BECAUSE DEFAULT SETTINGS RESTRICT PS1 EXECUTION COPY PASTE LINES INTO POWERSHELL

#specifies PII file extensions to search for
$extensions = @('*.jpg', '*.txt', '*.csv', '*.xlsx', '*.pdf', '*.docx')

#edit -Path parameter to search the directory and subdirectories make sure directory is reachable from current directory
Get-ChildItem -Path "Desktop" -Include $extensions -File -Recurse | Select-Object FullName