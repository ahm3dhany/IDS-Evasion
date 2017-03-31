# Search for rules:
Select-String "cve,2014-3120" C:\Snort\rules\*

# Start Snort
## console mode
C:\Snort\bin\snort.exe -i 1 -c C:\Snort\etc\snort.conf -A console -k none

## fast mode
C:\Snort\bin\snort.exe -i 1 -c C:\Snort\etc\snort.conf -A fast -k none
