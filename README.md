# **IDS-Evasion**
## **Attacks Snort could identify**
### ElasticSearch Dynamic Script Arbitrary Java Execution ([CVE-2014-3120](https://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2014-3120)):
Most of snort rules are *commented out* [by default](https://www.snort.org/faq/why-are-rules-commented-out-by-default). So we need to search for them either by product name (i.e. in our case "ElasticSearch") or even better by CVE (i.e. in our case "CVE-2014-3120") and *uncomment* them (i.e. remove the "#" character from the beginning of the line), in order to enable them. We can use the `Select-String` command (the "grep-like" command in powershell) for that purpose:
![powershell_search_cve](screenshots/ElasticSearch/powershell_search_cve.png)
Running snort:
![powershell_running_snort](screenshots/ElasticSearch/powershell_running_snort.png)
We'll use "exploit/multi/elasticsearch/script_mvel_rce" module to exploit this vulnerability (you can find this module using "search ElasticSearch" or "search CVE-2014-3120").
Setting module options, checking if the target is vulnerable and finally running the module:
![metasploit_set_and_exploit](screenshots/ElasticSearch/metasploit_set_and_exploit.png)
Checking Snort:
![powershell_snort_detecting_elastic_rce](screenshots/ElasticSearch/powershell_snort_detecting_elastic_rce.png)
As we see, snort identified the attack successfully.

### FTP Authentication Scanner ([CVE-1999-0502](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-0502)):
![powershell_no_result](screenshots/FTP_login/powershell_no_result.png)
![ftp_reconnaissance](screenshots/FTP_login/ftp_reconnaissance.png)
![unsuccess_login_rule](screenshots/FTP_login/unsuccess_login_rule.png)
![bruteforce_rule](screenshots/FTP_login/bruteforce_rule.png)
![metasploit_set_and_exploit](screenshots/FTP_login/metasploit_set_and_exploit.png)
![awk_no_of_lines](screenshots/FTP_login/awk_no_of_lines.png)
![powershell_snort_detect_ftp](screenshots/FTP_login/powershell_snort_detect_ftp.png)
![hydra](screenshots/FTP_login/hydra.png)
![powershell_snort_detect_hydra](screenshots/FTP_login/powershell_snort_detect_hydra.png)

