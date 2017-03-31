# accurate than "wc -l" command (i.e. newline character issue)
awk ' END { print NR } ' metasploitable3usernames.txt