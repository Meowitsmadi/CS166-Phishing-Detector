import re
from urllib.parse import urlparse

#TODO Analyze email address
#Done: Analyze URL/links

def phish_checker(link):
    
    #common patterns in phishing links
    sql_injection_patterns = [                               #below is for capitalized commands like INSERT and UPDATE
        r"(?i)\bUNION\s+SELECT\b",                           #UNION SELECT
        r"(?i)\bSELECT\s+.*FROM\b",                          #SELECT ... FROM
        r"(?i)DROP\s+TABLE\b",                               #DROP TABLE
        r"(?i)\bINSERT\s+INTO\b",                            #INSERT INTO
        r"(?i)\bUPDATE\s+.*SET\b",                           #UPDATE ... SET
        r"(?i)\bWHERE\s+.*\s*=\s*.*",                        #WHERE ... = ...
        r"(?i)\bexec(\s|\+)+(s|x)p\w+\b"                     #stored procedure call
    ]

    suspicious_chars = [
        r"(\%27)|(\')|(\-\-)|(\%3B)|(;)",  #potentially dangerous encoding
    ]

    #this loop checks the link for the above patterns
    for pattern in sql_injection_patterns + suspicious_chars:
        if re.search(pattern, link):
            return "Suspicious link detected! Suspected to use SQL Injection."
        
    #checks for suspicious domains
    url = urlparse(link)
    domain = url.netloc
    if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
        return "Link uses a raw IP address instead of a domain. Can be suspicious, approach with caution."
    
    return "Nothing suspicious detected."

#test
link = input("Paste your suspected link here: ")
result = phish_checker(link)
print(result)