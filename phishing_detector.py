import re
from urllib.parse import urlparse

# Analyze email address
# Analyze URL/links

def phish_checker(link):
    
    #common patterns in phishing links
    #TODO this currently suspects some normal links like canvas
    sql_injection_patterns = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",                              #for SQL meta characters
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",          #for common SQL injection characters
        r"\w*((\%27)|(\'))(\s)*((\%6F)|o|(\%4F))((\%72)|r|(\%52))",    
        r"exec(\s|\+)+(s|x)p\w+",                                      #for exec sp
        r"UNION(\s)+SELECT",                                           #below is for capitalized commands like INSERT and UPDATE
        r"SELECT(\s)+.*FROM",                                          # SELECT ... FROM
        r"DROP(\s)+TABLE",                                             # DROP TABLE
        r"INSERT(\s)+INTO",                                            # INSERT INTO
        r"UPDATE(\s)+.*SET",                                           # UPDATE ... SET
        r"WHERE(\s)+.*=",                                              # WHERE ... =
    ]

    #this loop checks the link for the above patterns
    for pattern in sql_injection_patterns:
        if re.search(pattern, link, re.IGNORECASE):
            return "Suspicious link detected! Suspected to use SQL Injection."
        
    #checks for suspicious domains
    url = urlparse(link)
    domain = url.netloc
    if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
        return "Link uses an IP address instead of a domain. Not immediately dangerous but approach with caution."
    
    return "Nothing suspicious detected."

#test
link = input("Paste your suspected link here: ")
result = phish_checker(link)
print(result)