import re
from urllib.parse import urlparse, parse_qs
import base64

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

    dangerous_terms = [
        'app/', 'pl/', 'io/', 'firebaseapp', 'repl.co'
    ]

    risky_tlds = [
        'me', 'ru', 'cn', 'zip', 'top', 'work', 'click', 'org/',
        'tk', 'gq', 'ga', 'cf', 'com/', 'html', 'php', 'ml'
    ]

    #this loop checks the link for the above patterns
    for pattern in sql_injection_patterns + suspicious_chars:
        if re.search(pattern, link):
            return "Link suspected to use SQL Injection. Do not click."
        
    #checks for suspicious domains
    url = urlparse(link)
    domain = url.hostname
    scheme = url.scheme

    if domain:  
        #check for raw IP addresses
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            return "Link uses a raw IP address instead of a domain. Can be suspicious, approach with caution."
        
        #check for risky TLDs
        for tld in risky_tlds:
            if link.lower().endswith(tld):
                return f"Link uses a risky TLD: '.{tld}'. Do not click."
    
    #below checks for redirects in link
    query_params = parse_qs(url.query)
    redirect_keys = ['url', 'redirect', 'next', 'dest']

    for key in redirect_keys:
        if key in query_params:
            redirect_url = query_params[key][0]
            redirect_domain = urlparse(redirect_url).hostname
            if redirect_domain and redirect_domain != domain:
                return f"Link may redirect you from {domain} to another site. Do not click."
            
    for val_list in query_params.values():
        for val in val_list:
            if is_base64(val):
                return "String in Base64 inside URL, possibly hiding payload."
            
    #check for if link uses http and not https
    if scheme.lower() == "http":
        return "Link uses unencrypted HTTP. Risk of interception or spoofing."
    
    #checks for dangerous terms found through testing
    for term in dangerous_terms:
        if term in link:
            return "Link confirmed dangerous. Do not click."
    
    return "Nothing suspicious detected."

def is_base64(s):
    try:
        if len(s) < 8 or len(s) % 4 != 0:
            return False
        return base64.b64encode(base64.b64decode(s)).decode() == s
    except Exception:
        return False

#test
link = input("Paste your suspected link here: ")
result = phish_checker(link)
print(result)