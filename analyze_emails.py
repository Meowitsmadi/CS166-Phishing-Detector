import requests
from dotenv import load_dotenv
import json
import os
import re
from email import *
from email.utils import parseaddr

load_dotenv()
API_KEY = os.getenv("VIRUS_TOTAL_API_KEY")

# Use a dataset that contains phishing .eml files to parse
def parse_email(emlFile):
    try:
        with open(emlFile, "r") as email:
            msg = message_from_file(email)
        return msg
    except Exception as e:
        print(f"Error: {e}")

def scan_domain(sender_addr):
    # Check the sender's domain against VirusTotal API
    domain = sender_addr.split("@")[1]
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY,
    }
    response = requests.get(url, headers=headers)
    response_dict = json.loads(response.text)

    results = response_dict["data"]["attributes"]["last_analysis_stats"]
    print(f"Results of the domain analysis: {results}")
    if results["malicious"] >= 1 or results["suspicious"] >= 1:
        print("One or more scans found the domain to be malicous or suspicious\n")
        return True
    else:
        print("The domain was not found to be malicious or suspicious\n")
        return False

def analyze_email(email):
    phishing_count = 0
    safe_count = 0
    msg = parse_email(email)
    sender_name, sender_addr = parseaddr(msg["From"])
    print(f"Sender's Name: {sender_name}, Sender's address: {sender_addr}\n")

    domain_scan = scan_domain(sender_addr)
    if domain_scan:
        phishing_count += 1
    else:
        safe_count += 1

    for header in msg.keys():
        if header == "Return-Path": # Check Return-Path (where email is returned incase of failure)
            # print(f"Email Return Path: {msg['Return-Path']}")
            if msg["Return-Path"] == sender_addr:
                print("Sender and return path match.")
                safe_count += 1
            else:
                print("Sender and return path do not match.")
                phishing_count += 1
        elif header == "Authentication-Results": # Check Authentication-Results
            results = msg["Authentication-Results"]

            dkim = re.search(r"dkim=([^\s;]+)", results)
            dkim_value = dkim.group(1) if dkim else None

            spf = re.search(r"spf=([^\s;]+)", results)
            spf_value = spf.group(1) if spf else None

            if dkim_value == "fail" or spf_value == "fail":
                print("Email failed DKIM and/or SPF authentication")
                phishing_count += 1
            if dkim_value == "none" or spf_value == "none":
                print("Email did not go through DKIM or SPF authentication")
                phishing_count += 1
            elif dkim_value == "pass" and spf_value == "pass":
                print("Email went through DKIM and SPF authentication")
                safe_count += 1
    
    safe_percent = int(safe_count / (phishing_count + safe_count) * 100)
    phish_percent = int(phishing_count / (phishing_count + safe_count) * 100)
    
    if phishing_count >= safe_count:
        return f"This email did not pass {phish_percent}% of our phishing checks and exhibits phishing characteristics in its headers."
    else:
        return f"This email passed {safe_percent}% of our phishing checks."


print(analyze_email("/Users/MeowItsMadi/Desktop/phish-test-email.eml"))
    
