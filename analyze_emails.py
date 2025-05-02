import requests
from dotenv import load_dotenv
import json
import os
import re
from email import *
from email.utils import parseaddr
import streamlit as st

load_dotenv()
API_KEY = os.getenv("VIRUS_TOTAL_API_KEY")

# Use a dataset that contains phishing .eml files to parse
def parse_email(emlString):
    try:
        msg = message_from_string(emlString)
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
    st.write(f"Results of the domain analysis: {results}\n")
    if results["malicious"] >= 1 or results["suspicious"] >= 1:
        st.write(":x: One or more scans found the domain to be malicous or suspicious\n")
        return True
    else:
        st.write(":white_check_mark: The domain was not found to be malicious or suspicious\n")
        return False

def analyze_email(email):
    phishing_count = 0
    safe_count = 0
    msg = parse_email(email)

    st.write("**Checking the \"From\" Headers...**")
    sender_name, sender_addr = parseaddr(msg["From"])
    st.write(f"Sender's Name: {sender_name}\n Sender's address: {sender_addr}\n")

    st.write("**Scanning the Domain...**")
    domain_scan = scan_domain(sender_addr)
    if domain_scan:
        phishing_count += 1
    else:
        safe_count += 1

    for header in msg.keys():
        if header == "Return-Path": # Check Return-Path (where email is returned incase of failure)
            st.write("**Comparing the Return-Path to Sender...**")
            st.write(f"Email Return Path: {msg['Return-Path']}\n")
            if msg["Return-Path"] == sender_addr:
                st.write(":white_check_mark: Sender and return path match.\n")
                safe_count += 1
            else:
                st.write(":x: Sender and return path do not match.\n")
                phishing_count += 1
        elif header == "Authentication-Results": # Check Authentication-Results
            results = msg["Authentication-Results"]

            dkim = re.search(r"dkim=([^\s;]+)", results)
            dkim_value = dkim.group(1) if dkim else None

            spf = re.search(r"spf=([^\s;]+)", results)
            spf_value = spf.group(1) if spf else None

            st.write("**Reading Authentication-Results:**")
            if dkim_value == "fail" or spf_value == "fail":
                st.write(":x: Email failed DKIM and/or SPF authentication\n")
                phishing_count += 1
            if dkim_value == "none" or spf_value == "none":
                st.write(":x: Email did not go through DKIM or SPF authentication\n")
                phishing_count += 1
            elif dkim_value == "pass" and spf_value == "pass":
                st.write(":white_check_mark: Email went through DKIM and SPF authentication\n")
                safe_count += 1
    
    safe_percent = int(safe_count / (phishing_count + safe_count) * 100)
    phish_percent = int(phishing_count / (phishing_count + safe_count) * 100)
    
    if phishing_count >= safe_count:
        return f"This email did not pass {phish_percent}% of our phishing checks and exhibits phishing characteristics in its headers.\n"
    else:
        return f"This email passed {safe_percent}% of our phishing checks.\n"

# For testing in terminal
# analyze_email("/Users/MeowItsMadi/Desktop/phish-test-email.eml")
    
