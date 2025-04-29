import requests
from dotenv import load_dotenv
import json
import os
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

# Extract the email sender's address (the "From" value)
def analyze_sender(email):
    msg = parse_email(email)
    sender_name, sender_addr = parseaddr(msg["From"])
    print(f"Sender's Name: {sender_name}, Sender's address: {sender_addr}\n")

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
        print("One or more scans found the domain to be malicous or suspicious\nResult: May be a phishing email!")
        return True
    else:
        print("The domain was not found to be malicious or suspicious\nResult: Most likely is not a phishing email!")
        return False
# print(analyze_sender("/Users/MeowItsMadi/Desktop/regular-email.eml"))

# Extract the email headers
def analyze_headers(email):
    msg = parse_email(email)

    # Recieved by (shows sender's IP address)

    # Return-Path (path that email is returned to if there's a failure)

    # Authentication Results (verifys sender is authentication)


def execute_all_checks(email):
    phishing = 0
    sender = analyze_sender(email)
    if sender: # malicious or suspicious sender
        phishing += 1
    
    headers = analyze_headers(email)
    
