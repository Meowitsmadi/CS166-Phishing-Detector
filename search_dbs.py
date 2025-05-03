import requests
from dotenv import load_dotenv
import json
import os
import streamlit as st

load_dotenv()

API_KEY = os.getenv("VIRUS_TOTAL_API_KEY")

def scan_url(url_input):
    """
    Sends an HTTP POST request to the API to return an analysis ID.
    """
    api_url = "https://www.virustotal.com/api/v3/urls"

    payload = { "url": url_input} 
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }

    # Returns an analysis api url concatenated with an ID from the scan
    try:
        response = requests.post(api_url, data=payload, headers=headers)
        response_dict = json.loads(response.text)
        return response_dict["data"]["links"]["self"]
    except Exception as e:
        print(f"Error: {e}")
    
def retrieve_url_analysis(url_input):
    """
    Sends an HTTP GET request using an analysis ID to the API to return a URL analysis.
    Uses multiple malware DBs & engines to classify the url as malicious, suspicious, undetected, and/or harmless.
    """
    analysis_url = scan_url(url_input)
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY,
    }

    try:
        response = requests.get(analysis_url, headers=headers)
        response_dict = json.loads(response.text)
        results = response_dict["data"]["attributes"]["stats"]
        # Example Output: {'malicious': 0, 'suspicious': 0, 'undetected': 30, 'harmless': 67, 'timeout': 0}
        print("The VirusTotal scan results: ")
        for category in results:
            print(results[category], category) 

        if results['malicious'] > 0 or results['suspicious'] > 0:
            return "At least one scan found the link to be malicious or suspicious."
        elif results['harmless'] > results['undetected']:
            return "Majority of the scans found the link to be harmless."
        else:
            return "Majority of the scans did not detect any signs of phishing."
    except Exception as e:
        print(f"Error: {e}")
    