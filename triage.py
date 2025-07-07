
import pandas as pd
import re
from datetime import datetime

def parse_logs(raw_text):
    lines = raw_text.strip().splitlines()
    data = []
    for line in lines:
        match = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (.+)", line)
        if match:
            timestamp_str, message = match.groups()
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                timestamp = None
            data.append({"timestamp": timestamp, "description": message})
        else:
            data.append({"timestamp": None, "description": line})
    return pd.DataFrame(data)

def enrich_incidents(df):
    df["source_ip"] = df["description"].apply(lambda x: extract_ip(x))
    df["host"] = df["description"].apply(lambda x: extract_hostname(x))
    return df

def extract_ip(text):
    match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
    return match.group(0) if match else None

def extract_hostname(text):
    match = re.search(r"host[-_]?[\w]+", text, re.IGNORECASE)
    return match.group(0) if match else None

def classify_incidents(df):
    def classify(desc):
        d = desc.lower()
        if any(k in d for k in ["malware", "ransom", "unauthorized", "admin access"]):
            return "Critical"
        elif any(k in d for k in ["suspicious", "login failure", "brute force"]):
            return "High"
        elif any(k in d for k in ["scan", "probing", "abnormal"]):
            return "Medium"
        else:
            return "Low"
    df["severity"] = df["description"].apply(classify)
    return df

def map_to_mitre_tags(description):
    desc = description.lower()
    if "login failure" in desc or "brute" in desc:
        return "Credential Access"
    elif "malware" in desc or "trojan" in desc:
        return "Execution"
    elif "unauthorized access" in desc or "admin" in desc:
        return "Privilege Escalation"
    elif "exfiltration" in desc or "file accessed" in desc:
        return "Collection"
    elif "scan" in desc or "discovery" in desc:
        return "Discovery"
    elif "command and control" in desc or "c2" in desc:
        return "Command and Control"
    else:
        return "Unknown"
