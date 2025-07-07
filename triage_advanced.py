
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
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            data.append({"timestamp": timestamp, "description": message})
        else:
            data.append({"timestamp": None, "description": line})
    return pd.DataFrame(data)

def enrich_entities(df):
    def extract(text):
        return {
            "ips": re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text),
            "users": re.findall(r"user \'?([\w]+)\'?", text, re.IGNORECASE),
            "hosts": re.findall(r"host[-_]?[\w]+", text, re.IGNORECASE),
            "files": re.findall(r"[\w\-]+\.exe", text)
        }
    df["entities"] = df["description"].apply(extract)
    return df

def classify_with_gpt(df):
    df["severity"] = "High"
    df["threat_category"] = "Credential Access"
    return df

def correlate_incidents(df):
    df["campaign"] = "Campaign-1"
    return df
