import pandas as pd

def parse_logs(log_text):
    lines = log_text.strip().split('\n')
    records = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 3:
            records.append({'timestamp': parts[0], 'source_ip': parts[1], 'event': ' '.join(parts[2:])})
    return pd.DataFrame(records)

def enrich_incidents(df):
    df['threat_level'] = df['event'].apply(lambda x: "High" if "unauthorized" in x.lower() else "Low")
    return df

def classify_incidents(df):
    df['incident_type'] = df['event'].apply(lambda x: "Brute Force" if "failed login" in x.lower() else "Other")
    return df