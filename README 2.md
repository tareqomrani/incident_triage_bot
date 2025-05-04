
# Incident Triage Bot  
An AI-powered assistant that automates the first-response triage process for cybersecurity incidents, helping analysts rapidly classify and prioritize alerts.

## Overview  
This project uses natural language processing (NLP) and rule-based logic to:  
- Parse raw incident descriptions  
- Classify alert types (e.g. phishing, malware, brute force)  
- Assess severity level  
- Suggest appropriate next steps  

It helps security teams reduce response time and fatigue from noisy alerts.

## Features  
- **Streamlit UI** for interactive input and visualization  
- **Pre-trained language model** to parse and summarize incident logs  
- **Rule-based engine** to assign severity and recommend actions  
- **IP geolocation lookup** (optional)  
- **Simple, mobile-compatible interface**  

## Use Cases  
- Tier 1 SOC teams  
- Cybersecurity students and analysts  
- Internal IT security triage dashboards  

## Technologies  
- Python  
- Streamlit  
- scikit-learn  
- spaCy or transformers (optional)  

## Getting Started  
1. Clone the repo  
2. Install requirements:  
   ```bash  
   pip install -r requirements.txt  
   ```  
3. Run the app:  
   ```bash  
   streamlit run triage_bot.py  
   ```  

## Example Input  
```
Unusual login detected from IP 203.0.113.45 on administrator account.  
```

## Output  
- Type: Brute Force  
- Severity: High  
- Action: Lock account and investigate recent logs  

## Future Improvements  
- Integrate with SIEM tools  
- Alert correlation across logs  
- Role-based access controls  
