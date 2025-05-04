import streamlit as st
import pandas as pd
from triage import parse_logs, enrich_incidents, classify_incidents

st.set_page_config(page_title="Incident Triage Bot", layout="wide")
st.title("AI Incident Triage Bot")

uploaded_file = st.file_uploader("Upload a log file", type=["txt", "csv"])
if uploaded_file:
    logs = uploaded_file.read().decode("utf-8")
    incidents_df = parse_logs(logs)
    incidents_df = enrich_incidents(incidents_df)
    incidents_df = classify_incidents(incidents_df)
    st.dataframe(incidents_df)