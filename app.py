
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import openai
from io import BytesIO
from triage import classify_incidents, map_to_mitre_tags
from triage_advanced import parse_logs, enrich_entities, classify_with_gpt, correlate_incidents

# Load OpenAI key
openai.api_key = st.secrets.get("OPENAI_API_KEY")

st.set_page_config(page_title="AI Incident Triage Bot", layout="wide")
st.title("🛡️ AI Incident Triage Bot")

def summarize_incident(text, gpt_enabled=False):
    if gpt_enabled:
        return "This is a placeholder summary. GPT-4 integration active."
    else:
        return "GPT-4 classification is disabled."

def load_example_logs():
    return """
    2025-07-01 12:45:23 - Login failure from IP 192.168.0.12
    2025-07-01 12:45:30 - Suspicious file accessed on host-223
    2025-07-01 12:46:10 - Admin access granted to user 'temp01'
    2025-07-01 12:48:02 - Malware signature detected in process xyz.exe
    """

def generate_markdown(df):
    from tabulate import tabulate
    return tabulate(df, headers='keys', tablefmt='pipe', showindex=False)

def generate_pdf(df):
    from fpdf import FPDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=10)
    for _, row in df.iterrows():
        line = f"{row['timestamp']} | {row['severity']} | {row['description']}"
        pdf.multi_cell(0, 10, line)
    return pdf.output(dest="S").encode("latin1")

def generate_ticket_json(row, gpt_enabled=False):
    return {
        "summary": f"[{row['severity']}] {row['description'][:60]}...",
        "details": {
            "timestamp": row["timestamp"],
            "category": row.get("threat_category", "Unknown"),
            "description": row["description"],
            "gpt_summary": summarize_incident(row["description"], gpt_enabled),
            "campaign": row.get("campaign", "Unlinked")
        },
        "priority": row["severity"].lower(),
        "status": "open"
    }

def plot_mitre_matrix(df):
    tactics = df["threat_category"].value_counts()
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.barh(tactics.index, tactics.values)
    ax.set_title("MITRE ATT&CK Tactic Frequency")
    st.pyplot(fig)

uploaded_file = st.file_uploader("📂 Upload log file (.txt or .csv)", type=["txt", "csv"])
use_example = st.checkbox("Use example logs")

if "use_gpt" not in st.session_state:
    st.session_state.use_gpt = False
use_gpt = st.checkbox("🧠 Enable GPT-4 Classification", value=st.session_state.use_gpt)
st.session_state.use_gpt = use_gpt

if uploaded_file or use_example:
    logs = uploaded_file.read().decode("utf-8") if uploaded_file else load_example_logs()

    with st.spinner("Processing logs..."):
        df = parse_logs(logs)
        df = enrich_entities(df)

        if use_gpt:
            df = classify_with_gpt(df)
        else:
            df = classify_incidents(df)
            df["threat_category"] = df["description"].apply(map_to_mitre_tags)

        df = correlate_incidents(df)

    st.subheader("📊 Triaged Incidents")
    col1, col2 = st.columns(2)
    with col1:
        severity_filter = st.multiselect("Filter by severity", df["severity"].unique().tolist())
    with col2:
        search_term = st.text_input("Search logs")

    filtered = df.copy()
    if severity_filter:
        filtered = filtered[filtered["severity"].isin(severity_filter)]
    if search_term:
        filtered = filtered[filtered.apply(lambda row: search_term.lower() in str(row).lower(), axis=1)]

    st.dataframe(filtered, use_container_width=True)

    if "severity" in filtered.columns:
        st.subheader("🔥 Severity Breakdown")
        counts = filtered["severity"].value_counts()
        fig, ax = plt.subplots()
        ax.pie(counts, labels=counts.index, autopct="%1.1f%%")
        ax.axis("equal")
        st.pyplot(fig)

    if "threat_category" in filtered.columns:
        st.subheader("🧩 MITRE ATT&CK Matrix")
        plot_mitre_matrix(filtered)

    st.subheader("🕵️ Extracted Entities & Campaigns")
    st.dataframe(filtered[["timestamp", "description", "entities", "campaign"]])

    st.subheader("📤 Export")
    col1, col2 = st.columns(2)
    col1.download_button("📄 Export Markdown", generate_markdown(filtered).encode(), file_name="incidents.md")
    col2.download_button("🧾 Export PDF", generate_pdf(filtered), file_name="incidents.pdf", mime="application/pdf")

    st.subheader("🧠 GPT Summaries")
    for i, row in filtered.iterrows():
        with st.expander(f"{row['description']}"):
            st.info(f"Threat: {row.get('threat_category', 'Unknown')} | Campaign: {row.get('campaign', '-')}")
            summary = summarize_incident(row["description"], use_gpt)
            st.text_area("Summary", summary, height=120, key=f"summary_{i}")

    st.subheader("🎟 Incident Ticket Generator")
    selected = st.selectbox("Select Incident", filtered["description"].tolist())
    row_data = filtered[filtered["description"] == selected].iloc[0]
    st.json(generate_ticket_json(row_data, use_gpt))
