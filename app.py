import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import openai
import base64
from io import BytesIO
from triage import parse_logs, enrich_incidents, classify_incidents, map_to_mitre_tags

openai.api_key = st.secrets.get("OPENAI_API_KEY")

st.set_page_config(page_title="Incident Triage Bot", layout="wide")
st.title("🛡️ AI Incident Triage Bot")

# Dark Mode Styling
if st.toggle("🌙 Enable Dark Mode", value=True):
    st.markdown("<style>body { background-color: #0e1117; color: white; }</style>", unsafe_allow_html=True)

@st.cache_data(show_spinner=False)
def process_logs(log_text):
    df = parse_logs(log_text)
    df = enrich_incidents(df)
    df = classify_incidents(df)
    df["threat_category"] = df["description"].apply(map_to_mitre_tags)
    return df

def summarize_incident(text):
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a cybersecurity analyst. Summarize root cause and recommend next steps."},
            {"role": "user", "content": f"Incident: {text}"}
        ],
        temperature=0.3
    )
    return response["choices"][0]["message"]["content"]

def load_example_logs():
    return """
    2025-07-01 12:45:23 - Login failure from IP 192.168.0.12
    2025-07-01 12:45:30 - Suspicious file accessed on host-223
    2025-07-01 12:46:10 - Admin access granted to user 'temp01'
    2025-07-01 12:48:02 - Malware signature detected in process xyz.exe
    """

def generate_markdown(df):
    return df.to_markdown(index=False)

def generate_pdf(df):
    from fpdf import FPDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=10)
    for i, row in df.iterrows():
        text = f"{row['timestamp'][:19]} | {row['severity']} | {row['description']}"
        pdf.multi_cell(0, 10, text)
    buffer = BytesIO()
    pdf.output(buffer)
    return buffer.getvalue()

def generate_ticket_json(row):
    return {
        "summary": f"[{row['severity']}] {row['description'][:60]}...",
        "details": {
            "timestamp": row["timestamp"],
            "category": row.get("threat_category", "Unknown"),
            "description": row["description"],
            "gpt_summary": summarize_incident(row["description"]),
        },
        "priority": row["severity"].lower(),
        "status": "open",
    }

def plot_mitre_matrix(df):
    tactics = df["threat_category"].value_counts()
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.barh(tactics.index, tactics.values)
    ax.set_title("🧩 MITRE ATT&CK Tactic Frequency")
    st.pyplot(fig)

# File Upload
uploaded_file = st.file_uploader("📂 Upload a log file (.txt or .csv)", type=["txt", "csv"])
use_example = st.checkbox("🔍 Use example logs instead")

if uploaded_file or use_example:
    logs = uploaded_file.read().decode("utf-8") if uploaded_file else load_example_logs()
    try:
        with st.spinner("🔍 Processing logs..."):
            incidents_df = process_logs(logs)

        # Filters
        st.subheader("📊 Triaged Incidents")
        col1, col2 = st.columns(2)
        with col1:
            severity_filter = st.multiselect("Filter by severity", incidents_df["severity"].unique().tolist())
        with col2:
            search_term = st.text_input("🔎 Search logs")

        filtered_df = incidents_df.copy()
        if severity_filter:
            filtered_df = filtered_df[filtered_df["severity"].isin(severity_filter)]
        if search_term:
            filtered_df = filtered_df[filtered_df.apply(
                lambda row: search_term.lower() in row.astype(str).str.lower().to_string(), axis=1)]

        st.dataframe(filtered_df, use_container_width=True)

        # Pie Chart
        if "severity" in filtered_df.columns and not filtered_df.empty:
            st.subheader("🔥 Severity Breakdown")
            counts = filtered_df["severity"].value_counts()
            fig, ax = plt.subplots()
            ax.pie(counts, labels=counts.index, autopct="%1.1f%%")
            ax.axis("equal")
            st.pyplot(fig)

        # MITRE ATT&CK Matrix
        if "threat_category" in filtered_df.columns:
            st.subheader("🧩 MITRE ATT&CK Matrix")
            plot_mitre_matrix(filtered_df)

        # Export Options
        st.subheader("📤 Export Options")
        col1, col2 = st.columns(2)
        with col1:
            markdown_data = generate_markdown(filtered_df)
            st.download_button("📄 Export as Markdown", markdown_data.encode(), file_name="incidents.md")
        with col2:
            pdf_data = generate_pdf(filtered_df)
            st.download_button("🧾 Export as PDF", pdf_data, file_name="incidents.pdf", mime="application/pdf")

        # GPT Summaries
        st.subheader("🧠 GPT-4 Root Cause Summaries")
        for i, row in filtered_df.iterrows():
            with st.expander(f"{row['description']}"):
                st.info(f"Threat Category: {row.get('threat_category', 'Unknown')}")
                summary = summarize_incident(row["description"])
                st.text_area("GPT-4 Summary", summary, height=150)

        # JSON Ticket Builder
        st.subheader("🎟 Incident Ticket Generator")
        selected_row = st.selectbox("Select Incident for Ticket Export", filtered_df["description"].tolist())
        row_data = filtered_df[filtered_df["description"] == selected_row].iloc[0]
        ticket_json = generate_ticket_json(row_data)
        st.json(ticket_json)

    except Exception as e:
        st.error(f"❌ Error: {e}")
