import pandas as pd
import requests
import streamlit as st

API_URL = "http://127.0.0.1:8000"

st.set_page_config(
    page_title="BOUNDARY//LAB SOC Intelligence",
    layout="wide",
)

st.title("BOUNDARY//LAB")
st.subheader("SOC Intelligence Platform")
st.caption("Security Log Analysis | Alert Triage | SOC Copilot")

st.divider()

# Check API connection
try:
    response = requests.get(f"{API_URL}/health", timeout=5)
    response.raise_for_status()
    st.success("SOC Intelligence API: ONLINE")
except requests.RequestException:
    st.error("SOC Intelligence API: OFFLINE")
    st.stop()

# Initialize event history
if "events" not in st.session_state:
    st.session_state.events = []

st.header("Security Event Analysis")

with st.form("authentication_form"):
    event_id = st.text_input("Event ID", value="AUTH-5001")

    failed_attempts = st.number_input(
        "Failed Authentication Attempts",
        min_value=0,
        max_value=100000,
        value=8,
        step=1,
    )

    source = st.text_input(
        "Log Source",
        value="synthetic-auth-server",
    )

    submitted = st.form_submit_button("Analyze Security Event")

if submitted:
    payload = {
        "event_id": event_id,
        "failed_attempts": int(failed_attempts),
        "source": source,
    }

    try:
        response = requests.post(
            f"{API_URL}/logs/authentication",
            json=payload,
            timeout=10,
        )
        response.raise_for_status()

        result = response.json()
        st.session_state.events.append(result)

        st.success("Security event analyzed successfully.")

    except requests.RequestException as error:
        st.error(f"Analysis request failed: {error}")

if st.session_state.events:
    latest = st.session_state.events[-1]

    event = latest["event"]
    analysis = latest["analysis"]
    explanation = latest["explanation"]

    st.divider()
    st.header("Latest Security Analysis")

    col1, col2, col3 = st.columns(3)

    col1.metric("Risk Score", f"{analysis['risk_score']}/100")
    col2.metric("Severity", event["severity"].upper())
    col3.metric(
        "Classification",
        analysis["classification"].upper(),
    )

    st.subheader("SOC Copilot Explanation")
    st.info(explanation["summary"])

    st.subheader("Supporting Evidence")
    for item in explanation["supporting_evidence"]:
        st.write(f"• {item}")

    st.subheader("Recommended Action")
    st.warning(explanation["recommended_action"])

    with st.expander("Analysis Limitations"):
        for limitation in explanation["limitations"]:
            st.write(f"• {limitation}")

   # Persistent security event history
    st.divider()
    st.header("Security Event History")

    try:
        response = requests.get(
            f"{API_URL}/events/history",
            timeout=10,
        )
        response.raise_for_status()

        history = response.json()

        if history:
            rows = []

            for record in history:
                rows.append({
                    "Database ID": record["id"],
                    "Event ID": record["event_id"],
                    "Timestamp": record["timestamp"],
                    "Severity": record["severity"].upper(),
                    "Classification": record["classification"].upper(),
                    "Risk Score": record["risk_score"],
                })

            df = pd.DataFrame(rows)

            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True,
            )

            st.subheader("Historical Risk Scores")

            chart_data = df.set_index("Database ID")["Risk Score"]

            st.bar_chart(chart_data)

            st.caption(
                f"Displaying {len(history)} persisted security events."
            )

        else:
            st.info("No security events have been saved yet.")

    except requests.RequestException as error:
        st.error(f"Unable to retrieve event history: {error}")