
from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

from model_preprocessing import convert_to_string_verified

# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="Lightweight Network Intrusion Detection",
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------------------------
# EXPECTED MODEL INPUT FEATURES
# --------------------------------------------------

EXPECTED_FEATURES = [
    "arp.opcode",
    "arp.hw.size",
    "icmp.checksum",
    "icmp.seq_le",
    "tcp.ack",
    "tcp.connection.syn",
    "tcp.dstport",
    "tcp.flags",
    "tcp.flags.ack",
    "tcp.len",
    "tcp.seq",
    "tcp.srcport",
    "udp.port",
    "udp.time_delta",
    "dns.qry.name",
    "dns.qry.name.len",
    "dns.qry.qu",
    "mqtt.conflag.cleansess",
    "mqtt.conflags",
    "mqtt.hdrflags",
    "mqtt.len",
    "mqtt.msgtype",
    "mqtt.proto_len",
    "mqtt.topic_len",
    "mqtt.ver"
]


CLASS_LABELS = {
    0: "Normal",
    1: "Attack"
}


# --------------------------------------------------
# LOAD THE SAVED DECISION TREE PIPELINE
# --------------------------------------------------

MODEL_PATH = Path(__file__).parent / "decision_tree_pipeline.joblib"


@st.cache_resource
def load_model():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Model file not found: {MODEL_PATH}"
        )

    return joblib.load(MODEL_PATH)


# --------------------------------------------------
# APPLICATION HEADER
# --------------------------------------------------

st.title("🛡️ Network Intrusion Detection System")

st.caption(
    "Lightweight Machine Learning-Based Network Attack Detection"
)

st.markdown("""
Upload a network traffic CSV file to identify potentially malicious
traffic using the trained Decision Tree classification pipeline.
""")

st.divider()


# --------------------------------------------------
# MODEL STATUS
# --------------------------------------------------

try:
    model = load_model()

    st.success("Decision Tree model loaded successfully.")

except Exception as error:
    st.error(f"Unable to load the model: {error}")
    st.stop()


# --------------------------------------------------
# CSV FILE UPLOAD
# --------------------------------------------------

st.subheader("Upload Network Traffic Data")

uploaded_file = st.file_uploader(
    "Choose a CSV file",
    type=["csv"],
    help="The CSV must contain all 25 required input features."
)


# --------------------------------------------------
# INPUT VALIDATION
# --------------------------------------------------

if uploaded_file is not None:

    try:
        traffic_data = pd.read_csv(uploaded_file)

        missing_features = [
            feature for feature in EXPECTED_FEATURES
            if feature not in traffic_data.columns
        ]

        extra_features = [
            feature for feature in traffic_data.columns
            if feature not in EXPECTED_FEATURES
        ]

        if missing_features:
            st.error(
                "The uploaded file is missing required features:"
            )
            st.write(missing_features)
            st.stop()

        if traffic_data.empty:
            st.error("The uploaded CSV contains no records.")
            st.stop()

        st.success("CSV file uploaded and required features validated.")

        st.write("### Input Dataset Preview")

        st.dataframe(
            traffic_data[EXPECTED_FEATURES].head(10),
            use_container_width=True
        )

        st.write(f"**Records uploaded:** {len(traffic_data):,}")
        st.write(f"**Required features found:** {len(EXPECTED_FEATURES)}")

        if extra_features:
            st.info(
                f"{len(extra_features)} additional column(s) "
                "were found and will not be used for prediction."
            )

    except Exception as error:
        st.error(f"Unable to process the uploaded CSV: {error}")
