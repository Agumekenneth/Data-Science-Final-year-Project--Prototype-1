
from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

# Import the custom function before loading the saved pipeline.
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
# MODEL INPUT CONFIGURATION
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

MODEL_PATH = Path(__file__).parent / "decision_tree_pipeline.joblib"


# --------------------------------------------------
# LOAD SAVED MODEL
# --------------------------------------------------

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
# RESET RESULTS WHEN A DIFFERENT FILE IS UPLOADED
# --------------------------------------------------

if uploaded_file is not None:

    file_signature = (uploaded_file.name, uploaded_file.size)

    if st.session_state.get("file_signature") != file_signature:
        st.session_state.file_signature = file_signature
        st.session_state.pop("classification_results", None)


# --------------------------------------------------
# INPUT VALIDATION AND CLASSIFICATION
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
            st.error("The uploaded file is missing required features:")
            st.write(missing_features)
            st.stop()

        if traffic_data.empty:
            st.error("The uploaded CSV contains no records.")
            st.stop()

        st.success("CSV file uploaded and required features validated.")

        st.write("### Input Dataset Preview")

        st.dataframe(
            traffic_data[EXPECTED_FEATURES].head(10),
            width="stretch"
        )

        st.write(f"**Records uploaded:** {len(traffic_data):,}")
        st.write(f"**Required features found:** {len(EXPECTED_FEATURES)}")

        if extra_features:
            st.info(
                f"{len(extra_features)} additional column(s) found. "
                "These will not be used for prediction."
            )

        st.divider()

        # --------------------------------------------------
        # RUN CLASSIFICATION
        # --------------------------------------------------

        st.subheader("Network Traffic Classification")

        if st.button(
            "Classify Network Traffic",
            type="primary",
            use_container_width=True
        ):

            with st.spinner("Classifying network traffic..."):

                input_features = traffic_data[EXPECTED_FEATURES].copy()

                predictions = model.predict(input_features)
                probabilities = model.predict_proba(input_features)

                results = input_features.copy()

                results["predicted_class"] = predictions

                results["classification"] = [
                    CLASS_LABELS.get(int(value), str(value))
                    for value in predictions
                ]

                results["confidence"] = (
                    probabilities.max(axis=1) * 100
                ).round(2)

                st.session_state.classification_results = results

        # --------------------------------------------------
        # DISPLAY CLASSIFICATION RESULTS
        # --------------------------------------------------

        if "classification_results" in st.session_state:

            results = st.session_state.classification_results

            total_records = len(results)

            normal_count = (
                results["classification"] == "Normal"
            ).sum()

            attack_count = (
                results["classification"] == "Attack"
            ).sum()

            st.subheader("Classification Summary")

            col1, col2, col3 = st.columns(3)

            col1.metric("Total Records", f"{total_records:,}")
            col2.metric("Normal Traffic", f"{normal_count:,}")
            col3.metric("Attack Traffic", f"{attack_count:,}")

            st.write("### Classification Results")

            st.dataframe(
                results,
                use_container_width=True
            )

            st.write("### Prediction Confidence")

            st.write(
                f"Average confidence: "
                f"**{results['confidence'].mean():.2f}%**"
            )

            st.caption(
                "Confidence represents the model's estimated probability "
                "for its predicted class. It is not a guarantee of correctness."
            )

            # --------------------------------------------------
            # DOWNLOAD RESULTS
            # --------------------------------------------------

            csv_data = results.to_csv(index=False).encode("utf-8")

            st.download_button(
                label="Download Classification Results",
                data=csv_data,
                file_name="network_traffic_classification_results.csv",
                mime="text/csv",
                use_container_width=True
            )

    except Exception as error:
        st.error(f"Unable to process the uploaded CSV: {error}")
