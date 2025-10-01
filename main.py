import pandas as pd
import joblib
import os
import time
import numpy as np
from itertools import cycle # Import cycle for continuous IP rotation

# Import all three agent components from our central agents.py file
from agents import anomaly_agent_executor, coordinator_agent_executor, run_signature_check

# --- CONFIGURATION ---
MODEL_DIR = 'models'
DATA_DIR = 'data'
MODEL_PATH = os.path.join(MODEL_DIR, 'anomaly_detector.joblib')
SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.joblib')
TEST_DATA_PATH = os.path.join(DATA_DIR, 'Bruteforce-Tuesday-no-metadata.parquet')
THREAT_FEED_FILE = "threat_feed.txt"
PROACTIVE_CHECK_INTERVAL_SECONDS = 15 # Check threat feed every 15 seconds

# Define the dynamic test cases (10 IPs)
# Note: IP reputations are dynamic, but these are chosen to generally represent the categories below.
DYNAMIC_TEST_IPS = [
    "185.220.101.243",  # 1. High Risk (Should Block)
    "1.1.1.1",          # 2. Benign (Should Log/Escalate)
    "172.67.240.24",    # 3. Medium Risk (Gray Area, Should Log/Monitor)
    "8.8.8.8",          # 4. Benign (Should Log/Escalate)
    "192.81.218.15",    # 5. High Risk (Should Block)
    "208.67.222.222",   # 6. Benign (Should Log/Escalate)
    "172.67.240.24",    # 7. Medium Risk (Repeat Ambiguous Case)
    "185.220.101.243",  # 8. High Risk (Repeat Block Case)
    "1.1.1.1",          # 9. Benign (Repeat Filter Case)
    "192.81.218.15"     # 10. High Risk (Repeat Block Case)
]

# --- Functions to load artifacts and data ---
def load_artifacts():
    print("Loading the anomaly detection model and scaler...")
    try:
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        print("Model and scaler loaded successfully.")
        return model, scaler
    except FileNotFoundError:
        print("Error: Model or scaler file not found.")
        return None, None

def load_and_prepare_data(file_path):
    print(f"Loading and preparing test data from {file_path}...")
    try:
        df = pd.read_parquet(file_path)
        required_features = [
            'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Fwd Packets Length Total', 'Bwd Packets Length Total', 'Fwd Packet Length Max',
            'Bwd Packet Length Max', 'Flow IAT Mean', 'Flow IAT Std',
            'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total'
        ]
        df_features = df[required_features].copy()
        print("Data prepared successfully.")
        return df_features
    except (FileNotFoundError, KeyError) as e:
        print(f"Error during data loading: {e}")
        return None

def explain_anomaly(model, scaler, data_features, index):
    # Simple explanation: show top contributing features for anomaly
    try:
        # For simplicity, show the feature values at the anomaly index
        row = data_features.iloc[index]
        top_features = row.nlargest(3)  # Top 3 features by value
        explanation = f"Top contributing features: {', '.join([f'{k}: {v:.2f}' for k, v in top_features.items()])}"
        return explanation
    except Exception as e:
        print(f"Error generating explanation: {e}")
        return "Explanation not available."

# --- THE MAIN ORCHESTRATION LOOP (Updated for Dynamic Test Cycling) ---
def run_soc_orchestrator(model, scaler, data_features):
    processed_ips_from_feed = set()
    last_proactive_check = time.time()
    
    # Pre-calculate all anomalies to be processed
    print("\n--- [ML MODEL] Scaling data and predicting anomalies... ---")
    data_scaled = scaler.transform(data_features)
    predictions = model.predict(data_scaled)
    anomaly_indices = np.where(predictions == -1)[0]
    
    # Use a limited number of anomalies equal to the length of our test IPs
    num_tests = len(DYNAMIC_TEST_IPS)
    anomaly_iterator = iter(anomaly_indices[:num_tests]) # Only process enough anomalies for our test IPs
    
    # Create an iterator that cycles through our test IPs
    ip_cycler = iter(DYNAMIC_TEST_IPS) 

    print(f"\n--- [Reactive Alert] Preparing to process {num_tests} dynamic test cases... ---")

    print("\n--- --- SOC Orchestrator is now LIVE ------")
    print("Simulating live network traffic analysis and proactive threat hunting.")

    try:
        test_case_count = 0
        while test_case_count < num_tests:
            
            # --- A. REACTIVE DEFENSE (Process one anomaly alert) ---
            try:
                index = next(anomaly_iterator)
                current_test_ip = next(ip_cycler)
                test_case_count += 1
                
                print(f"\n--- TEST CASE #{test_case_count}: IP {current_test_ip} (Row {index}) ---")
                
                print(f"[STAGE 1] Triggering Anomaly Agent for IP: {current_test_ip}...")

                import datetime
                start_time = datetime.datetime.now()
                
                # --- Anomaly Agent Execution (FIXED ASSIGNMENT) ---
                report_dict = anomaly_agent_executor.invoke({"input": current_test_ip})
                investigation_report = report_dict['output'] # <-- CORRECTLY ASSIGNED

                end_time = datetime.datetime.now()
                duration = (end_time - start_time).total_seconds()

                # Log investigation time and success (assuming success if no exception)
                log_line = f"{datetime.datetime.now().isoformat()} - INVESTIGATION - IP: {current_test_ip} - Duration: {duration} - Status: Success\n"
                with open("investigation_times.log", "a") as log_file:
                    log_file.write(log_line)

                # Generate explanation for anomaly
                explanation = explain_anomaly(model, scaler, data_features, index)
                if explanation:
                    print(f"[XAI] Explanation for anomaly at index {index}: {explanation}")
                else:
                    print("[XAI] Explanation not available.")

                print("\n[STAGE 2] Passing Anomaly Agent's report to Coordinator...")
                
                # --- Coordinator Agent Execution ---
                coordinator_agent_executor.invoke({"input": investigation_report}) # <-- NOW CORRECT

            except StopIteration:
                print("\n--- All anomaly test cases completed. Continuing with proactive checks only. ---")
            
            # --- B. PROACTIVE DEFENSE (Check threat feed periodically) ---
            current_time = time.time()
            if current_time - last_proactive_check > PROACTIVE_CHECK_INTERVAL_SECONDS:
                processed_ips_from_feed = run_signature_check(processed_ips_from_feed, THREAT_FEED_FILE)
                last_proactive_check = current_time

            # Slow down the simulation to make it observable
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n------ SOC Orchestrator shutting down. ------")

# --- MAIN EXECUTION BLOCK ---
if __name__ == "__main__":
    # Ensure the threat feed file exists for the Signature Agent
    if not os.path.exists(THREAT_FEED_FILE):
        print(f"Creating a sample threat feed file: {THREAT_FEED_FILE}")
        with open(THREAT_FEED_FILE, 'w') as f:
            f.write("203.0.113.78\n")
            f.write("198.51.100.12\n")

    model, scaler = load_artifacts()
    
    if model and scaler:
        all_data_features = load_and_prepare_data(TEST_DATA_PATH)
        if all_data_features is not None:
            # Use data features sufficient for our test cases
            run_soc_orchestrator(model, scaler, all_data_features)
            print("\n------ Full SOC Workflow Simulation Complete ------")
