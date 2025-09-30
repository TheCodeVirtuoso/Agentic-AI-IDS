import pandas as pd
import joblib
import os
import time
import numpy as np

# Import the agent executor and the final coordinator from Phase 3
from agents import anomaly_agent_executor, coordinator_agent_executor

# --- CONFIGURATION ---
MODEL_DIR = 'models'
DATA_DIR = 'data'
MODEL_PATH = os.path.join(MODEL_DIR, 'anomaly_detector.joblib')
SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.joblib')
# We'll use a data file that contains attack traffic for our test
TEST_DATA_PATH = os.path.join(DATA_DIR, 'Bruteforce-Tuesday-no-metadata.parquet') 

# --- 1. LOAD ARTIFACTS ---
def load_artifacts():
    """Loads the saved machine learning model and scaler."""
    print("Loading the anomaly detection model and scaler...")
    try:
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        print("Model and scaler loaded successfully.")
        return model, scaler
    except FileNotFoundError:
        print("Error: Model or scaler file not found. Please ensure they are in the 'models' directory.")
        return None, None

# --- 2. LOAD AND PREPARE DATA ---
def load_and_prepare_data(file_path):
    """Loads and prepares network traffic data for prediction."""
    print(f"Loading and preparing test data from {file_path}...")
    try:
        df = pd.read_parquet(file_path)
        # These are the exact feature columns our model was trained on
        required_features = [
            'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Fwd Packets Length Total', 'Bwd Packets Length Total', 'Fwd Packet Length Max',
            'Bwd Packet Length Max', 'Flow IAT Mean', 'Flow IAT Std',
            'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total'
        ]
        df_features = df[required_features].copy()
        
        # This dataset doesn't have IP addresses, which is fine for our simulation.
        # We will simulate finding a suspicious IP when an anomaly is detected.
        print("Data prepared successfully.")
        return df_features
        
    except (FileNotFoundError, KeyError) as e:
        print(f"Error during data loading: {e}")
        return None

# --- 3. THE MAIN ORCHESTRATION LOGIC ---
def run_soc_simulation(model, scaler, data_features):
    """
    Runs the full simulation:
    1. Scales the data.
    2. Predicts anomalies using the ML model.
    3. Triggers the AI agent workflow for each detected anomaly.
    """
    print("\n--- [ML MODEL] Scaling data and predicting anomalies ---")
    
    # Scale the feature data using the loaded scaler
    data_scaled = scaler.transform(data_features)
    
    # Predict anomalies (-1 for anomalies, 1 for normal)
    predictions = model.predict(data_scaled)
    
    # Find the indices of the rows that are predicted as anomalies
    anomaly_indices = np.where(predictions == -1)[0]
    
    print(f"Prediction complete. Found {len(anomaly_indices)} potential anomalies.")
    
    # --- AGENT WORKFLOW ---
    # To avoid spamming APIs, we will only process the first few anomalies found
    max_anomalies_to_process = 3
    processed_count = 0

    if len(anomaly_indices) == 0:
        print("\nNo anomalies detected in the provided data. Simulation complete.")
        return

    print(f"\n--- [AI AGENTS] Starting investigation for the first {max_anomalies_to_process} anomalies ---")
    
    for index in anomaly_indices:
        if processed_count >= max_anomalies_to_process:
            break
            
        processed_count += 1
        print(f"\n\n--- Processing Anomaly #{processed_count} (from data row {index}) ---")
        
        # ** SIMULATION STEP **
        # Since we don't have the real IP, we'll use a known suspicious IP for demonstration.
        # In a real system, you would get this from the data row.
        simulated_suspicious_ip = "185.191.207.121" # A known bad IP for testing
        
        print(f"[STAGE 1] ML model detected an anomaly. Simulating source IP: {simulated_suspicious_ip}")
        print("Triggering Anomaly Investigator Agent...")

        try:
            # Invoke the anomaly agent to investigate the simulated IP
            investigation_result = anomaly_agent_executor.invoke({"input": simulated_suspicious_ip})
            investigation_report = investigation_result['output']
            
            print("\n--- [STAGE 1] Anomaly Agent's Final Report ---")
            print(investigation_report)
            
            # Pass the report to the Coordinator Agent
            print("\n\n[STAGE 2] Coordinator Agent is reviewing the report...")
            final_decision = coordinator_agent_executor.invoke({"input": investigation_report})
            
            print("\n--- [STAGE 2] Coordinator Agent's Final Decision ---")
            print(final_decision['output'])

        except Exception as e:
            print(f"An error occurred during agent execution: {e}")
        
        time.sleep(2) # Add a small delay to avoid overwhelming APIs if processing many alerts

# --- MAIN EXECUTION BLOCK ---
if __name__ == "__main__":
    model, scaler = load_artifacts()
    
    if model and scaler:
        data_features = load_and_prepare_data(TEST_DATA_PATH)
        
        if data_features is not None:
            run_soc_simulation(model, scaler, data_features)
            print("\n\n------ Full SOC Workflow Simulation Complete ------")