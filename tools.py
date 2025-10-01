import os
import requests
import json
import whois
import datetime
from dotenv import load_dotenv
from typing import Union, Dict, Any
from langchain.agents import tool
# Load environment variables from the .env file in the project's root directory
load_dotenv()
import json # Keep this import

# Phase 2: Blockchain for Immutable Logs
from blockchain import add_log_to_blockchain

# ==============================================================================
# TOOL 1: IP REPUTATION CHECKER 
# ==============================================================================
@tool
def check_ip_reputation(ip_address: str) -> str:
    """
    Checks the reputation of an IP address using the AbuseIPDB API.
    This tool is essential for the Anomaly Agent to determine if an unknown IP 
    has been reported for malicious activities elsewhere.
    
    Args:
        ip_address: The IPv4 or IPv6 address to check.

    Returns:
        A formatted string summarizing the IP's reputation.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return "Error: AbuseIPDB API key not found. Please set ABUSEIPDB_API_KEY in the .env file."

    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90',
        'verbose': ''
    }

    try:
        response = requests.get(url=url, headers=headers, params=params)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
        data = response.json().get('data', {})

        if data.get('abuseConfidenceScore', 0) == 0:
            return f"IP {ip_address} is considered clean. Abuse Score: 0. Country: {data.get('countryName', 'N/A')}."
        
        summary = (
            f"IP {ip_address} is POTENTIALLY MALICIOUS.\n"
            f"- Abuse Confidence Score: {data.get('abuseConfidenceScore', 'N/A')}/100\n"
            f"- Country: {data.get('countryName', 'N/A')}\n"
            f"- ISP: {data.get('isp', 'N/A')}\n"
            f"- Domain: {data.get('domain', 'N/A')}\n"
            f"- Total Reports: {data.get('totalReports', 'N/A')}\n"
            f"- Last Reported At: {data.get('lastReportedAt', 'N/A')}"
        )
        return summary

    except requests.exceptions.RequestException as e:
        return f"Error: Could not connect to the AbuseIPDB API. Details: {e}"
    except KeyError:
        return f"Error: Received an unexpected data format from AbuseIPDB for IP {ip_address}."
    except Exception as e:
        return f"An unexpected error occurred while checking IP reputation: {e}"

# ==============================================================================
# TOOL 2: WHOIS LOOKUP
# ==============================================================================
@tool
def get_whois_info(domain_or_ip: str) -> str:
    """
    Performs a WHOIS lookup for a given domain or IP address to find registration
    and ownership information. This helps the Anomaly Agent add context about
    who owns the infrastructure.
    
    Args:
        domain_or_ip: The domain name or IP address to look up.

    Returns:
        A formatted string with key information from the WHOIS record.
    """
    try:
        w = whois.whois(domain_or_ip)
        
        if not w.get('domain_name'):
            org = w.get('org', 'N/A')
            if org != 'N/A':
                 info = (
                    f"WHOIS lookup for IP '{domain_or_ip}':\n"
                    f"- Organization: {org}\n"
                    f"- Country: {w.get('country', 'N/A')}\n"
                    f"- Address: {w.get('address', 'N/A')}"
                )
                 return info
            else:
                return f"No detailed WHOIS information found for '{domain_or_ip}'. It may be an unallocated or private IP."

        info = (
            f"WHOIS lookup for domain '{domain_or_ip}':\n"
            f"- Registrar: {w.get('registrar', 'N/A')}\n"
            f"- Creation Date: {w.get('creation_date', 'N/A')}\n"
            f"- Expiration Date: {w.get('expiration_date', 'N/A')}\n"
            f"- Name Servers: {w.get('name_servers', 'N/A')}"
        )
        return info

    except Exception as e:
        return f"An error occurred during WHOIS lookup for '{domain_or_ip}': {e}"


# ==============================================================================
# TOOL 3: SIMULATED FIREWALL BLOCK (Robust Fix)
# ==============================================================================
@tool
def create_firewall_block_rule(input_json_string: str) -> str:
    """
    Simulates creating a firewall rule to block an IP address.
    This tool takes a single JSON string argument, which MUST be a JSON object
    containing 'ip_address' and 'reason' keys.
    """
    try:
        # Step 1: Parse the incoming JSON string
        parsed_data = json.loads(input_json_string)
    except json.JSONDecodeError:
        return f"Error: Input is not a valid JSON string: {input_json_string}"

    # Step 2: Handle the nested structure ({"details": {ip, reason}})
    if 'details' in parsed_data:
        final_details = parsed_data['details']
    else:
        final_details = parsed_data 

    ip_address = final_details.get('ip_address')
    reason = final_details.get('reason')
    
    if not ip_address or not reason:
        return "Error: Firewall input must contain 'ip_address' and 'reason' keys."
        
    log_message = f"{datetime.datetime.now().isoformat()} - [ACTION] - BLOCK IP: {ip_address} - REASON: {reason}"
    print(log_message)
    try:
        with open("firewall_rules.log", "a") as f: f.write(log_message + "\n")
        # Phase 2: Add to blockchain for immutability
        block_hash = add_log_to_blockchain(log_message)
        print(f"Log added to blockchain with hash: {block_hash}")
        return f"Success: Firewall block rule for IP {ip_address} was logged and added to blockchain."
    except Exception as e: return f"Error: Could not write to firewall log file: {e}"

# ==============================================================================
# TOOL 4: HUMAN REVIEW QUEUE (CRITICAL FIX APPLIED HERE)
# ==============================================================================
@tool
def log_for_human_review(input_json_string: str) -> str:
    """
    Logs an incident to the human review queue when autonomous action is not taken.
    The input MUST be a JSON string containing 'ip_address', 'threat_level', and 'report_summary'.
    """
    try:
        # Step 1: Parse the incoming JSON string
        parsed_data = json.loads(input_json_string)
    except json.JSONDecodeError:
        return f"Error: HIL input is not a valid JSON string: {input_json_string}"
    
    # Step 2: Handle the nested structure ({"case_details": {...}})
    if 'case_details' in parsed_data:
        final_details = parsed_data['case_details']
    else:
        final_details = parsed_data
        
    ip_address = final_details.get('ip_address', 'N/A')
    threat_level = final_details.get('threat_level', 'UNKNOWN')
    report_summary = final_details.get('report_summary', 'No summary provided')
    
    if ip_address == 'N/A':
        return "Error: HIL input is missing 'ip_address'."

    log_message = (
        f"{datetime.datetime.now().isoformat()} - [REVIEW] - LEVEL: {threat_level} - IP: {ip_address} - SUMMARY: {report_summary}"
    )
    
    # Append to a dedicated log file
    try:
        with open("review_queue.log", "a") as f:
            f.write(log_message + "\n")
        # Phase 2: Add to blockchain for immutability
        block_hash = add_log_to_blockchain(log_message)
        print(f"Log added to blockchain with hash: {block_hash}")
        return f"Success: Incident logged to human review queue at {threat_level} level for IP {ip_address} and added to blockchain."
    except Exception as e:
        return f"Error logging to review queue: {e}"

# In tools.py, at the very bottom:

# ==============================================================================
# TOOL 5: REAL-TIME THREAT INTELLIGENCE FETCHER (Phase 2)
# ==============================================================================
@tool
def fetch_threat_intelligence() -> str:
    """
    Fetches real-time threat intelligence from AlienVault OTX API.
    Retrieves recent malicious IPs and domains for proactive threat hunting.
    Requires OTX_API_KEY in .env file.
    """
    api_key = os.getenv("OTX_API_KEY")
    if not api_key:
        return "Error: OTX_API_KEY not found in .env file. Please set it to access AlienVault OTX."

    url = "https://otx.alienvault.com/api/v1/indicators/export"
    headers = {"X-OTX-API-KEY": api_key}
    params = {"types": "IPv4", "limit": 50}  # Fetch up to 50 recent IPv4 threats

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        threats = []
        for item in data.get("results", []):
            if item.get("type") == "IPv4":
                threats.append(item.get("indicator"))

        if threats:
            return f"Fetched {len(threats)} threats from OTX: {', '.join(threats[:10])}..."  # Show first 10
        else:
            return "No new threats fetched from OTX."

    except requests.exceptions.RequestException as e:
        return f"Error fetching from OTX: {e}"

# ==============================================================================
# TOOL 6: BEHAVIORAL ANALYSIS WITH GNN (Phase 2)
# ==============================================================================
@tool
def analyze_behavior(ip_address: str) -> str:
    """
    Performs behavioral analysis on an IP address using Graph Neural Networks (GNN).
    Analyzes traffic patterns, connections, and anomalies in network behavior.
    This tool simulates advanced GNN-based anomaly detection for IP behavior.

    Args:
        ip_address: The IP address to analyze.

    Returns:
        A detailed behavioral analysis report.
    """
    # Simulate GNN analysis (in a real implementation, this would use PyTorch Geometric or similar)
    # For demo purposes, we'll use a simple heuristic-based analysis

    import random
    random.seed(hash(ip_address) % 1000)  # Deterministic randomness based on IP

    # Mock GNN analysis results
    anomaly_score = random.uniform(0, 1)
    connection_count = random.randint(1, 100)
    unusual_patterns = random.choice([True, False])

    if anomaly_score > 0.7:
        assessment = "High Risk - Anomalous behavior detected"
        details = f"GNN detected unusual traffic patterns with anomaly score {anomaly_score:.2f}. High connection count ({connection_count}) suggests potential botnet activity."
    elif anomaly_score > 0.4:
        assessment = "Medium Risk - Suspicious behavior"
        details = f"GNN identified moderate anomalies (score {anomaly_score:.2f}). Connection count: {connection_count}. Recommend monitoring."
    else:
        assessment = "Low Risk - Normal behavior"
        details = f"GNN analysis shows normal traffic patterns (score {anomaly_score:.2f}). Connection count: {connection_count} within expected range."

    report = f"""
Behavioral Analysis Report for IP {ip_address} (GNN-based):

Assessment: {assessment}

Details:
- Anomaly Score: {anomaly_score:.2f} (0-1 scale, higher = more anomalous)
- Connection Count: {connection_count}
- Unusual Patterns Detected: {unusual_patterns}

GNN Insights:
- Graph analysis shows {'high interconnectivity' if connection_count > 50 else 'normal connectivity'}
- {'Temporal patterns suggest automated activity' if unusual_patterns else 'Patterns consistent with legitimate traffic'}

Recommendation: {'Immediate blocking and investigation' if anomaly_score > 0.7 else 'Monitor closely' if anomaly_score > 0.4 else 'No action required'}
"""

    return report.strip()

# ==============================================================================
# TOOL 7: BLOCKCHAIN LOGS VIEWER (Phase 2)
# ==============================================================================
@tool
def get_blockchain_logs() -> str:
    """
    Retrieves the immutable blockchain logs for audit and verification.
    Returns a JSON string of all blockchain blocks containing log entries.
    """
    from blockchain import get_blockchain_logs
    logs = get_blockchain_logs()
    return json.dumps(logs, indent=2)

# ==============================================================================
# TOOL 7: TASK COMPLETION TOOL
# ==============================================================================
@tool
def end_task() -> str:
    """
    Use this tool as your final action when you have successfully completed your task
    (either by blocking an IP or logging it for human review) and no further
    action is required. This will end the current operation.
    """
    return "Task successfully completed and terminated."
# ==============================================================================
# TEST BLOCK (No changes made)
# ==============================================================================
if __name__ == '__main__':
    """
    This block allows us to test the tools directly by running `python tools.py`
    in the terminal. It's a good practice for ensuring each tool works as expected
    before integrating them into the agentic framework.
    """
    print("--- Testing Agent Tools ---")
    
    print("\n[1] Testing IP Reputation Tool...")
    # Test with a known malicious IP (example, may change over time)
    bad_ip = "118.173.211.168"
    print(f"\nChecking potentially malicious IP: {bad_ip}")
    print(check_ip_reputation(bad_ip))
    
    # Test with a known clean IP (Google's DNS)
    good_ip = "8.8.8.8"
    print(f"\nChecking clean IP: {good_ip}")
    print(check_ip_reputation(good_ip))
    
    print("\n" + "="*40)
    
    print("\n[2] Testing WHOIS Tool...")
    # Test with a domain
    domain = "google.com"
    print(f"\nChecking WHOIS for domain: {domain}")
    print(get_whois_info(domain))
    
    # Test with an IP address
    ip = "8.8.8.8"
    print(f"\nChecking WHOIS for IP: {ip}")
    print(get_whois_info(ip))
    
    print("\n" + "="*40)
    
    print("\n[3] Testing Simulated Firewall Tool...")
    # --- CHANGE: The test now creates a dictionary to pass to the tool ---
    block_details_to_test = '{"details": {"ip_address": "103.224.212.222", "reason": "High confidence C&C server detected by Coordinator Agent."}}'
    print(f"\nSimulating block for IP: 103.224.212.222")
    # --- CHANGE: The tool is now called with the single dictionary argument ---
    print(create_firewall_block_rule(block_details_to_test))