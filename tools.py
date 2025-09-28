import os
import requests
import json
import whois
import datetime
from dotenv import load_dotenv
from typing import Union

# Load environment variables from the .env file in the project's root directory
load_dotenv()

# ==============================================================================
# TOOL 1: IP REPUTATION CHECKER
# ==============================================================================
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
        
        # If the score is > 0, provide a detailed, multi-line summary for the LLM to parse
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
             # It's likely an IP address lookup
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

        # It's a domain name lookup
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
# TOOL 3: SIMULATED FIREWALL BLOCK
# ==============================================================================
def create_firewall_block_rule(ip_address: str, reason: str) -> str:
    """
    Simulates creating a firewall rule to block an IP address. This is a safe
    "action" tool for the Coordinator Agent. It prints the action to the console
    and appends it to a log file for auditing purposes.
    
    Args:
        ip_address: The IP address to be blocked.
        reason: The reason for blocking the IP, provided by the Coordinator Agent.

    Returns:
        A confirmation message that the action was logged.
    """
    log_message = (
        f"{datetime.datetime.now().isoformat()} - [ACTION] - BLOCK IP: {ip_address} - REASON: {reason}"
    )
    
    # Print to console for immediate feedback during runtime
    print(log_message)
    
    # Append to a log file for record-keeping
    try:
        with open("firewall_rules.log", "a") as f:
            f.write(log_message + "\n")
        return f"Success: Firewall block rule for IP {ip_address} was simulated and logged."
    except Exception as e:
        return f"Error: Could not write to firewall log file. Details: {e}"

# ==============================================================================
# TEST BLOCK
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
    malicious_ip_to_block = "103.224.212.222" # Example IP from a threat feed
    block_reason = "High confidence C&C server detected by Coordinator Agent."
    print(f"\nSimulating block for IP: {malicious_ip_to_block}")
    print(create_firewall_block_rule(malicious_ip_to_block, block_reason))