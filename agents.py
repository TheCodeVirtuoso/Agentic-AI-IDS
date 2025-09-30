import os
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import PromptTemplate

# Import the tools we created in Phase 2.
from tools import check_ip_reputation, get_whois_info, create_firewall_block_rule, log_for_human_review

# Load environment variables from the .env file
load_dotenv()

# ==============================================================================
# 1. INITIALIZE THE LLM
# ==============================================================================
llm = ChatGoogleGenerativeAI(model="gemini-2.5-pro", 
                             temperature=0.0, # CRITICAL: Set to 0.0 for maximum determinism (changed from 0.3)
                             convert_system_message_to_human=True)

# ==============================================================================
# 2. ANOMALY AGENT (THE "INVESTIGATOR")
# ==============================================================================
anomaly_agent_tools = [check_ip_reputation, get_whois_info]
anomaly_prompt_template = """
You are a cybersecurity analyst AI. Your mission is to investigate a suspicious IP address.

**Available Tools:**
{tools}

**Output Format Rules:**
When you use a tool, you MUST use the following format:
Thought: Your reasoning for using a tool.
Action: The name of the tool to use from this list: [{tool_names}]
Action Input: The input for the tool (e.g., the IP address)
When you have gathered all facts, you MUST provide your final answer in this exact format:
Thought: I have enough information to create the final report.
Final Answer:
IP Address: [The IP you investigated]
Threat Assessment: [High Risk | Medium Risk | Low Risk | Benign]
Summary:
[Bullet point of evidence 1]
Recommendation: [Recommend blocking | Monitor for further activity | No action needed]
**Begin Investigation!**
**IP to Investigate:** {input}
**Your Investigation Log:** {agent_scratchpad}
"""
anomaly_agent_prompt = PromptTemplate.from_template(anomaly_prompt_template)
anomaly_agent = create_react_agent(llm, anomaly_agent_tools, anomaly_agent_prompt)
anomaly_agent_executor = AgentExecutor(agent=anomaly_agent, 
                                       tools=anomaly_agent_tools, 
                                       verbose=True,
                                       handle_parsing_errors=True)

# ==============================================================================
# 3. COORDINATOR AGENT (THE "MANAGER")
# ==============================================================================
coordinator_tools = [create_firewall_block_rule, log_for_human_review]

# --- CRITICAL FIX APPLIED HERE ---
# We add {tool_names} to the main prompt body to ensure it is visible to the parser.
import os
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import PromptTemplate

# Import the tools we created in Phase 2.
from tools import check_ip_reputation, get_whois_info, create_firewall_block_rule, log_for_human_review

# Load environment variables from the .env file
load_dotenv()

# ==============================================================================
# 1. INITIALIZE THE LLM
# ==============================================================================
llm = ChatGoogleGenerativeAI(model="gemini-pro-latest", # Changed model to gemini-pro for stability
                             temperature=0.0, 
                             convert_system_message_to_human=True)

# ==============================================================================
# 2. ANOMALY AGENT (THE "INVESTIGATOR")
# ==============================================================================
anomaly_agent_tools = [check_ip_reputation, get_whois_info]
anomaly_prompt_template = """
You are a cybersecurity analyst AI. Your mission is to investigate a suspicious IP address.

**Available Tools:**
{tools}

**Output Format Rules:**
When you use a tool, you MUST use the following format:
Thought: Your reasoning for using a tool.
Action: The name of the tool to use from this list: [{tool_names}]
Action Input: The input for the tool (e.g., the IP address)
When you have gathered all facts, you MUST provide your final answer in this exact format:
Thought: I have enough information to create the final report.
Final Answer:
IP Address: [The IP you investigated]
Threat Assessment: [High Risk | Medium Risk | Low Risk | Benign]
Summary:
[Bullet point of evidence 1]
Recommendation: [Recommend blocking | Monitor for further activity | No action needed]
**Begin Investigation!**
**IP to Investigate:** {input}
**Your Investigation Log:** {agent_scratchpad}
"""
anomaly_agent_prompt = PromptTemplate.from_template(anomaly_prompt_template)
anomaly_agent = create_react_agent(llm, anomaly_agent_tools, anomaly_agent_prompt)
anomaly_agent_executor = AgentExecutor(agent=anomaly_agent, 
                                       tools=anomaly_agent_tools, 
                                       verbose=True,
                                       handle_parsing_errors=True)

# ==============================================================================
# 3. COORDINATOR AGENT (THE "MANAGER")
# ==============================================================================
coordinator_tools = [create_firewall_block_rule, log_for_human_review]

# --- CRITICAL FIX APPLIED HERE ---
coordinator_prompt_template = """
You are a rule-based AI Agent managing a SOC. You will be given a report. Follow your rules exactly.

**Available Tools (Use only the names listed here: {tool_names}):** 
{tools}

**Your Rules:**
1.  Review the "Threat Assessment" in the report.
2.  If the "Threat Assessment" is "High Risk", you MUST use the `create_firewall_block_rule` tool.
3.  If the "Threat Assessment" is NOT "High Risk" (Low, Medium, or Benign), you MUST use the `log_for_human_review` tool.
4.  **Your entire response MUST consist ONLY of the Action: and Action Input: lines to execute the required tool, and nothing else.**

**CRITICAL RESPONSE FORMATTING (Must follow these exact formats):**

**FORMAT 1: If you decide to BLOCK (threat is "High Risk")**
Action: create_firewall_block_rule
Action Input: {{"details": {{"ip_address": "...", "reason": "..."}}}}

**FORMAT 2: If you decide to LOG FOR REVIEW (threat is NOT "High Risk")**
Action: log_for_human_review
Action Input: {{"case_details": {{"ip_address": "...", "threat_level": "...", "report_summary": "..."}}}}

**Begin Decision Process.**
**Intelligence Report to Analyze:**
---
{input}
---
{agent_scratchpad}
"""
# We intentionally remove the 'Your Decision Log:' header as it sometimes triggers conversational filler.

coordinator_prompt = PromptTemplate.from_template(coordinator_prompt_template)
coordinator_agent = create_react_agent(llm, coordinator_tools, coordinator_prompt)
coordinator_agent_executor = AgentExecutor(agent=coordinator_agent,
                                         tools=coordinator_tools,
                                         verbose=True,
                                         handle_parsing_errors=True)

# ==============================================================================
# 4. SIGNATURE AGENT (THE "PROACTIVE HUNTER") - As a function
# ==============================================================================
def run_signature_check(processed_ips: set, threat_feed_file: str) -> set:
    """
    This function acts as the Signature Agent. It reads a threat feed,
    identifies new threats, and passes a report to the Coordinator Agent.
    """
    print("\n--- [Signature Agent Function] Checking threat feed... ---")
    try:
        if not os.path.exists(threat_feed_file): return processed_ips
        with open(threat_feed_file, 'r') as f:
            current_threat_ips = {line.strip() for line in f if line.strip()}
        new_threats = current_threat_ips - processed_ips
        if new_threats:
            print(f"Found {len(new_threats)} new threat(s) in feed: {', '.join(new_threats)}")
            for ip in new_threats:
                report = f"- IP Address: {ip}\n- Threat Assessment: High Risk\n- Summary: IP found on threat intelligence feed.\n- Recommendation: Recommend blocking"
                print(f"--- [Signature Agent Function] New threat {ip} found. Sending report to Coordinator... ---")
                coordinator_agent_executor.invoke({"input": report})
                processed_ips.add(ip)
        else: print("--- [Signature Agent Function] No new threats found in feed. ---")
        return processed_ips
    except Exception as e:
        print(f"[ERROR] An error occurred in the signature agent function: {e}")
        return processed_ips