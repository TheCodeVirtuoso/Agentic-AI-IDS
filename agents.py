import os
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.agents import AgentExecutor, create_react_agent
from langchain.memory import ConversationBufferWindowMemory
from langchain_core.prompts import PromptTemplate

# Import the tools we created in Phase 2.
from tools import check_ip_reputation, get_whois_info, create_firewall_block_rule, log_for_human_review, end_task, fetch_threat_intelligence, analyze_behavior, check_virustotal

# Load environment variables from the .env file
load_dotenv()

# ==============================================================================
# 1. INITIALIZE THE LLM
# ==============================================================================
llm = ChatGoogleGenerativeAI(model="gemini-pro-latest",
                             temperature=0.0, # CRITICAL: Set to 0.0 for maximum determinism
                             convert_system_message_to_human=True)

# ==============================================================================
# 2. ANOMALY AGENT (THE "INVESTIGATOR")
# ==============================================================================
anomaly_agent_tools = [check_ip_reputation, get_whois_info, analyze_behavior, check_virustotal]
# In agents.py, replace anomaly_prompt_template:

anomaly_prompt_template = """
You are a cybersecurity analyst AI. Your mission is to investigate a suspicious IP address and produce a structured report. You are the "Anomaly Agent".

**Available Tools:**
{tools}

**Output Format Rules:**
When you use a tool, you MUST use the following format:
Thought: Your reasoning for using a tool.
Action: The name of the tool to use from this list: [{tool_names}]
Action Input: The input for the tool (e.g., the IP address)

**SCORING GUIDELINES (USE THESE FOR YOUR FINAL ASSESSMENT):**
- Start Score at 0.
- IF Abuse Score > 50: ADD 40 points.
- IF VirusTotal Malicious Engines > 0: ADD 25 points.
- IF Abuse Score == 0 AND WHOIS points to a major trusted entity (Google, Cloudflare): SUBTRACT 10 points.
- IF WHOIS indicates a high-risk hosting provider: ADD 20 points.

When you have gathered all facts, you MUST provide your final answer in this exact format:
Thought: I have calculated the confidence score and have enough information to create the final report.
Final Answer:
- IP Address: [The IP you investigated]
- Confidence Score: [The final calculated score out of 100]
- Threat Assessment: [High Risk | Medium Risk | Low Risk | Benign] (Based on score: > 40 is High, 10-40 is Medium, < 10 is Low/Benign)
- Summary:
    - [Bullet point of evidence 1]
- Recommendation: [Recommend blocking | Monitor for further activity | No action needed]
**Begin Investigation!**
**IP to Investigate:** {input}
**Your Investigation Log:** {agent_scratchpad}
"""
anomaly_agent_prompt = PromptTemplate.from_template(anomaly_prompt_template)
anomaly_agent = create_react_agent(llm, anomaly_agent_tools, anomaly_agent_prompt)
anomaly_agent_executor = AgentExecutor(agent=anomaly_agent,
                                       tools=anomaly_agent_tools,
                                       verbose=True,
                                       handle_parsing_errors=True,
                                       memory=ConversationBufferWindowMemory(k=5))




coordinator_tools = [create_firewall_block_rule, log_for_human_review, end_task]

# --- FINAL, ULTIMATE FIX APPLIED HERE ---
# In agents.py, replace coordinator_prompt_template:

coordinator_prompt_template = """
You are a single-step decision-making agent. Your entire purpose is to choose and execute one tool based on the report. You are the "Coordinator Agent".

**Available Tools (Use only the names listed here: {tool_names}):** 
{tools}

**Your Rules:**
1.  Review the "Confidence Score" in the report.
2.  If the "Confidence Score" is greater than 50, you MUST use the `create_firewall_block_rule` tool.
3.  If the "Confidence Score" is 50 or less, you MUST use the `log_for_human_review` tool.

**CRITICAL RESPONSE FORMATTING:**
You must follow the Action/Action Input format.

**Begin Decision Process.**
**Intelligence Report to Analyze:**
---
{input}
---
Your Decision Log: {agent_scratchpad}
"""
# --- END FINAL FIX ---

coordinator_prompt = PromptTemplate.from_template(coordinator_prompt_template)
coordinator_agent = create_react_agent(llm, coordinator_tools, coordinator_prompt)
coordinator_agent_executor = AgentExecutor(agent=coordinator_agent,
                                         tools=coordinator_tools,
                                         verbose=True,
                                         handle_parsing_errors=True,
                                         max_iterations=2,
                                         memory=ConversationBufferWindowMemory(k=5))

# ==============================================================================
# 4. SIGNATURE AGENT (THE "PROACTIVE HUNTER") - As a function
# ==============================================================================
def run_signature_check(processed_ips: set, threat_feed_file: str) -> set:
    """
    This function acts as the Signature Agent. It reads a threat feed,
    identifies new threats, and passes a report to the Coordinator Agent.
    Now includes real-time threat intelligence fusion from OTX API (Phase 2).
    """
    print("\n--- [Signature Agent Function] Checking threat feed and fetching real-time intelligence... ---")
    try:
        # Phase 2: Fetch real-time threats from OTX
        otx_result = fetch_threat_intelligence.run("")
        print(f"[Phase 2] {otx_result}")
        if "Fetched" in otx_result:
            # Extract IPs from the result and add to threat feed
            try:
                threats_str = otx_result.split(": ")[1].split("...")[0]
                otx_ips = [ip.strip() for ip in threats_str.split(", ") if ip.strip()]
                with open(threat_feed_file, 'a') as f:
                    for ip in otx_ips:
                        if ip not in processed_ips:
                            f.write(ip + "\n")
            except:
                pass  # If parsing fails, continue with file

        if not os.path.exists(threat_feed_file): return processed_ips
        with open(threat_feed_file, 'r') as f:
            current_threat_ips = {line.strip() for line in f if line.strip()}
        new_threats = current_threat_ips - processed_ips
        if new_threats:
            print(f"Found {len(new_threats)} new threat(s) in feed: {', '.join(new_threats)}")
            for ip in new_threats:
                print(f"--- [Signature Agent Function] New threat {ip} found. Triggering Anomaly Agent for full investigation... ---")
                report_dict = anomaly_agent_executor.invoke({"input": ip})
                investigation_report = report_dict['output']
                print(f"--- [Signature Agent Function] Anomaly Agent investigation complete for {ip}. Sending report to Coordinator... ---")
                coordinator_agent_executor.invoke({"input": investigation_report})
                processed_ips.add(ip)
        else: print("--- [Signature Agent Function] No new threats found in feed. ---")
        return processed_ips
    except Exception as e:
        print(f"[ERROR] An error occurred in the signature agent function: {e}")
        return processed_ips
