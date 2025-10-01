import os
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.agents import AgentExecutor, create_react_agent
from langchain.memory import ConversationBufferWindowMemory
from langchain_core.prompts import PromptTemplate

# Import the tools we created in Phase 2.
from tools import check_ip_reputation, get_whois_info, create_firewall_block_rule, log_for_human_review, end_task, fetch_threat_intelligence, analyze_behavior

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
anomaly_agent_tools = [check_ip_reputation, get_whois_info, analyze_behavior]
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
                                       handle_parsing_errors=True,
                                       memory=ConversationBufferWindowMemory(k=5))




coordinator_tools = [create_firewall_block_rule, log_for_human_review, end_task]

# --- FINAL, ULTIMATE FIX APPLIED HERE ---
coordinator_prompt_template = """
You are a coordinator agent. Based on the threat assessment in the report:

- If "High Risk", block the IP using create_firewall_block_rule with IP and reason.
- Otherwise, log for human review using log_for_human_review with IP, threat_level, report_summary.

Then, always end the task with end_task.

Use the ReAct format: Thought, Action, Action Input.

Available Tools: {tools}

Tool Names: {tool_names}

Report:
{input}

{agent_scratchpad}
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
                report = f"- IP Address: {ip}\n- Threat Assessment: High Risk\n- Summary: IP found on threat intelligence feed.\n- Recommendation: Recommend blocking"
                print(f"--- [Signature Agent Function] New threat {ip} found. Sending report to Coordinator... ---")
                coordinator_agent_executor.invoke({"input": report})
                processed_ips.add(ip)
        else: print("--- [Signature Agent Function] No new threats found in feed. ---")
        return processed_ips
    except Exception as e:
        print(f"[ERROR] An error occurred in the signature agent function: {e}")
        return processed_ips
