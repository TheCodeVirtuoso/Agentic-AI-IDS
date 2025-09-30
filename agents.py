import os
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import PromptTemplate

# Import the tools we created in Phase 2.
from tools import check_ip_reputation, get_whois_info, create_firewall_block_rule

# Load environment variables from the .env file
load_dotenv()

# ==============================================================================
# 1. INITIALIZE THE LLM
# ==============================================================================
llm = ChatGoogleGenerativeAI(model="gemini-pro-latest", 
                             temperature=0.3, # Set to 0.0 for maximum determinism and format adherence
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
You MUST use the following format to use a tool:
Thought: Your reasoning for using a tool.
Action: The name of the tool to use from this list: [{tool_names}]
Action Input: The input for the tool (e.g., the IP address).

When you have gathered all facts, provide your final answer in this exact format:

Thought: I have enough information to create the final report.
Final Answer:
IP Address: [The IP you investigated]
Threat Assessment: [High Risk | Medium Risk | Low Risk | Benign]
Summary:
[Bullet point of evidence 1]
[Bullet point of evidence 2]
Recommendation: [Recommend blocking | Monitor for further activity | No action needed]


**Begin Investigation!**
**IP to Investigate:** {input}
**Your Investigation Log:**
{agent_scratchpad}
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
coordinator_tools = [create_firewall_block_rule]

# THIS IS THE CRITICAL FIX: The prompt is now extremely strict and provides a direct template.
coordinator_prompt_template = """
You are a decision-making AI Agent managing a Security Operations Center. You will be given a report. Follow your rules exactly.

**Available Tool:**
{tools}

**RULES:**
1.  Review the "Threat Assessment" in the report.
2.  If "Threat Assessment" is "High Risk", you MUST use the `create_firewall_block_rule` tool.
3.  If "Threat Assessment" is NOT "High Risk", you MUST NOT use any tools. Your FINAL ANSWER must be: "Escalate to human analyst."

**CRITICAL FORMATTING INSTRUCTION:**
When you use the `create_firewall_block_rule` tool, you MUST format your response in EXACTLY two lines like this, and nothing else:

Action: {tool_names}
Action Input: {{"ip_address": "...", "reason": "..."}}

**Do not add any other text or formatting. Replace the ... with data from the report.**

**Intelligence Report:**
---
{input}
---

**Begin Decision Process.**
Your Decision Log:
{agent_scratchpad}
"""

coordinator_prompt = PromptTemplate.from_template(coordinator_prompt_template)
coordinator_agent = create_react_agent(llm, coordinator_tools, coordinator_prompt)
coordinator_agent_executor = AgentExecutor(agent=coordinator_agent,
                                         tools=coordinator_tools,
                                         verbose=True,
                                         handle_parsing_errors=True)

# ==============================================================================
# 4. TEST BLOCK (For directly testing this file, not used by main.py)
# ==============================================================================
if __name__ == '__main__':
    print("This file defines the agents. To run the full simulation, run main.py.")
    pass