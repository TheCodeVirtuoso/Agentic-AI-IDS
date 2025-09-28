import os
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.agents import tool, AgentExecutor, create_react_agent
from langchain_core.prompts import PromptTemplate
from langchain.agents import tool
# Import the tools we created in Phase 2
from tools import check_ip_reputation, get_whois_info,create_firewall_block_rule

# Load environment variables from .env file
load_dotenv()

# ==============================================================================
# AGENT IMPLEMENTATION
# ==============================================================================

# 1. Initialize the LLM (The "Brain" of the agent)
# We'll use Google's Gemini Pro model.
llm = ChatGoogleGenerativeAI(model="gemini-2.5-pro", 
                             temperature=0.3, # Lower temperature for more deterministic, factual responses
                             convert_system_message_to_human=True) # Helps with compatibility

# 2. Define the Tools
# LangChain needs to know what tools the agent can use. We wrap our functions
# from tools.py in a list.
tools = [check_ip_reputation, get_whois_info]

# 3. Create the Prompt Template (The "Instructions" for the agent)
# This is the most critical part. We tell the agent who it is, what its goal is,
# what tools it has, and how it should think.
prompt_template = """
You are an expert cybersecurity analyst AI agent. Your mission is to investigate suspicious IP addresses.

You have access to the following tools:
{tools}

To conduct your investigation, use the tool names listed here: {tool_names}

You must use the following thinking process:
1.  **Question:** What is the first piece of information I need to gather about the IP address?
2.  **Thought:** I should use a specific tool to find this information. I will decide which tool is best.
3.  **Action:** The tool I will use, along with the required input (the IP address).
4.  **Observation:** The result returned by the tool.
5.  ... (Repeat this Question/Thought/Action/Observation process as many times as necessary to gather all the facts).
6.  **Final Thought:** I now have enough information to form a conclusion.
7.  **Final Answer:** A comprehensive summary of your findings. This summary must be structured as follows:
    - **IP Address:** The IP that was investigated.
    - **Threat Assessment:** A final verdict (e.g., "High Risk," "Medium Risk," "Low Risk," "Benign").
    - **Summary:** A concise, bullet-pointed summary of all the evidence found (e.g., from WHOIS, IP reputation checks).
    - **Recommendation:** A suggested action (e.g., "Recommend blocking," "Monitor for further activity," "No action needed").

Begin your investigation for the following IP address:
{input}

Your thought process log (Question/Thought/Action/Observation):
{agent_scratchpad}
"""

# Create the prompt from the template
prompt = PromptTemplate.from_template(prompt_template)


# 4. Create the Agent
# This binds the LLM, the prompt, and the tools together.
anomaly_agent = create_react_agent(llm, tools, prompt)

# 5. Create the Agent Executor
# This is the runtime environment that actually makes the agent work.
# It invokes the agent, executes the chosen tools, and logs the process.
# `verbose=True` is essential for debugging as it shows the agent's thought process.
anomaly_agent_executor = AgentExecutor(agent=anomaly_agent, 
                                       tools=tools, 
                                       verbose=True,
                                       handle_parsing_errors=True) # Helps with stability

# ==============================================================================
# COORDINATOR AGENT IMPLEMENTATION
# ==============================================================================

# 1. Define the Tools for the Coordinator
# This agent only has one job: to block threats. So it only needs one tool.
coordinator_tools = [create_firewall_block_rule]

# 2. Create the Prompt Template for the Coordinator
# This prompt is different. It's not about investigation, it's about decision-making.
coordinator_prompt_template = """
You are the Coordinator Agent, the manager of an Autonomous Security Operations Center (SOC).
You have received an intelligence report from an analyst agent about a suspicious IP address.
Your job is to review this report and make a final decision.

You have access to the following tool:
{tools}

Use the tool names listed here: {tool_names}

Analyze the provided intelligence report and follow these rules:
1.  If the report's "Threat Assessment" is "High Risk" AND the "Recommendation" is to "Recommend blocking", then you MUST take action.
2.  Your action should be to use the `create_firewall_block_rule` tool.
3.  The `reason` for the block should be a concise summary of the findings from the report (e.g., "High abuse score, associated with brute-force attacks.").
4.  If the Threat Assessment is "Medium Risk," "Low Risk," or "Benign," you will not take any action. Your final answer should state that you are escalating to a human analyst for review.

Here is the intelligence report:
---
{input}
---

Based on the report and your rules, determine your final course of action.
Your thought process log (Thought/Action/Observation):
{agent_scratchpad}
"""

# Create the prompt from the template
coordinator_prompt = PromptTemplate.from_template(coordinator_prompt_template)

# 3. Create the Coordinator Agent
coordinator_agent = create_react_agent(llm, coordinator_tools, coordinator_prompt)

# 4. Create the Coordinator Agent Executor
coordinator_agent_executor = AgentExecutor(agent=coordinator_agent,
                                         tools=coordinator_tools,
                                         verbose=True,
                                         handle_parsing_errors=True)


# ==============================================================================
# TEST BLOCK
# ==============================================================================


# ==============================================================================
# TEST BLOCK - FULL WORKFLOW SIMULATION
# ==============================================================================
if __name__ == '__main__':
    print("------ Starting Full SOC Workflow Simulation ------")
    
    # A known malicious IP to trigger a "High Risk" assessment
    suspicious_ip = "103.224.212.222" # This IP is often reported for web attacks
    
    # --- STAGE 1: ANOMALY AGENT INVESTIGATION ---
    print(f"\n[STAGE 1] Anomaly Agent is investigating IP: {suspicious_ip}...")
    
    # Invoke the anomaly agent
    investigation_result = anomaly_agent_executor.invoke({"input": suspicious_ip})
    investigation_report = investigation_result['output']
    
    print("\n--- [STAGE 1] Anomaly Agent's Final Report ---")
    print(investigation_report)
    
    # --- STAGE 2: COORDINATOR AGENT DECISION ---
    print("\n\n[STAGE 2] Coordinator Agent is reviewing the report...")
    
    # Invoke the coordinator agent with the report from the first agent
    final_decision = coordinator_agent_executor.invoke({"input": investigation_report})
    
    print("\n--- [STAGE 2] Coordinator Agent's Final Action ---")
    print(final_decision['output'])

    print("\n------ Full SOC Workflow Simulation Complete ------")