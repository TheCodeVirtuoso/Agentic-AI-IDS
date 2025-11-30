# IEEE Paper Summary: An Agentic AI Framework for Autonomous Cybersecurity Defense

**Abstract**—This paper presents a novel multi-agent framework for an autonomous Intrusion Detection System (IDS). The system leverages Large Language Models (LLMs) to power a team of specialized AI agents that collaborate to detect, investigate, and respond to cybersecurity threats in real-time. By integrating machine learning-based anomaly detection, multi-source threat intelligence correlation, and a blockchain-based immutable ledger, the proposed framework demonstrates a significant advancement in the automation of Security Operations Center (SOC) workflows.

**I. INTRODUCTION**

The increasing volume and sophistication of cyber threats necessitate a paradigm shift from traditional, human-in-the-loop security operations to more autonomous and intelligent systems. This paper introduces an agentic AI framework that simulates a collaborative SOC, where specialized agents work in concert to provide a rapid and effective defense against network intrusions.

**II. SYSTEM ARCHITECTURE**

The framework is composed of three core AI agents:

*   **Anomaly Agent:** An LLM-powered investigator that uses a suite of tools to analyze suspicious IP addresses. Its capabilities include querying external threat intelligence APIs (AbuseIPDB, VirusTotal), performing WHOIS lookups, and executing behavioral analysis.
*   **Coordinator Agent:** A decision-making agent that receives the Anomaly Agent's report and, based on a calculated confidence score, executes a response. Its actions include creating firewall rules and logging incidents for human review.
*   **Signature Agent:** A proactive threat hunter that monitors external threat feeds and triggers the Anomaly Agent to investigate new, known threats.

**III. KEY TECHNOLOGIES**

*   **LangChain Framework:** The agents are built using the LangChain framework, which facilitates the integration of LLMs with external tools and data sources.
*   **Isolation Forest:** A pre-trained Isolation Forest model is used for unsupervised anomaly detection in network traffic data.
*   **Blockchain:** A simple, custom-built blockchain provides an immutable ledger for all critical system actions, ensuring a secure and verifiable audit trail.
*   **Flask:** A lightweight web framework is used to create a real-time dashboard for monitoring the system's activities.

**IV. CONCLUSION**

The proposed agentic AI framework presents a promising approach to automating cybersecurity defense. By combining the strengths of LLMs, machine learning, and blockchain technology, the system provides a robust, adaptive, and extensible solution for modern threat detection and response. Future work will focus on expanding the agent's toolset, implementing a model retraining pipeline, and exploring more advanced collaborative behaviors.
