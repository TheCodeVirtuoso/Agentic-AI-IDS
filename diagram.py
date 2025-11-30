from graphviz import Digraph

# CRITICAL CHANGE: rankdir='LR' for Left-to-Right (horizontal) layout
dot = Digraph('ACF_Architecture_Horizontal', comment='Agentic Cybersecurity Framework Architecture')
dot.attr(rankdir='LR', splines='ortho', nodesep='0.5', ranksep='1.5')
dot.attr('node', shape='box', style='rounded,filled', fillcolor='#2D3748', fontname='Helvetica', color='#E2E8F0', fontcolor='#E2E8F0')
dot.attr('edge', color='#4A5568', fontname='Helvetica')
dot.attr('graph', bgcolor='transparent', label='Agentic Cybersecurity Framework (ACF) - Horizontal Flow', fontname='Helvetica', fontsize='20', fontcolor='#E2E8F0')

# --- Column 1: Input Sources ---
with dot.subgraph(name='cluster_0') as c:
    c.attr(style='rounded,filled', fillcolor='#1A202C', color='#4A5568', label='Input Sources')
    c.node('data_source', 'Network Flow Data', shape='cylinder')
    c.node('threat_feed', 'Threat Feed', shape='note')

# --- Column 2: Detection and Analysis ---
with dot.subgraph(name='cluster_1') as c:
    c.attr(style='rounded,filled', fillcolor='#1A202C', color='#4A5568', label='Detection and Analysis')
    c.node('ml_model', 'Isolation Forest\nML Model')
    c.node('anomaly_agent', 'Anomaly Agent\n(LLM)', shape='Mdiamond', fillcolor='#4299E1')
    c.node('signature_agent', 'Signature Agent\n(Function)', shape='septagon', fillcolor='#48BB78')
    
    # Place API tools in the same rank to align them
    with c.subgraph(name='cluster_apis') as api_cluster:
        api_cluster.attr(rank='same', style='invis')
        api_cluster.node('whois_api', 'WHOIS API', shape='folder', fillcolor='#667EEA')
        api_cluster.node('abusedb_api', 'AbuseDB API', shape='folder', fillcolor='#667EEA')

# --- Column 3: Coordination and Decision ---
with dot.subgraph(name='cluster_2') as c:
    c.attr(style='rounded,filled', fillcolor='#1A202C', color='#E53E3E', label='Coordination and Decision')
    c.node('coordinator_agent', 'Coordinator Agent\n(LLM)', shape='octagon')
    c.node('decision_diamond', 'Risk Level\nHigh?', shape='diamond', fillcolor='#38B2AC')

# --- Column 4: Response and Audit ---
with dot.subgraph(name='cluster_3') as c:
    c.attr(style='rounded,filled', fillcolor='#1A202C', color='#4A5568', label='Response and Audit')
    c.node('block_action', 'Firewall Block Action', shape='parallelogram', fillcolor='#C53030')
    c.node('log_action', 'Human Review Queue', shape='parallelogram', fillcolor='#D69E2E')
    c.node('audit_trail', 'Immutable Audit Trail', shape='box3d', fillcolor='#718096')

# --- Define Edges (Connections) ---
# Input to Detection
dot.edge('data_source', 'ml_model')
dot.edge('threat_feed', 'signature_agent')

# Detection to Analysis
dot.edge('ml_model', 'anomaly_agent', label='Raw Anomaly\nAlert')
dot.edge('anomaly_agent', 'whois_api')
dot.edge('anomaly_agent', 'abusedb_api')

# Analysis to Coordination
dot.edge('anomaly_agent', 'coordinator_agent', label='  Structured Report\nwith Confidence Score  ', tailport='e', headport='w')
dot.edge('signature_agent', 'coordinator_agent', label='High-Confidence\nAlert', tailport='e', headport='w')

# Coordination to Decision
dot.edge('coordinator_agent', 'decision_diamond')

# Decision to Response
dot.edge('decision_diamond', 'block_action', label='Yes')
dot.edge('decision_diamond', 'log_action', label='No')

# Response to Audit
dot.edge('block_action', 'audit_trail', style='dashed')
dot.edge('log_action', 'audit_trail', style='dashed')


# --- Render the graph ---
try:
    dot.render('ACF_Architecture_Horizontal', format='png', view=False, cleanup=True)
    print("SUCCESS: 'ACF_Architecture_Horizontal.png' has been created.")
    print("Please rename this file to 'placeholder_architecture_diagram.png' and upload it to Overleaf.")
except Exception as e:
    print(f"ERROR: Could not render the diagram. Please ensure Graphviz is installed and in your system PATH.")
    print(f"Details: {e}")