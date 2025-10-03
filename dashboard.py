from flask import Flask, render_template_string, request, redirect, url_for, session,jsonify
import os
import json
from datetime import datetime
import pytz
from agents import anomaly_agent_executor, coordinator_agent_executor
import time
import hashlib
app = Flask(__name__)
app.secret_key = 'cn-agentic-ids-secret-key'  # For session management
# --- 1. BLOCKCHAIN IMPLEMENTATION ---
class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps({
            "index": self.index, "timestamp": self.timestamp,
            "data": self.data, "previous_hash": self.previous_hash
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, time.time(), "Genesis Block: NexusGuard AI System Initialized", "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, data):
        latest_block = self.get_latest_block()
        new_block = Block(latest_block.index + 1, time.time(), data, latest_block.hash)
        self.chain.append(new_block)
        return new_block

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            if current_block.hash != current_block.calculate_hash():
                return False
            if current_block.previous_hash != previous_block.hash:
                return False
        return True

    def get_chain(self):
        return [block.__dict__ for block in self.chain]

# Global blockchain instance and helper functions
log_blockchain = Blockchain()
log_blockchain.add_block("System Startup: Agent monitoring initiated.") # Initial log for demo

def add_log_to_blockchain(log_entry):
    return log_blockchain.add_block(log_entry)

def get_blockchain_logs():
    return log_blockchain.get_chain()
# Paths to log files
FIREWALL_LOG = 'firewall_rules.log'
REVIEW_LOG = 'review_queue.log'
FEEDBACK_LOG = 'feedback.log'
INVESTIGATION_LOG = 'investigation_times.log'

# Logs Template


# --- (Other File Paths & Templates) ---
FIREWALL_LOG = 'firewall_rules.log'
REVIEW_LOG = 'review_queue.log'
FEEDBACK_LOG = 'feedback.log'
INVESTIGATION_LOG = 'investigation_times.log'

# --- 2. NEW BLOCKCHAIN VISUALIZATION TEMPLATE ---
BLOCKCHAIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Blockchain Integrity - NexusGuard AI</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" />
    <style>
        @keyframes gradientBG { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }
        body { 
            background: linear-gradient(-45deg, #0f0f23, #1a1a2e, #16213e, #0f0f23); 
            background-size: 400% 400%; animation: gradientBG 15s ease infinite; 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #e2e8f0;
            overflow: hidden; /* Prevent scrollbars during preloader */
        }
        
        /* --- BLOCKCHAIN PRELOADER --- */
        #preloader {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: #0f0f23; z-index: 10000;
            display: flex; justify-content: center; align-items: center; text-align: center;
            opacity: 1; transition: opacity 1s ease-out;
        }
        #preloader.fade-out { opacity: 0; }
        .cube-container { display: flex; }
        .cube {
            width: 30px; height: 30px; margin: 0 5px;
            background-color: rgba(239, 68, 68, 0.7);
            animation: cube-stretch 1.2s infinite ease-in-out;
        }
        .cube-2 { animation-delay: -1.1s; }
        .cube-3 { animation-delay: -1.0s; }
        .cube-4 { animation-delay: -0.9s; }
        @keyframes cube-stretch {
            0%, 40%, 100% { transform: scaleY(0.4); }
            20% { transform: scaleY(1.0); }
        }
        .preloader-text {
            /* --- PADDING ADJUSTMENT --- */
            margin-top: 2rem; /* Adjusted positioning */
            font-family: 'Courier New', monospace; font-size: 1.2rem;
            color: #ef4444; text-shadow: 0 0 8px rgba(239, 68, 68, 0.5);
        }
        /* --- END PRELOADER --- */

        .navbar { background: rgba(30, 41, 59, 0.7) !important; backdrop-filter: blur(10px); border-bottom: 1px solid rgba(148, 163, 184, 0.1); }
        .navbar-brand { color: #ef4444 !important; font-weight: 700; text-shadow: 0 0 10px rgba(239, 68, 68, 0.5); }
        .header-container { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
        .validation-status { padding: 0.5rem 1rem; border-radius: 8px; font-weight: 600; background: rgba(51, 65, 85, 0.8); color: #cbd5e1; }
        .validation-status.valid { background: rgba(22, 163, 74, 0.3); color: #4ade80; border: 1px solid #22c55e; }
        .validation-status.invalid { background: rgba(239, 68, 68, 0.3); color: #f87171; border: 1px solid #ef4444; }
        
        .blockchain-container { display: flex; overflow-x: auto; padding: 2rem 1rem; }
        .block-card { 
            flex: 0 0 380px; margin-right: 20px; 
            background: rgba(30, 41, 59, 0.9); backdrop-filter: blur(15px);
            border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            display: flex; flex-direction: column;
            opacity: 0; /* Initially hidden for animation */
            transform: translateY(20px);
            animation: fadeInBlock 0.8s ease-out forwards;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        .block-card:hover { transform: translateY(-10px); box-shadow: 0 12px 40px rgba(239, 68, 68, 0.2); }
        @keyframes fadeInBlock { to { opacity: 1; transform: translateY(0); } }
        
        .block-header { background: rgba(239, 68, 68, 0.1); border-bottom: 1px solid rgba(239, 68, 68, 0.2); padding: 0.75rem 1rem; font-weight: 700; border-radius: 15px 15px 0 0; display: flex; justify-content: space-between; align-items: center; }
        .block-header .index { font-size: 1.2rem; color: #f87171; }
        .block-header .timestamp { font-size: 0.8rem; color: #94a3b8; }
        .block-body { padding: 1rem; font-family: 'Courier New', monospace; font-size: 0.9rem; word-break: break-all; }
        .block-body strong { color: #e2e8f0; }
        .block-body .data { background: rgba(0,0,0,0.3); padding: 0.75rem; border-radius: 8px; margin: 0.75rem 0; color: #cbd5e1; }
        .hash { color: #f87171; text-shadow: 0 0 8px rgba(239, 68, 68, 0.5); font-size: 0.85rem; }
        .chain-link { 
            min-width: 50px; align-self: center; height: 5px; 
            animation: pulse-link 2s infinite ease-in-out;
            opacity: 0; /* Initially hidden for animation */
            animation: fadeInBlock 0.8s ease-out forwards;
        }
        @keyframes pulse-link {
            0%, 100% { background: linear-gradient(90deg, rgba(239, 68, 68, 0.4), rgba(239, 68, 68, 0)); }
            50% { background: linear-gradient(90deg, rgba(239, 68, 68, 0.8), rgba(239, 68, 68, 0)); }
        }
        .btn-danger { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); border: none; box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3); }
    </style>
</head>
<body>
    <div id="preloader">
        <div>
            <div class="cube-container">
                <div class="cube cube-1"></div>
                <div class="cube cube-2"></div>
                <div class="cube cube-3"></div>
                <div class="cube cube-4"></div>
            </div>
            <p class="preloader-text">Verifying Ledger Integrity...</p>
        </div>
    </div>

    <nav class="navbar navbar-dark">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1"><i class="fas fa-shield-alt me-2"></i>NexusGuard AI</span>
            <div>
                <a href="/dashboard" class="btn btn-outline-light me-2"><i class="fas fa-home me-1"></i>Dashboard</a><a href="/logs" class="btn btn-outline-light me-2"><i class="fas fa-file-alt me-1"></i>Logs</a>
                <a href="/blockchain_logs" class="btn btn-outline-light me-2 active"><i class="fas fa-link me-1"></i>Blockchain</a><a href="/agents" class="btn btn-outline-light me-2"><i class="fas fa-robot me-1"></i>Agents</a>
                <a href="/settings" class="btn btn-outline-light me-2"><i class="fas fa-cog me-1"></i>Settings</a><a href="/logout" class="btn btn-outline-danger"><i class="fas fa-sign-out-alt me-1"></i>Logout</a>
            </div>
        </div>
    </nav>
    <div class="container-fluid mt-4">
        <div class="header-container px-3">
            <div><h3 class="mb-0"><i class="fas fa-cubes me-2"></i>Blockchain Log Integrity</h3><p class="text-muted mb-0">Immutable ledger of all critical security events.</p></div>
            <div><span id="validation-status" class="validation-status me-3">Status: Unknown</span><button id="validate-chain-btn" class="btn btn-danger"><i class="fas fa-check-shield me-2"></i>Validate Chain</button></div>
        </div>
        <div class="blockchain-container">
            {% for block in chain %}
                <div class="block-card" style="animation-delay: {{ loop.index0 * 0.15 }}s;">
                    <div class="block-header"><span class="index">Block #{{ block.index }}</span><span class="timestamp">{{ block.timestamp }}</span></div>
                    <div class="block-body"><strong>Data:</strong><div class="data">{{ block.data }}</div><strong>Previous Hash:</strong><p class="hash">{{ block.previous_hash }}</p><strong>Block Hash:</strong><p class="hash">{{ block.hash }}</p></div>
                </div>
                {% if not loop.last %}<div class="chain-link" style="animation-delay: {{ loop.index0 * 0.15 + 0.1 }}s;"></div>{% endif %}
            {% endfor %}
        </div>
    </div>
    <script>
        window.addEventListener('load', function() {
            const preloader = document.getElementById('preloader');
            setTimeout(() => {
                preloader.classList.add('fade-out');
                preloader.addEventListener('transitionend', () => {
                    preloader.style.display = 'none';
                    document.body.style.overflow = 'auto'; // Restore scroll
                });
            }, 1500); // Preloader duration
        });

        document.getElementById('validate-chain-btn').addEventListener('click', function() {
            const statusEl = document.getElementById('validation-status');
            statusEl.textContent = 'Validating...'; statusEl.className = 'validation-status';
            fetch('/api/validate_chain').then(response => response.json()).then(data => {
                if (data.valid) { statusEl.textContent = 'Chain Integrity: VALID'; statusEl.classList.add('valid'); } 
                else { statusEl.textContent = 'Chain Integrity: COMPROMISED'; statusEl.classList.add('invalid'); }
            }).catch(err => { statusEl.textContent = 'Error during validation'; statusEl.classList.add('invalid'); });
        });
    </script>
</body>
</html>
"""
LOGS_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logs - NexusGuard AI</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" />
    <style>
        @keyframes gradientBG { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }
        body { 
            background: linear-gradient(-45deg, #0f0f23, #1a1a2e, #16213e, #0f0f23); 
            background-size: 400% 400%; animation: gradientBG 15s ease infinite; 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #e2e8f0;
            overflow: hidden;
        }

        /* --- LOGS PRE-LOADER (MATRIX STYLE) --- */
        #preloader {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: #0f0f23; z-index: 10000;
            display: flex; justify-content: center; align-items: center; text-align: center;
            opacity: 1; transition: opacity 1s ease-out;
            overflow: hidden;
        }
        #preloader.fade-out { opacity: 0; }
        #matrix-canvas { position: absolute; top: 0; left: 0; width: 100%; height: 100%; }
        .preloader-text {
            font-family: 'Courier New', monospace; font-size: 1.5rem;
            color: #ef4444; text-shadow: 0 0 10px rgba(239, 68, 68, 0.7);
            z-index: 1;
            animation: flicker 1.5s infinite alternate;
        }
        @keyframes flicker { 0%, 18%, 22%, 25%, 53%, 57%, 100% { text-shadow: 0 0 8px #ef4444, 0 0 15px #ef4444; color: #fff; } 20%, 24%, 55% { text-shadow: none; color: #ef4444; } }
        /* --- END PRE-LOADER --- */

        .navbar { background: rgba(30, 41, 59, 0.7) !important; backdrop-filter: blur(10px); border-bottom: 1px solid rgba(148, 163, 184, 0.1); }
        .navbar-brand { color: #ef4444 !important; font-weight: 700; text-shadow: 0 0 10px rgba(239, 68, 68, 0.5); }
        .card { background: rgba(30, 41, 59, 0.95); backdrop-filter: blur(20px); border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 15px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3); margin-bottom: 20px; opacity: 0; animation: fadeInUp 0.8s ease-out forwards; }
        .card-header { border-radius: 15px 15px 0 0 !important; border: none; font-weight: 600; background: rgba(51, 65, 85, 0.8) !important; color: #f1f5f9 !important; }
        .table { color: #e2e8f0; }
        .table th { background: transparent; border-bottom: 2px solid rgba(239, 68, 68, 0.3); color: #f1f5f9; font-weight: 600; }
        .table td { border-color: rgba(148, 163, 184, 0.1); vertical-align: middle; }
        .table-striped>tbody>tr:nth-of-type(odd)>* { background-color: rgba(239, 68, 68, 0.05); }
        
        /* --- CHANGE: Added hover effect for table rows for better interactivity --- */
        .table-hover>tbody>tr:hover>* {
            background-color: rgba(239, 68, 68, 0.15) !important;
            color: #f8f9fa;
        }

        .form-control { background: rgba(51, 65, 85, 0.8); border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 10px; color: #e2e8f0; }
        .form-control:focus { background: rgba(51, 65, 85, 0.9); border-color: #ef4444; box-shadow: 0 0 0 0.2rem rgba(239, 68, 68, 0.25); }
        .btn-primary { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); border: none; box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3); }
        @keyframes fadeInUp { from { opacity: 0; transform: translateY(30px); } to { opacity: 1; transform: translateY(0); } }
    </style>
</head>
<body>
    <div id="preloader">
        <canvas id="matrix-canvas"></canvas>
        <h3 class="preloader-text">Compiling Log Data...</h3>
    </div>

    <nav class="navbar navbar-dark">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1"><i class="fas fa-shield-alt me-2"></i>NexusGuard AI</span>
            <div>
                <a href="/dashboard" class="btn btn-outline-light me-2"><i class="fas fa-home me-1"></i>Dashboard</a>
                <a href="/logs" class="btn btn-outline-light me-2 active"><i class="fas fa-file-alt me-1"></i>Logs</a>
                <a href="/blockchain_logs" class="btn btn-outline-light me-2"><i class="fas fa-link me-1"></i>Blockchain</a>
                <a href="/agents" class="btn btn-outline-light me-2"><i class="fas fa-robot me-1"></i>Agents</a>
                <a href="/settings" class="btn btn-outline-light me-2"><i class="fas fa-cog me-1"></i>Settings</a>
                <a href="/logout" class="btn btn-outline-danger"><i class="fas fa-sign-out-alt me-1"></i>Logout</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="row">
            <div class="col-12">
                <div class="card" style="animation-delay: 0.2s;">
                    <div class="card-header"><h5><i class="fas fa-file-alt me-2"></i>Detailed Logs Viewer</h5></div>
                    <div class="card-body">
                        <div class="row mb-3 gx-2">
                            <div class="col-md-3"><input type="text" class="form-control" id="searchInput" placeholder="Search logs..."></div>
                            <div class="col-md-2">
                                <select class="form-control" id="logType">
                                    <option value="all">All Logs</option>
                                    <option value="Firewall">Firewall</option>
                                    <option value="Review">Review</option>
                                    <option value="Feedback">Feedback</option>
                                    <option value="Override">Override</option>
                                </select>
                            </div>
                            <div class="col-md-2"><input type="date" class="form-control" id="dateFilter"></div>
                            <div class="col-md-1"><button class="btn btn-outline-secondary w-100" onclick="clearFilters()" title="Clear Filters"><i class="fas fa-times"></i></button></div>
                            <div class="col-md-2"><button class="btn btn-primary w-100" onclick="exportLogs('csv')"><i class="fas fa-download me-1"></i>Export CSV</button></div>
                            <div class="col-md-2"><button class="btn btn-outline-light w-100" onclick="exportLogs('json')"><i class="fas fa-download me-1"></i>Export JSON</button></div>
                        </div>
                        <div class="table-responsive" style="max-height: 600px;">
                            <table class="table table-striped table-hover" id="logsTable">
                                <thead><tr><th>Timestamp</th><th>Type</th><th>Details</th></tr></thead>
                                <tbody>
                                    {% for log in logs %}
                                    <tr><td>{{ log.timestamp }}</td><td>{{ log.type }}</td><td>{{ log.details }}</td></tr>
                                    {% endfor %}
                                    <tr id="no-results-row" style="display: none;">
                                        <td colspan="3" class="text-center text-muted py-4">No logs found matching your criteria.</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // --- PRELOADER & MATRIX EFFECT (NO CHANGES) ---
        window.addEventListener('load', function() {
            const preloader = document.getElementById('preloader');
            setTimeout(() => {
                preloader.classList.add('fade-out');
                preloader.addEventListener('transitionend', () => {
                    preloader.style.display = 'none';
                    document.body.style.overflow = 'auto';
                });
            }, 1500);
        });
        
        const canvas = document.getElementById('matrix-canvas');
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        const alphabet = 'アァカサタナハマヤャラワガザダバパイィキシチニヒミリヰギジヂビピウゥクスツヌフムユュルグズブヅプエェケセテネヘメレヱゲゼデベペオォコソトノホモヨョロヲゴゾドボポヴッンABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        const fontSize = 16;
        const columns = canvas.width / fontSize;
        const rainDrops = [];
        for (let x = 0; x < columns; x++) { rainDrops[x] = 1; }
        function drawMatrix() {
            ctx.fillStyle = 'rgba(15, 15, 35, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = '#ef4444';
            ctx.font = fontSize + 'px monospace';
            for (let i = 0; i < rainDrops.length; i++) {
                const text = alphabet.charAt(Math.floor(Math.random() * alphabet.length));
                ctx.fillText(text, i * fontSize, rainDrops[i] * fontSize);
                if (rainDrops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    rainDrops[i] = 0;
                }
                rainDrops[i]++;
            }
        }
        setInterval(drawMatrix, 33);
        
        // --- FUNCTIONAL JAVASCRIPT ---

        /**
         * Filters the log table based on user input.
         */
        function filterLogs() {
            const searchText = document.getElementById('searchInput').value.toLowerCase();
            const logType = document.getElementById('logType').value;
            const dateFilter = document.getElementById('dateFilter').value;
            const table = document.getElementById('logsTable');
            const rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');
            const noResultsRow = document.getElementById('no-results-row');
            let visibleRows = 0;

            // Start loop from 0, but exclude the 'no-results-row' from filtering
            for (let i = 0; i < rows.length; i++) {
                if (rows[i].id === 'no-results-row') continue;

                const cells = rows[i].getElementsByTagName('td');
                if (cells.length > 2) {
                    const timestamp = cells[0].textContent;
                    const type = cells[1].textContent;
                    const details = cells[2].textContent.toLowerCase();

                    const textMatch = details.includes(searchText);
                    const typeMatch = (logType === 'all' || type === logType);
                    const dateMatch = (dateFilter === '' || timestamp.startsWith(dateFilter));

                    if (textMatch && typeMatch && dateMatch) {
                        rows[i].style.display = '';
                        visibleRows++;
                    } else {
                        rows[i].style.display = 'none';
                    }
                }
            }

            // --- CHANGE: Show or hide the "No results" message based on visible row count ---
            noResultsRow.style.display = visibleRows === 0 ? '' : 'none';
        }

        /**
         * Exports the currently visible logs to either CSV or JSON format.
         */
        function exportLogs(format) {
            const table = document.getElementById('logsTable');
            const rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');
            const headers = ['Timestamp', 'Type', 'Details'];
            const data = [];

            for (let i = 0; i < rows.length; i++) {
                if (rows[i].style.display !== 'none' && rows[i].id !== 'no-results-row') {
                    const cells = rows[i].getElementsByTagName('td');
                    if (cells.length > 2) {
                        data.push({
                            Timestamp: cells[0].textContent,
                            Type: cells[1].textContent,
                            Details: cells[2].textContent
                        });
                    }
                }
            }

            if (data.length === 0) {
                alert("No logs to export with the current filters.");
                return;
            }

            let fileContent, mimeType, fileName;
            if (format === 'csv') {
                let csvContent = headers.join(',') + '\\n';
                data.forEach(row => {
                    const values = headers.map(header => {
                        let cellData = String(row[header] || ''); // Ensure data is a string
                        if (cellData.includes(',') || cellData.includes('"')) {
                            cellData = `"${cellData.replace(/"/g, '""')}"`;
                        }
                        return cellData;
                    });
                    csvContent += values.join(',') + '\\n';
                });
                fileContent = csvContent;
                mimeType = 'text/csv;charset=utf-8;';
                fileName = 'nexusguard_logs.csv';
            } else {
                fileContent = JSON.stringify(data, null, 2);
                mimeType = 'application/json;charset=utf-8;';
                fileName = 'nexusguard_logs.json';
            }

            const blob = new Blob([fileContent], { type: mimeType });
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.setAttribute('download', fileName);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        // --- CHANGE: Added a new function to clear all active filters ---
        /**
         * Resets all filter inputs to their default state and re-runs the filter.
         */
        function clearFilters() {
            document.getElementById('searchInput').value = '';
            document.getElementById('logType').value = 'all';
            document.getElementById('dateFilter').value = '';
            filterLogs(); // Update the table view
        }

        // Attach event listeners
        document.getElementById('searchInput').addEventListener('keyup', filterLogs);
        document.getElementById('logType').addEventListener('change', filterLogs);
        document.getElementById('dateFilter').addEventListener('change', filterLogs);
        
        // --- CHANGE: Initial call to filterLogs to handle the "No results" row on page load if logs are empty ---
        document.addEventListener('DOMContentLoaded', filterLogs);

    </script>
</body>
</html>
"""

# Login Template with animated gradient background and modern styling
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Login - NexusGuard AI</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" />
    <style>
        @keyframes gradientBG {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        body {
            height: 100vh;
            margin: 0;
            background: linear-gradient(-45deg, #0f0f23, #1a1a2e, #16213e, #0f0f23);
            background-size: 400% 400%;
            animation: gradientBG 15s ease infinite;
            display: flex;
            justify-content: center;
            align-items: center;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            color: #e2e8f0;
            overflow: hidden; /* Prevent scrollbars during animation */
        }
        
        /* --- PRE-LOADER STYLES (RED THEME & GLOWS) --- */
        #preloader {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: #0f0f23;
            z-index: 10000;
            display: flex;
            justify-content: center;
            align-items: center;
            text-align: center;
            color: #ef4444; /* Bright Red */
            font-family: 'Courier New', Courier, monospace;
        }
        #preloader.fade-out {
            animation: fadeOutPreloader 1s ease-out forwards;
        }
        .preloader-icon {
            font-size: 5rem;
            margin-bottom: 2rem;
            display: block;
            animation: icon-pulse 2s infinite ease-in-out;
            color: #dc2626; /* Slightly darker red for base icon */
            text-shadow: 0 0 10px rgba(220, 38, 38, 0.7); /* Red initial shadow */
        }
        .preloader-text {
            font-size: 1.2rem;
            letter-spacing: 2px;
            opacity: 0;
            transition: opacity 0.8s ease-in-out;
            margin: 10px 0;
            color: #ef4444; /* Bright red text */
            text-shadow: 0 0 8px rgba(239, 68, 68, 0.5); /* Red text shadow */
        }
        @keyframes icon-pulse {
            0%, 100% { 
                transform: scale(1); 
                text-shadow: 0 0 15px rgba(239, 68, 68, 0.7), 0 0 25px rgba(239, 68, 68, 0.3); /* Multiple shadow layers */
            }
            50% { 
                transform: scale(1.1); 
                text-shadow: 0 0 25px rgba(239, 68, 68, 1), 0 0 40px rgba(239, 68, 68, 0.6);
            }
        }
        @keyframes fadeOutPreloader {
            to { opacity: 0; }
        }

        /* --- LOGIN CARD STYLES (RED THEME) --- */
        .login-card {
            background: rgba(30, 41, 59, 0.95);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(148, 163, 184, 0.1);
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            padding: 2rem;
            width: 100%;
            max-width: 400px;
            color: #e2e8f0;
        }
        .login-card.hidden {
            opacity: 0;
            visibility: hidden;
        }
        .login-card.visible {
            opacity: 1;
            visibility: visible;
            animation: fadeInUp 0.8s ease-out forwards;
        }
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .login-card h4 {
            margin-bottom: 1.5rem;
            font-weight: 700;
            text-align: center;
            color: #ef4444; /* Bright Red */
            text-shadow: 0 0 10px rgba(239, 68, 68, 0.5); /* Red glow for title */
        }
        .form-label {
            color: #cbd5e1;
            font-weight: 500;
        }
        .form-control {
            background: rgba(51, 65, 85, 0.8);
            border: 1px solid rgba(148, 163, 184, 0.2);
            border-radius: 10px;
            color: #e2e8f0;
        }
        .form-control:focus {
            background: rgba(51, 65, 85, 0.9);
            border-color: #ef4444; /* Red border on focus */
            box-shadow: 0 0 0 0.2rem rgba(239, 68, 68, 0.25); /* Red shadow on focus */
        }
        .btn-primary {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); /* Red gradient button */
            border: none;
            border-radius: 10px;
            font-weight: 600;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3); /* Red button shadow */
        }
        .btn-primary:hover {
            background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%); /* Darker red on hover */
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(239, 68, 68, 0.4); /* Enhanced red button shadow */
        }
        .alert {
            background: rgba(239, 68, 68, 0.8);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #fef2f2;
            text-align: center;
            border-radius: 10px;
            margin-top: 1rem;
            box-shadow: 0 0 10px rgba(239, 68, 68, 0.3); /* Red alert shadow */
        }
    </style>
</head>
<body>
    
    <div id="preloader">
        <div>
            <i class="fas fa-shield-alt preloader-icon"></i>
            <p class="preloader-text" id="preloader-text-1">Initializing Security Protocols...</p>
            <p class="preloader-text" id="preloader-text-2">Loading Agent Framework...</p>
            <p class="preloader-text" id="preloader-text-3">Welcome to NexusGuard AI</p>
        </div>
    </div>

    <div class="login-card hidden">
        <h4>NexusGuard AI Login</h4>
        <form method="post">
            <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" required />
            </div>
            <button type="submit" class="btn btn-primary w-100">Login</button>
        </form>
        {% if error %}
        <div class="alert">{{ error }}</div>
        {% endif %}
    </div>

    <script>
        window.addEventListener('load', function() {
            const preloader = document.getElementById('preloader');
            const loginCard = document.querySelector('.login-card');

            setTimeout(() => document.getElementById('preloader-text-1').style.opacity = 1, 500);
            setTimeout(() => document.getElementById('preloader-text-2').style.opacity = 1, 1500);
            setTimeout(() => document.getElementById('preloader-text-3').style.opacity = 1, 2500);

            setTimeout(function() {
                preloader.classList.add('fade-out');
                
                preloader.addEventListener('animationend', function() {
                    preloader.style.display = 'none';
                    loginCard.classList.remove('hidden');
                    loginCard.classList.add('visible');
                }, { once: true });
            }, 4000);
        });
    </script>
</body>
</html>
"""
# Updated Agents Template with Animations
# Updated Agents Template with Loader Animation
AGENTS_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Agents - NexusGuard AI</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" />
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        @keyframes gradientBG { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }
        body { 
            background: linear-gradient(-45deg, #0f0f23, #1a1a2e, #16213e, #0f0f23); 
            background-size: 400% 400%; animation: gradientBG 15s ease infinite; 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #e2e8f0;
            overflow: hidden;
        }
        
        /* --- CYBERSECURITY SHIELD PRELOADER --- */
        #preloader {
            position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
            background: linear-gradient(135deg, #0f0f23 60%, #1a1a2e 100%);
            z-index: 10000;
            display: flex; flex-direction: column; justify-content: center; align-items: center;
            opacity: 1; transition: opacity 1s ease-out;
        }
        #preloader.fade-out { opacity: 0; }
        .shield-glow {
            display: flex; justify-content: center; align-items: center;
            margin-bottom: 2rem;
        }
        .shield-icon {
            font-size: 6rem;
            color: #ef4444;
            filter: drop-shadow(0 0 30px #ef4444cc) drop-shadow(0 0 60px #0f0f23);
            animation: shield-pulse 1.5s infinite alternate;
        }
        @keyframes shield-pulse {
            0% { text-shadow: 0 0 20px #ef4444, 0 0 40px #ef4444; }
            100% { text-shadow: 0 0 40px #ef4444, 0 0 80px #ef4444; }
        }
        .cyber-loader {
            display: flex; gap: 0.5rem; margin-bottom: 1.5rem;
        }
        .cyber-dot {
            width: 16px; height: 16px; border-radius: 50%;
            background: #ef4444;
            box-shadow: 0 0 10px #ef4444, 0 0 30px #ef4444aa;
            opacity: 0.7;
            animation: cyber-dot-blink 1.2s infinite alternate;
        }
        .cyber-dot:nth-child(2) { animation-delay: 0.3s; }
        .cyber-dot:nth-child(3) { animation-delay: 0.6s; }
        @keyframes cyber-dot-blink {
            0% { opacity: 0.7; }
            100% { opacity: 1; box-shadow: 0 0 20px #ef4444, 0 0 40px #ef4444; }
        }
        .preloader-text {
            font-family: 'Share Tech Mono', 'Courier New', monospace;
            font-size: 1.3rem;
            color: #ef4444;
            letter-spacing: 2px;
            text-shadow: 0 0 10px #ef4444, 0 0 30px #ef4444aa;
            margin-top: 0.5rem;
            text-align: center;
            animation: cyber-text-flicker 2s infinite alternate;
        }
        @keyframes cyber-text-flicker {
            0%, 100% { opacity: 1; }
            45% { opacity: 0.7; }
            50% { opacity: 0.4; }
            55% { opacity: 0.7; }
        }
        
        /* --- INVESTIGATION LOADER (ROBOT) --- */
        #loader-overlay {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background-color: rgba(15, 15, 35, 0.85); backdrop-filter: blur(8px);
            z-index: 9999; display: none; justify-content: center;
            align-items: center; flex-direction: column;
        }
        #loader-overlay .fa-robot {
            font-size: 5rem; color: #ef4444; margin-bottom: 25px;
            animation: robot-pulse-red 2s ease-in-out infinite;
        }
        @keyframes robot-pulse-red {
            0%, 100% { transform: scale(1); text-shadow: 0 0 10px rgba(239, 68, 68, 0.7); }
            50% { transform: scale(1.1); text-shadow: 0 0 30px rgba(239, 68, 68, 1); }
        }
        #loader-overlay p { font-weight: 500; font-size: 1.2rem; color: #e2e8f0; }

        .navbar { background: rgba(30, 41, 59, 0.7) !important; backdrop-filter: blur(10px); border-bottom: 1px solid rgba(148, 163, 184, 0.1); }
        .navbar-brand { color: #ef4444 !important; font-weight: 700; text-shadow: 0 0 10px rgba(239, 68, 68, 0.5); }
        .card { background: rgba(30, 41, 59, 0.95); backdrop-filter: blur(20px); border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 15px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3); margin-bottom: 20px; transition: transform 0.3s ease, box-shadow 0.3s ease; }
        .card:hover { transform: translateY(-5px); box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4); }
        .card-header { border-radius: 15px 15px 0 0 !important; border: none; font-weight: 600; background: rgba(51, 65, 85, 0.8) !important; color: #f1f5f9 !important; }
        
        /* --- FIX: TEXT VISIBILITY --- */
        .card-body p {
            color: #cbd5e1; /* Brighter text for paragraphs */
            margin-bottom: 0.75rem;
        }
        .card-body p i {
            color: #94a3b8; /* Give icons a distinct, lighter color */
            width: 20px; /* Align icons nicely */
        }
        #agentMetrics p span {
            color: #f1f5f9; /* Make metric numbers stand out */
            font-weight: 600;
        }
        /* --- END OF FIX --- */

        .btn-primary { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); border: none; border-radius: 10px; box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3); transition: all 0.3s ease; }
        .btn-primary:hover { transform: scale(1.05); }
        .terminal { background: rgba(0, 0, 0, 0.8); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 10px; padding: 1rem; font-family: 'Courier New', monospace; color: #ff5555; max-height: 300px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; box-shadow: 0 0 15px rgba(239, 68, 68, 0.2); }
        .table { color: #e2e8f0; }
        .table td { border-color: rgba(148, 163, 184, 0.1); }
        .animate-card { opacity: 0; animation: fadeInUp 0.6s ease-out forwards; }
        @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        .delay-1 { animation-delay: 0.1s; }
        .delay-2 { animation-delay: 0.2s; }
        .delay-3 { animation-delay: 0.3s; }
        .delay-4 { animation-delay: 0.4s; }
        .delay-5 { animation-delay: 0.5s; }
    </style>
</head>
<body>

    <div id="preloader">
        <div class="shield-glow">
            <i class="fas fa-shield-alt shield-icon"></i>
        </div>
        <div class="cyber-loader">
            <div class="cyber-dot"></div>
            <div class="cyber-dot"></div>
            <div class="cyber-dot"></div>
        </div>
        <div class="preloader-text" id="preloader-text">Initializing Cyber Defense...</div>
    </div>

    <div id="loader-overlay"><i class="fas fa-robot"></i><p>Agents are investigating...</p></div>

    <nav class="navbar navbar-dark">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1"><i class="fas fa-shield-alt me-2"></i>NexusGuard AI</span>
            <div>
                <a href="/dashboard" class="btn btn-outline-light me-2"><i class="fas fa-home me-1"></i>Dashboard</a>
                <a href="/logs" class="btn btn-outline-light me-2"><i class="fas fa-file-alt me-1"></i>Logs</a>
                <a href="/blockchain_logs" class="btn btn-outline-light me-2"><i class="fas fa-link me-1"></i>Blockchain</a>
                <a href="/agents" class="btn btn-outline-light me-2 active"><i class="fas fa-robot me-1"></i>Agents</a>
                <a href="/settings" class="btn btn-outline-light me-2"><i class="fas fa-cog me-1"></i>Settings</a>
                <a href="/logout" class="btn btn-outline-danger"><i class="fas fa-sign-out-alt me-1"></i>Logout</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="row">
             <div class="col-md-4">
                <div class="card animate-card delay-1">
                    <div class="card-header"><h5><i class="fas fa-robot me-2"></i>Agent Statuses</h5></div>
                    <div class="card-body">
                        <p><i class="fas fa-circle text-success me-2"></i>Anomaly Agent: <span class="badge bg-success">Available</span></p>
                        <p><i class="fas fa-circle text-success me-2"></i>Coordinator Agent: <span class="badge bg-success">Available</span></p>
                        <p><i class="fas fa-circle text-success me-2"></i>Signature Agent: <span class="badge bg-success">Running (Proactive)</span></p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card animate-card delay-2">
                    <div class="card-header"><h5><i class="fas fa-chart-bar me-2"></i>Agent Metrics</h5></div>
                    <div class="card-body" id="agentMetrics">
                        <p><i class="fas fa-search me-2"></i>Investigations: <span id="investigations_count">...</span></p>
                        <p><i class="fas fa-shield-alt me-2"></i>Blocks Issued: <span id="blocks_count">...</span></p>
                        <p><i class="fas fa-clock me-2"></i>Avg Response Time: <span id="avg_response_time">...</span>s</p>
                        <p><i class="fas fa-check-circle me-2"></i>Success Rate: <span id="success_rate">...</span>%</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card animate-card delay-3">
                    <div class="card-header"><h5><i class="fas fa-search me-2"></i>Manual IP Investigation</h5></div>
                    <div class="card-body">
                        <form id="investigation-form" method="post">
                            <div class="mb-3">
                                <label for="ip" class="form-label">IP Address</label>
                                <input type="text" class="form-control" id="ip" name="ip" placeholder="e.g., 192.168.1.1" required>
                            </div>
                            <button type="submit" class="btn btn-primary"><i class="fas fa-play me-2"></i>Investigate</button>
                        </form>
                        {% if error %}
                        <div class="alert alert-danger mt-3">{{ error }}</div>
                        {% endif %}
                    </div>
                </div>
            </div>
        </div>

        {% if report %}
        <div class="row mt-4">
            <div class="col-12">
                <div class="card animate-card delay-4">
                    <div class="card-header"><h5><i class="fas fa-file-alt me-2"></i>Investigation Report for IP: {{ ip }}</h5></div>
                    <div class="card-body">
                        <div class="terminal">{{ report }}</div>
                    </div>
                </div>
            </div>
        </div>
        {% endif %}

        {% if coordinator %}
        <div class="row mt-4">
            <div class="col-12">
                <div class="card animate-card delay-5">
                    <div class="card-header"><h5><i class="fas fa-gavel me-2"></i>Coordinator Decision</h5></div>
                    <div class="card-body">
                        <div class="terminal">{{ coordinator }}</div>
                    </div>
                </div>
            </div>
        </div>
        {% endif %}

        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card animate-card delay-4">
                    <div class="card-header">
                        <h5 class="card-title"><i class="fas fa-chart-line me-2"></i>Agent Activity Chart</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="agentActivityChart"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card animate-card delay-5">
                    <div class="card-header">
                        <h5 class="card-title"><i class="fas fa-history me-2"></i>Recent Agent Activities</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive" style="max-height: 330px; overflow-y: auto;">
                            <table class="table table-sm table-borderless">
                                <tbody>
                                    {% for activity in recent_activities %}
                                    <tr>
                                        <td><small class="text-muted">{{ activity.timestamp }}</small></td>
                                        <td>{{ activity.details }}</td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        window.addEventListener('load', function() {
            const preloader = document.getElementById('preloader');
            const textEl = document.getElementById('preloader-text');
            setTimeout(() => { textEl.textContent = "Deploying AI Agents..."; }, 1200);
            setTimeout(() => { textEl.textContent = "Activating Threat Intelligence..."; }, 2200);
            setTimeout(() => {
                preloader.classList.add('fade-out');
                preloader.addEventListener('transitionend', () => {
                    preloader.style.display = 'none';
                    document.body.style.overflow = 'auto';
                });
            }, 3400);
        });

        function updateMetrics() {
            fetch('/api/metrics')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('investigations_count').textContent = data.investigations_count;
                    document.getElementById('blocks_count').textContent = data.blocks_count;
                    document.getElementById('avg_response_time').textContent = data.avg_response_time;
                    document.getElementById('success_rate').textContent = data.success_rate;
                })
                .catch(error => console.error('Error fetching metrics:', error));
        }

        document.addEventListener('DOMContentLoaded', function() {
            updateMetrics();
            setInterval(updateMetrics, 5000);

            const investigationForm = document.getElementById('investigation-form');
            if (investigationForm) {
                investigationForm.addEventListener('submit', function() {
                    const ipInput = document.getElementById('ip');
                    if (ipInput && ipInput.value.trim() !== '') {
                        document.getElementById('loader-overlay').style.display = 'flex';
                    }
                });
            }
        });
        
        const ctx = document.getElementById('agentActivityChart').getContext('2d');
        const agentActivityChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['January', 'February', 'March', 'April', 'May', 'June', 'July'],
                datasets: [{
                    label: 'Investigations', data: [65, 59, 80, 81, 56, 55, 40],
                    borderColor: '#f87171', backgroundColor: 'rgba(239, 68, 68, 0.2)',
                    fill: true, tension: 0.4
                }, {
                    label: 'Blocks', data: [28, 48, 40, 19, 86, 27, 90],
                    borderColor: '#9ca3af', backgroundColor: 'rgba(156, 163, 175, 0.2)',
                    fill: true, tension: 0.4
                }]
            },
            options: { 
                responsive: true, 
                scales: { 
                    y: { beginAtZero: true, grid: { color: 'rgba(226, 232, 240, 0.1)' }, ticks: { color: '#cbd5e1' } },
                    x: { grid: { color: 'rgba(226, 232, 240, 0.1)' }, ticks: { color: '#cbd5e1' } }
                },
                plugins: { legend: { labels: { color: '#e2e8f0' } } }
            }
        });
    </script>
</body>
</html>
"""
# Preloader Template after login
PRELOADER_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Loading Dashboard - NexusGuard AI</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" />
    <style>
        @keyframes gradientBG {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        body {
            height: 100vh;
            margin: 0;
            background: linear-gradient(-45deg, #0f0f23, #1a1a2e, #16213e, #0f0f23);
            background-size: 400% 400%;
            animation: gradientBG 15s ease infinite;
            display: flex;
            justify-content: center;
            align-items: center;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            color: #e2e8f0;
            overflow: hidden;
        }
        #preloader {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: #0f0f23;
            z-index: 10000;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            text-align: center;
            opacity: 1;
            transition: opacity 1s ease-out;
        }
        #preloader.fade-out {
            opacity: 0;
        }
        .shield-icon {
            font-size: 5rem;
            color: #ef4444;
            animation: shield-pulse 2s infinite ease-in-out;
            margin-bottom: 2rem;
        }
        @keyframes shield-pulse {
            0%, 100% {
                transform: scale(1);
                text-shadow: 0 0 20px rgba(239, 68, 68, 0.7);
            }
            50% {
                transform: scale(1.1);
                text-shadow: 0 0 40px rgba(239, 68, 68, 1);
            }
        }
        .preloader-text {
            font-size: 1.5rem;
            color: #ef4444;
            text-shadow: 0 0 10px rgba(239, 68, 68, 0.5);
            margin-bottom: 1rem;
        }
        .progress-bar {
            width: 300px;
            height: 10px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 5px;
            overflow: hidden;
            margin-top: 1rem;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #ef4444, #dc2626);
            width: 0%;
            animation: fill-progress 3s ease-out forwards;
        }
        @keyframes fill-progress {
            to { width: 100%; }
        }
    </style>
</head>
<body>
    <div id="preloader">
        <i class="fas fa-shield-alt shield-icon"></i>
        <p class="preloader-text">Initializing Dashboard...</p>
        <div class="progress-bar">
            <div class="progress-fill"></div>
        </div>
    </div>

    <script>
        window.addEventListener('load', function() {
            setTimeout(function() {
                window.location.href = '/dashboard';
            }, 3000); // Redirect after 3 seconds
        });
    </script>
</body>
</html>
"""

# Enhanced HTML Template with animated background, modern colors, and interactive elements
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CN-Agentic-IDS Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" />
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
    /* --- Core Theme & Animations --- */
    @keyframes gradientBG {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }
    @keyframes fadeInUp {
        from { opacity: 0; transform: translateY(30px); }
        to { opacity: 1; transform: translateY(0); }
    }
    @keyframes fadeInLeft {
        from { opacity: 0; transform: translateX(-30px); }
        to { opacity: 1; transform: translateX(0); }
    }
    @keyframes fadeInRight {
        from { opacity: 0; transform: translateX(30px); }
        to { opacity: 1; transform: translateX(0); }
    }
    @keyframes pulse-red {
        0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }
        70% { box-shadow: 0 0 0 12px rgba(239, 68, 68, 0); }
        100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
    }

    body {
        background: linear-gradient(-45deg, #0f0f23, #1a1a2e, #16213e, #0f0f23);
        background-size: 400% 400%;
        animation: gradientBG 15s ease infinite;
        min-height: 100vh;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        color: #e2e8f0;
    }

    /* --- Custom Scrollbar (Red Theme) --- */
    ::-webkit-scrollbar { width: 8px; }
    ::-webkit-scrollbar-track { background: #1e293b; }
    ::-webkit-scrollbar-thumb { background: #555; border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: #ef4444; }

    /* --- Animations --- */
    .animate-fade-in-up { animation: fadeInUp 0.8s ease-out forwards; opacity: 0; }
    .animate-fade-in-left { animation: fadeInLeft 0.8s ease-out forwards; opacity: 0; }
    .animate-fade-in-right { animation: fadeInRight 0.8s ease-out forwards; opacity: 0; }
    .delay-1 { animation-delay: 0.1s; }
    .delay-2 { animation-delay: 0.2s; }
    .delay-3 { animation-delay: 0.3s; }
    .delay-4 { animation-delay: 0.4s; }
    .delay-5 { animation-delay: 0.5s; }

    /* --- NexusGuard AI Navbar (Red Theme) --- */
    .navbar {
        background: rgba(15, 15, 35, 0.7) !important;
        backdrop-filter: blur(12px);
        border-bottom: 1px solid rgba(239, 68, 68, 0.2);
        padding: 0.75rem 1.5rem;
    }
    .navbar-brand {
        color: #ef4444 !important;
        font-weight: 700;
        text-shadow: 0 0 10px rgba(239, 68, 68, 0.6);
    }
    .nav-button {
        background-color: transparent;
        border: 1px solid rgba(239, 68, 68, 0.3);
        color: #f87171;
        padding: 0.5rem 1rem;
        margin: 0 0.25rem;
        border-radius: 8px;
        transition: all 0.3s ease;
        text-decoration: none;
        display: inline-block;
    }
    .nav-button:hover {
        background-color: rgba(239, 68, 68, 0.2);
        color: #fff;
        transform: translateY(-2px);
        text-shadow: 0 0 5px rgba(255, 255, 255, 0.5);
    }
    .nav-button.active {
        background-color: #ef4444;
        border-color: #ef4444;
        color: #fff;
        font-weight: 500;
        box-shadow: 0 0 15px rgba(239, 68, 68, 0.5);
    }

    #live-clock {
        color: #94a3b8;
        font-family: 'Courier New', Courier, monospace;
        font-size: 1rem;
        margin-right: 1rem;
        background: rgba(0,0,0,0.2);
        padding: 0.5rem 1rem;
        border-radius: 8px;
        border: 1px solid rgba(148, 163, 184, 0.1);
    }
    

    /* --- Enhanced Card Styling (Red Theme) --- */
    .card {
        background: rgba(30, 41, 59, 0.9);
        backdrop-filter: blur(20px);
        border: 1px solid rgba(148, 163, 184, 0.1);
        border-radius: 15px;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        transition: all 0.3s ease;
        margin-bottom: 20px;
    }
    .card:hover {
        transform: translateY(-5px);
        box-shadow: 0 12px 40px rgba(0, 0, 0, 0.5);
        border-color: rgba(239, 68, 68, 0.3);
    }
    .card-header {
        border-radius: 15px 15px 0 0 !important;
        border-bottom: 1px solid rgba(239, 68, 68, 0.2) !important;
        font-weight: 600;
        background: rgba(51, 65, 85, 0.8) !important;
        color: #f1f5f9 !important;
        padding: 1rem 1.25rem;
    }
    .card-body { color: #cbd5e1; }

    /* --- Table Styling --- */
    .table { color: #e2e8f0; }
    .table th, .table td { border-bottom: 1px solid rgba(148, 163, 184, 0.1); padding: 0.9rem; }
    .table th { font-weight: 600; color: #f1f5f9; }
    .table-responsive { max-height: 400px; overflow-y: auto; }

    /* --- Enhanced Stats Card (Red Theme) --- */
    .stats-card-body .stat-item span {
        font-weight: 700;
        color: #f87171; /* Highlight numbers in red */
    }

    /* --- Buttons and Badges (Red Theme) --- */
    .btn-primary {
        background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
        border: none;
        border-radius: 10px;
        color: white;
        transition: all 0.3s ease;
        box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
    }
    .btn-primary:hover {
        background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(239, 68, 68, 0.4);
    }
    .badge { font-size: 0.8em; padding: 0.5em 0.75em; }

    /* --- Header Gradients and Colors --- */
    .card-header.bg-danger { animation: pulse-red 2s infinite; background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%) !important; }
    .card-header.bg-warning { background: linear-gradient(135deg, #d97706 0%, #b45309 100%) !important; color: #fff !important; }
    .card-header.bg-info { background: linear-gradient(135deg, #0891b2 0%, #0e7490 100%) !important; }
    .card-header.bg-success { background: linear-gradient(135deg, #059669 0%, #047857 100%) !important; }
    .card-header.bg-secondary { background: linear-gradient(135deg, #4b5563 0%, #374151 100%) !important; }
    .text-white { color: #f1f5f9 !important; }
    .text-dark { color: #1e293b !important; }
</style>
</head>
<body>

    <nav class="navbar navbar-dark">
    <div class="container-fluid">
        <span class="navbar-brand mb-0 h1">
            <i class="fas fa-shield-virus me-2"></i>NexusGuard AI
        </span>
        <div class="d-flex align-items-center">
            <span id="live-clock"></span>
            <a href="/dashboard" class="nav-button active"><i class="fas fa-home me-1"></i>Dashboard</a>
            <a href="/logs" class="nav-button"><i class="fas fa-file-alt me-1"></i>Logs</a>
            <a href="/blockchain_logs" class="nav-button"><i class="fas fa-link me-1"></i>Blockchain</a>
            <a href="/agents" class="nav-button"><i class="fas fa-robot me-1"></i>Agents</a>
            <a href="/settings" class="nav-button"><i class="fas fa-cog me-1"></i>Settings</a>
            <a href="/logout" class="nav-button"><i class="fas fa-sign-out-alt me-1"></i>Logout</a>
        </div>
    </div>
</nav>
    <div class="container mt-4">
        <div class="row">
            <div class="col-lg-7">
                <div class="card animate-fade-in-left delay-1">
                    <div class="card-header bg-danger text-white">
                        <h5><i class="fas fa-ban me-2"></i>Firewall Rules (Blocked IPs)</h5>
                    </div>
                    <div class="card-body table-responsive">
                        <table class="table">
                            <thead>
                                <tr><th>Timestamp</th><th>IP</th><th>Reason</th><th>Override</th></tr>
                            </thead>
                            <tbody>
                                {% for entry in firewall_entries %}
                                <tr>
                                    <td>{{ entry.timestamp }}</td>
                                    <td>{{ entry.ip }}</td>
                                    <td>{{ entry.reason }}</td>
                                    <td><button class="btn btn-sm btn-success btn-override" onclick="overrideAction('{{ entry.ip }}', 'unblock')"><i class="fas fa-unlock"></i> Unblock</button></td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            <div class="col-lg-5">
                 <div class="card animate-fade-in-right delay-2">
                    <div class="card-header bg-info text-white">
                        <h5><i class="fas fa-chart-bar me-2"></i>System Stats</h5>
                    </div>
                    <div class="card-body stats-card-body">
                        <div class="stat-item">
                            <i class="fas fa-fire"></i>
                            <div class="stat-info">
                                Total Firewall Rules
                                <span>{{ firewall_count }}</span>
                            </div>
                        </div>
                        <div class="stat-item">
                            <i class="fas fa-list"></i>
                            <div class="stat-info">
                                Review Queue Items
                                <span>{{ review_count }}</span>
                            </div>
                        </div>
                        <div class="stat-item">
                            <i class="fas fa-comments"></i>
                             <div class="stat-info">
                                Feedback Submitted
                                <span>{{ feedback_count }}</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
             <div class="col-lg-7">
                <div class="card animate-fade-in-left delay-3">
                    <div class="card-header bg-warning text-dark">
                        <h5><i class="fas fa-eye me-2"></i>Review Queue (Low/Medium Risk)</h5>
                    </div>
                    <div class="card-body table-responsive">
                        <table class="table">
                            <thead>
                                <tr><th>Timestamp</th><th>Level</th><th>IP</th><th>Summary</th><th>Action</th></tr>
                            </thead>
                            <tbody>
                                {% for entry in review_entries %}
                                <tr>
                                    <td>{{ entry.timestamp }}</td>
                                    <td><span class="badge bg-{{ 'warning' if entry.level == 'Medium' else 'info' }}">{{ entry.level }}</span></td>
                                    <td>{{ entry.ip }}</td>
                                    <td>{{ entry.summary }}</td>
                                    <td><button class="btn btn-sm btn-danger btn-override" onclick="overrideAction('{{ entry.ip }}', 'block')"><i class="fas fa-lock"></i> Block</button></td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            <div class="col-lg-5">
                <div class="card animate-fade-in-right delay-4">
                    <div class="card-header bg-success text-white">
                        <h5><i class="fas fa-comment-dots me-2"></i>Provide Feedback</h5>
                    </div>
                    <div class="card-body">
                        <form method="post" action="/submit_feedback">
                            <div class="mb-3">
                                <label for="ip" class="form-label">IP Address</label>
                                <input type="text" class="form-control" id="ip" name="ip" placeholder="e.g., 192.168.1.1" required>
                            </div>
                            <div class="mb-3">
                                <label for="feedback" class="form-label">Feedback</label>
                                <textarea class="form-control" id="feedback" name="feedback" rows="3" required></textarea>
                            </div>
                            <button type="submit" class="btn btn-primary w-100"><i class="fas fa-paper-plane me-2"></i>Submit Feedback</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-12">
                <div class="card animate-fade-in-up delay-5">
                    <div class="card-header bg-secondary text-white">
                        <h5><i class="fas fa-chart-line me-2"></i>Recent Activity Chart</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="activityChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    

    <script>
        function showPopup(title, text, icon) {
            Swal.fire({
                title: title, text: text, icon: icon, timer: 2000,
                timerProgressBar: true, showConfirmButton: false,
                position: 'top-end', toast: true
            });
        }

        document.addEventListener('DOMContentLoaded', function() {
            {% if login_success %}
            showPopup('Welcome!', 'Login successful!', 'success');
            {% endif %}
            {% if feedback_success %}
            showPopup('Thank you!', 'Feedback submitted successfully!', 'success');
            {% endif %}
        });

        function overrideAction(ip, action) {
            Swal.fire({
                title: `Are you sure?`, text: `Do you want to ${action} IP ${ip}?`,
                icon: 'warning', showCancelButton: true,
                confirmButtonText: `Yes, ${action} it!`, cancelButtonText: 'Cancel'
            }).then((result) => {
                if (result.isConfirmed) {
                    fetch('/override', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ ip: ip, action: action })
                    }).then(response => response.json()).then(data => {
                        showPopup('Success', data.message, 'success');
                        setTimeout(() => location.reload(), 2100);
                    });
                }
            });
        }

        // Enhanced chart with dark theme styles
        const ctx = document.getElementById('activityChart').getContext('2d');
        const activityChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
                datasets: [{
                    label: 'Incidents Detected',
                    data: [12, 19, 3, 5, 2, 3],
                    borderColor: '#60a5fa',
                    backgroundColor: 'rgba(96, 165, 250, 0.15)',
                    tension: 0.4,
                    fill: true,
                    pointBackgroundColor: '#60a5fa',
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2,
                    pointRadius: 6,
                    pointHoverRadius: 8
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 2000, easing: 'easeInOutQuart' },
                plugins: {
                    title: {
                        display: true, text: 'Monthly Incident Trends',
                        font: { size: 16, weight: 'bold' }, color: '#e2e8f0'
                    },
                    legend: {
                        labels: { usePointStyle: true, color: '#e2e8f0' }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(226, 232, 240, 0.1)' },
                        ticks: { color: '#cbd5e1' }
                    },
                    x: {
                        grid: { color: 'rgba(226, 232, 240, 0.1)' },
                        ticks: { color: '#cbd5e1' }
                    }
                }
            }
        });

        function updateDashboard() {
            fetch('/api/dashboard_data')
                .then(response => response.json())
                .then(data => {
                    // This function would update the DOM.
                    // For brevity, the full DOM update logic is in your original file.
                    console.log("Dashboard data updated:", data);
                })
                .catch(error => console.error('Error updating dashboard:', error));
        }
        
        // Polling is disabled in this static example, but the function is here.
        // setInterval(updateDashboard, 10000);
        </script>
        <script>
    // Live Clock Functionality
    function updateClock() {
        const clockElement = document.getElementById('live-clock');
        if (clockElement) {
            const now = new Date();
            const options = {
                timeZone: 'Asia/Kolkata',
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: true
            };
            clockElement.textContent = now.toLocaleString('en-IN', options);
        }
    }

    // Update the clock every second
    document.addEventListener('DOMContentLoaded', function() {
        updateClock(); // Initial call
        setInterval(updateClock, 1000);
    });
</script>
</body>
</html>
"""

def convert_to_ist(timestamp_str):
    try:
        dt = datetime.fromisoformat(timestamp_str)
        ist = pytz.timezone('Asia/Kolkata')
        dt_ist = dt.astimezone(ist)
        return dt_ist.strftime('%Y-%m-%d %H:%M:%S IST')
    except Exception:
        return timestamp_str  # Return original if conversion fails

def parse_log_file(filepath):
    entries = []
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            for line in f:
                parts = line.strip().split(' - ')
                if len(parts) >= 4:
                    timestamp = convert_to_ist(parts[0])
                    action = parts[1].strip('[]')
                    details = ' - '.join(parts[2:])
                    if 'BLOCK IP:' in details:
                        ip = details.split('BLOCK IP:')[1].split(' - ')[0].strip()
                        reason = details.split(' - REASON:')[1] if ' - REASON:' in details else ''
                        entries.append({'timestamp': timestamp, 'action': action, 'ip': ip, 'reason': reason})
                    elif 'REVIEW' in action:
                        level = parts[2].split(' - ')[0]
                        ip = parts[3].split(' - ')[0]
                        summary = ' - '.join(parts[4:])
                        entries.append({'timestamp': timestamp, 'level': level, 'ip': ip, 'summary': summary})
    return entries

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == 'admin123': # Simple password for demo
            session['logged_in'] = True
            session['login_success'] = True
            # <--- FIX: Redirect to the new preloader route instead of the dashboard directly --->
            return redirect(url_for('preloader'))
        else:
            return render_template_string(LOGIN_TEMPLATE, error='Invalid password')
    return render_template_string(LOGIN_TEMPLATE)

# <--- FIX: New route for the preloader page --->
@app.route('/preloader')
def preloader():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template_string(PRELOADER_TEMPLATE)

# <--- FIX: Renamed route from '/' to '/dashboard' for clarity --->
@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    firewall_entries = parse_log_file(FIREWALL_LOG)
    review_entries = parse_log_file(REVIEW_LOG)
    firewall_count = len(firewall_entries)
    review_count = len(review_entries)
    feedback_count = sum(1 for line in open(FEEDBACK_LOG) if line.strip()) if os.path.exists(FEEDBACK_LOG) else 0
    login_success = session.pop('login_success', False)
    feedback_success = session.pop('feedback_success', False)
    
    return render_template_string(HTML_TEMPLATE, 
                                  firewall_entries=firewall_entries, 
                                  review_entries=review_entries, 
                                  firewall_count=firewall_count, 
                                  review_count=review_count, 
                                  feedback_count=feedback_count, 
                                  login_success=login_success, 
                                  feedback_success=feedback_success)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/override', methods=['POST'])
def override():
    data = request.get_json()
    ip = data.get('ip')
    action = data.get('action')
    
    # Simulate override action (e.g., log it or call a tool)
    log_message = f"{datetime.now().isoformat()} - [OVERRIDE] - {action.upper()} IP: {ip}"
    with open('override_actions.log', 'a') as f:
        f.write(log_message + '\n')
    
    # <--- FIX: Moved unreachable code before the return statement --->
    add_log_to_blockchain(f"Manual Override: User performed '{action.upper()}' on IP {ip}.")
    return jsonify({'message': f'Override action {action} for IP {ip} logged.'})


@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    ip = request.form.get('ip')
    feedback = request.form.get('feedback')
    log_message = f"{datetime.now().isoformat()} - FEEDBACK - IP: {ip} - {feedback}"
    with open(FEEDBACK_LOG, 'a') as f:
        f.write(log_message + '\n')
    session['feedback_success'] = True
    # <--- FIX: Updated to redirect to the renamed 'dashboard' route --->
    return redirect(url_for('dashboard'))



@app.route('/logs')
def logs():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    logs = []
    for filepath, log_type in [(FIREWALL_LOG, 'Firewall'), (REVIEW_LOG, 'Review'), (FEEDBACK_LOG, 'Feedback'), ('override_actions.log', 'Override')]:
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                for line in f:
                    parts = line.strip().split(' - ')
                    if len(parts) >= 2:
                        timestamp = convert_to_ist(parts[0])
                        details = ' - '.join(parts[1:])
                        logs.append({'timestamp': timestamp, 'type': log_type, 'details': details})
    logs.sort(key=lambda x: x['timestamp'], reverse=True)
    return render_template_string(LOGS_TEMPLATE, logs=logs)

@app.route('/api/dashboard_data')
def dashboard_data():
    firewall_entries = parse_log_file(FIREWALL_LOG)
    review_entries = parse_log_file(REVIEW_LOG)
    firewall_count = len(firewall_entries)
    review_count = len(review_entries)
    feedback_count = sum(1 for line in open(FEEDBACK_LOG) if line.strip()) if os.path.exists(FEEDBACK_LOG) else 0
    return {
        'firewall_entries': firewall_entries,
        'review_entries': review_entries,
        'firewall_count': firewall_count,
        'review_count': review_count,
        'feedback_count': feedback_count
    }

@app.route('/api/agents_data')
def agents_data():
    # Agent statuses (static for now)
    agent_statuses = {
        'Anomaly Agent': 'Available',
        'Coordinator Agent': 'Available',
        'Signature Agent': 'Running (Proactive)'
    }

    # Recent activities (parse logs for agent mentions)
    recent_activities = []
    for filepath in [FIREWALL_LOG, REVIEW_LOG]:
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                for line in f:
                    if 'Agent' in line or 'investigation' in line.lower():
                        parts = line.strip().split(' - ')
                        if len(parts) >= 2:
                            timestamp = convert_to_ist(parts[0])
                            details = ' - '.join(parts[1:])
                            recent_activities.append({'timestamp': timestamp, 'details': details})
    recent_activities.sort(key=lambda x: x['timestamp'], reverse=True)
    recent_activities = recent_activities[:10]  # Last 10

    # Metrics
    investigations_count = len(recent_activities)  # Approximate
    blocks_count = len(parse_log_file(FIREWALL_LOG))
    avg_response_time = "N/A"  # No timing data available
    success_rate = "N/A"  # No success/failure data available

    return {
        'agent_statuses': agent_statuses,
        'recent_activities': recent_activities,
        'investigations_count': investigations_count,
        'blocks_count': blocks_count,
        'avg_response_time': avg_response_time,
        'success_rate': success_rate
    }

@app.route('/api/metrics')
def api_metrics():
    # Calculate metrics from logs
    investigations_count = 0
    total_duration = 0
    success_count = 0
    if os.path.exists("investigation_times.log"):
        with open("investigation_times.log", "r") as f:
            for line in f:
                investigations_count += 1
                parts = line.split(" - ")
                try:
                    duration_str = parts[3].split(": ")[1]
                    total_duration += float(duration_str)
                    if "Success" in parts[2]:
                        success_count += 1
                except (IndexError, ValueError):
                    continue
    blocks_count = 0
    if os.path.exists(FIREWALL_LOG):
        with open(FIREWALL_LOG, 'r') as f:
            blocks_count = len(f.readlines())
    avg_response_time = round(total_duration / investigations_count, 2) if investigations_count > 0 else 0
    success_rate = round((success_count / investigations_count) * 100, 2) if investigations_count > 0 else 0
    return json.dumps({
        'investigations_count': investigations_count,
        'blocks_count': blocks_count,
        'avg_response_time': avg_response_time,
        'success_rate': success_rate
    })


import time
import re
@app.route('/agents', methods=['GET', 'POST'])
def agents():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    report = None
    coordinator = None
    ip = None
    error = None

    if request.method == 'POST':
        ip = request.form.get('ip')
        if ip:
            
            start_time = time.time()
            try:
                # This is a manual investigation, we can still trigger the agents
                report_dict = anomaly_agent_executor.invoke({"input": ip})
                investigation_report = report_dict['output']
                report = investigation_report

                # Pass to coordinator
                coordinator_result = coordinator_agent_executor.invoke({"input": investigation_report})
                coordinator = coordinator_result['output']
                duration = time.time() - start_time
                log_message = f"{datetime.now().isoformat()} - IP: {ip} - Status: Success - Duration: {duration:.2f}\n"
                with open(INVESTIGATION_LOG, "a") as f:
                    f.write(log_message)
                add_log_to_blockchain(f"Agent Action: Investigation for {ip} completed. Decision: {coordinator}")
            except Exception as e:
                error = str(e)
                duration = time.time() - start_time
                log_message = f"{datetime.now().isoformat()} - IP: {ip} - Status: Failure - Duration: {duration:.2f}\n"
                with open(INVESTIGATION_LOG, "a") as f:
                    f.write(log_message)
        else:
            error = "Please provide an IP address."

    # Recent activities (parse logs for agent mentions)
    recent_activities = []
    # Regex to find a timestamp like "2025-10-01 15:17:58 IST" at the end of a line
    timestamp_regex = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} IST)$')

    log_files_to_check = [FIREWALL_LOG, REVIEW_LOG, INVESTIGATION_LOG]
    for filepath in log_files_to_check:
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    timestamp = None
                    details = ""
                    
                    # Try to find a timestamp at the end of the line
                    match = timestamp_regex.search(line)
                    if match:
                        # If found, this is the format: "DETAILS... TIMESTAMP"
                        timestamp = match.group(1)
                        details = line[:match.start()].strip()
                    else:
                        # Fallback for correctly formatted logs: "TIMESTAMP - DETAILS..."
                        parts = line.split(' - ')
                        if len(parts) >= 2:
                            # Simple check to see if the first part is a timestamp
                            if parts[0].startswith('202'): 
                                timestamp = convert_to_ist(parts[0])
                                details = ' - '.join(parts[1:])

                    # Add the parsed activity to the list if it's valid
                    if timestamp and details:
                        recent_activities.append({'timestamp': timestamp, 'details': details})

    # Sort activities by timestamp and get the latest 10
    recent_activities.sort(key=lambda x: x['timestamp'], reverse=True)
    recent_activities = recent_activities[:10]
    # --- END OF FIX ---

    return render_template_string(AGENTS_TEMPLATE, report=report, coordinator=coordinator, ip=ip, error=error, recent_activities=recent_activities)
@app.route('/blockchain_logs')
def blockchain_logs():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    chain_data = get_blockchain_logs()
    
    # --- FIX: Add a check to prevent TypeError ---
    for block in chain_data:
        # Check if the timestamp is a number (float or int) before converting
        if isinstance(block['timestamp'], (int, float)):
            block['timestamp'] = datetime.fromtimestamp(block['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
    # --- END OF FIX ---
        
    return render_template_string(BLOCKCHAIN_TEMPLATE, chain=chain_data)

@app.route('/api/validate_chain')
def validate_chain_api():
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    is_valid = log_blockchain.is_chain_valid()
    return jsonify({'valid': is_valid})
    

@app.route('/settings')
def settings():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings - CN-Agentic-IDS Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" />
    <style>
        body {
            background: linear-gradient(-45deg, #0f0f23, #1a1a2e, #16213e, #0f0f23);
            background-size: 400% 400%;
            animation: gradientBG 15s ease infinite;
            min-height: 100vh;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            color: #e2e8f0;
        }
        @keyframes gradientBG {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        .navbar-brand { color: #60a5fa !important; font-weight: 700; }
        .card {
            background: rgba(30, 41, 59, 0.95);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(148, 163, 184, 0.1);
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            margin-bottom: 20px;
        }
        .card-header {
            border-radius: 15px 15px 0 0 !important;
            border: none;
            font-weight: 600;
            background: rgba(51, 65, 85, 0.8) !important;
            color: #f1f5f9 !important;
        }
        .card-body { color: #cbd5e1; }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1">
                <i class="fas fa-shield-alt me-2"></i>CN-Agentic-IDS Dashboard
            </span>
            <div>
                <a href="/dashboard" class="btn btn-outline-light me-2"><i class="fas fa-home me-1"></i>Dashboard</a>
                <a href="/logs" class="btn btn-outline-light me-2"><i class="fas fa-file-alt me-1"></i>Logs</a>
                <a href="/blockchain_logs" class="btn btn-outline-light me-2"><i class="fas fa-link me-1"></i>Blockchain</a>
                <a href="/agents" class="btn btn-outline-light me-2"><i class="fas fa-robot me-1"></i>Agents</a>
                <a href="/settings" class="btn btn-outline-light me-2"><i class="fas fa-cog me-1"></i>Settings</a>
                <a href="/logout" class="btn btn-outline-danger"><i class="fas fa-sign-out-alt me-1"></i>Logout</a>
            </div>
        </div>
    </nav>
    <div class="container mt-4">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-cog me-2"></i>Settings</h5>
            </div>
            <div class="card-body">
                <p>Settings functionality coming soon.</p>
            </div>
        </div>
    </div>
</body>
</html>
""")

if __name__ == '__main__':
    app.run(debug=True)

