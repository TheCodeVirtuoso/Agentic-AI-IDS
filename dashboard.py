from flask import Flask, render_template_string, request, redirect, url_for, session
import os
import json
from datetime import datetime
import pytz
from agents import anomaly_agent_executor, coordinator_agent_executor

app = Flask(__name__)
app.secret_key = 'cn-agentic-ids-secret-key'  # For session management

# Paths to log files
FIREWALL_LOG = 'firewall_rules.log'
REVIEW_LOG = 'review_queue.log'
FEEDBACK_LOG = 'feedback.log'
INVESTIGATION_LOG = 'investigation_times.log'
# Logs Template
LOGS_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logs - CN-Agentic-IDS Dashboard</title>
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
        .table { color: #e2e8f0; }
        .table th {
            background: rgba(51, 65, 85, 0.8);
            border-color: rgba(148, 163, 184, 0.2);
            color: #f1f5f9;
            font-weight: 600;
        }
        .table td { border-color: rgba(148, 163, 184, 0.1); vertical-align: middle; }
        .table-responsive { max-height: 600px; overflow-y: auto; }
        .form-control {
            background: rgba(51, 65, 85, 0.8);
            border: 1px solid rgba(148, 163, 184, 0.2);
            border-radius: 10px;
            color: #e2e8f0;
        }
        .form-control:focus {
            background: rgba(51, 65, 85, 0.9);
            border-color: #60a5fa;
            color: #f1f5f9;
            box-shadow: 0 0 0 0.2rem rgba(96, 165, 250, 0.25);
        }
        .btn-primary {
            background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
            border: none;
            border-radius: 10px;
            color: white;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
        }
        .btn-primary:hover {
            background: linear-gradient(135deg, #2563eb 0%, #1e40af 100%);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(59, 130, 246, 0.4);
        }
        .btn-outline-light {
            border-color: rgba(148, 163, 184, 0.3);
            color: #cbd5e1;
        }
        .btn-outline-light:hover {
            background: rgba(148, 163, 184, 0.1);
            border-color: #60a5fa;
            color: #60a5fa;
        }
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
        <div class="row">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fas fa-file-alt me-2"></i>Detailed Logs Viewer</h5>
                    </div>
                    <div class="card-body">
                        <div class="row mb-3">
                            <div class="col-md-3">
                                <input type="text" class="form-control" id="searchInput" placeholder="Search logs...">
                            </div>
                            <div class="col-md-2">
                                <select class="form-control" id="logType">
                                    <option value="all">All Logs</option>
                                    <option value="firewall">Firewall</option>
                                    <option value="review">Review</option>
                                    <option value="feedback">Feedback</option>
                                    <option value="override">Override</option>
                                </select>
                            </div>
                            <div class="col-md-2">
                                <input type="date" class="form-control" id="dateFilter">
                            </div>
                            <div class="col-md-2">
                                <button class="btn btn-primary w-100" onclick="exportLogs('csv')"><i class="fas fa-download me-1"></i>Export CSV</button>
                            </div>
                            <div class="col-md-2">
                                <button class="btn btn-outline-light w-100" onclick="exportLogs('json')"><i class="fas fa-download me-1"></i>Export JSON</button>
                            </div>
                        </div>
                        <div class="table-responsive">
                            <table class="table table-striped" id="logsTable">
                                <thead>
                                    <tr><th>Timestamp</th><th>Type</th><th>Details</th></tr>
                                </thead>
                                <tbody>
                                    {% for log in logs %}
                                    <tr>
                                        <td>{{ log.timestamp }}</td>
                                        <td>{{ log.type }}</td>
                                        <td>{{ log.details }}</td>
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
        function filterLogs() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const logType = document.getElementById('logType').value;
            const dateFilter = document.getElementById('dateFilter').value;
            const rows = document.querySelectorAll('#logsTable tbody tr');

            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                const type = row.cells[1].textContent.toLowerCase();
                const timestamp = row.cells[0].textContent.split(' ')[0]; // Date part

                let show = true;
                if (searchTerm && !text.includes(searchTerm)) show = false;
                if (logType !== 'all' && !type.includes(logType)) show = false;
                if (dateFilter && !timestamp.includes(dateFilter)) show = false;

                row.style.display = show ? '' : 'none';
            });
        }

        document.getElementById('searchInput').addEventListener('input', filterLogs);
        document.getElementById('logType').addEventListener('change', filterLogs);
        document.getElementById('dateFilter').addEventListener('change', filterLogs);

        function exportLogs(format) {
            const rows = Array.from(document.querySelectorAll('#logsTable tbody tr')).filter(row => row.style.display !== 'none');
            let data = rows.map(row => ({
                timestamp: row.cells[0].textContent,
                type: row.cells[1].textContent,
                details: row.cells[2].textContent
            }));

            if (format === 'csv') {
                let csv = 'Timestamp,Type,Details\\n';
                data.forEach(row => {
                    csv += `"${row.timestamp}","${row.type}","${row.details}"\\n`;
                });
                const blob = new Blob([csv], { type: 'text/csv' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'logs.csv';
                a.click();
            } else if (format === 'json') {
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'logs.json';
                a.click();
            }
        }
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
    <title>Login - CN-Agentic-IDS Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" />
    <style>
        /* Dark theme animated gradient background */
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
        }
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
        .login-card h4 {
            margin-bottom: 1.5rem;
            font-weight: 700;
            text-align: center;
            color: #60a5fa;
            text-shadow: 0 0 10px rgba(96, 165, 250, 0.5);
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
            box-shadow: inset 0 0 5px rgba(0,0,0,0.2);
            transition: border-color 0.3s ease, box-shadow 0.3s ease;
        }
        .form-control:focus {
            background: rgba(51, 65, 85, 0.9);
            border-color: #60a5fa;
            color: #f1f5f9;
            outline: none;
            box-shadow: 0 0 0 0.2rem rgba(96, 165, 250, 0.25);
        }
        .form-control::placeholder {
            color: #94a3b8;
        }
        .btn-primary {
            background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
            border: none;
            border-radius: 10px;
            font-weight: 600;
            color: white;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
        }
        .btn-primary:hover {
            background: linear-gradient(135deg, #2563eb 0%, #1e40af 100%);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(59, 130, 246, 0.4);
        }
        .alert {
            background: rgba(239, 68, 68, 0.8);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #fef2f2;
            font-weight: 600;
            text-align: center;
            border-radius: 10px;
            margin-top: 1rem;
            box-shadow: 0 0 10px rgba(239, 68, 68, 0.3);
        }
    </style>
</head>
<body>
    <div class="login-card">
        <h4>CN-Agentic-IDS Login</h4>
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
    <title>Agents - CN-Agentic-IDS Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" />
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .animate-card {
            opacity: 0;
            animation: fadeInUp 0.6s ease-out forwards;
        }
        .delay-1 { animation-delay: 0.1s; }
        .delay-2 { animation-delay: 0.2s; }
        .delay-3 { animation-delay: 0.3s; }
        .delay-4 { animation-delay: 0.4s; }
        .delay-5 { animation-delay: 0.5s; }

        /* --- NEW ANIMATED ROBOT LOADER STYLES --- */
        #loader-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(15, 15, 35, 0.85);
            backdrop-filter: blur(8px);
            z-index: 9999;
            display: none; /* Hidden by default */
            justify-content: center;
            align-items: center;
            flex-direction: column;
        }
        #loader-overlay .fa-robot {
            font-size: 5rem; /* Large robot icon */
            color: #60a5fa;
            margin-bottom: 25px;
            animation: robot-pulse 2s ease-in-out infinite;
        }
        @keyframes robot-pulse {
            0% {
                transform: scale(1);
                text-shadow: 0 0 5px rgba(96, 165, 250, 0.5);
            }
            50% {
                transform: scale(1.1);
                text-shadow: 0 0 25px rgba(96, 165, 250, 1);
            }
            100% {
                transform: scale(1);
                text-shadow: 0 0 5px rgba(96, 165, 250, 0.5);
            }
        }
        #loader-overlay p {
            font-weight: 500;
            font-size: 1.2rem;
            letter-spacing: 0.5px;
            color: #e2e8f0;
        }
        /* --- END LOADER STYLES --- */

        .navbar-brand { color: #60a5fa !important; font-weight: 700; }
        .card {
            background: rgba(30, 41, 59, 0.95);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(148, 163, 184, 0.1);
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            margin-bottom: 20px;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4);
        }
        .card-header {
            border-radius: 15px 15px 0 0 !important;
            border: none;
            font-weight: 600;
            background: rgba(51, 65, 85, 0.8) !important;
            color: #f1f5f9 !important;
        }
        .card-body { color: #cbd5e1; }
        .form-control {
            background: rgba(51, 65, 85, 0.8);
            border: 1px solid rgba(148, 163, 184, 0.2);
            border-radius: 10px;
            color: #e2e8f0;
        }
        .btn-primary {
            background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
            border: none;
            border-radius: 10px;
            transition: all 0.3s ease;
        }
        .btn-primary:hover { transform: scale(1.05); }
        .terminal {
            background: rgba(0, 0, 0, 0.8);
            border: 1px solid rgba(0, 255, 0, 0.3);
            border-radius: 10px; padding: 1rem;
            font-family: 'Courier New', monospace;
            color: #00ff00;
            max-height: 300px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
            box-shadow: 0 0 15px rgba(0, 255, 0, 0.2);
        }
        .table { color: #e2e8f0; }
        .table td { border-color: rgba(148, 163, 184, 0.1); }
    </style>
</head>
<body>

    <div id="loader-overlay">
        <i class="fas fa-robot"></i>
        <p>Agents are investigating...</p>
    </div>

    <nav class="navbar navbar-dark bg-dark">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1"><i class="fas fa-shield-alt me-2"></i>CN-Agentic-IDS Dashboard</span>
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

        const ctx = document.getElementById('agentActivityChart').getContext('2d');
        const agentActivityChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['January', 'February', 'March', 'April', 'May', 'June', 'July'],
                datasets: [{
                    label: 'Investigations', data: [65, 59, 80, 81, 56, 55, 40],
                    borderColor: 'rgb(75, 192, 192)', backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    fill: true, tension: 0.4
                }, {
                    label: 'Blocks', data: [28, 48, 40, 19, 86, 27, 90],
                    borderColor: 'rgb(255, 99, 132)', backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    fill: true, tension: 0.4
                }]
            },
            options: { responsive: true, scales: { y: { beginAtZero: true } } }
        });
        
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
        /* Dark theme with animated gradient background */
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
        @keyframes scaleIn {
            from { opacity: 0; transform: scale(0.9); }
            to { opacity: 1; transform: scale(1); }
        }
        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }
            70% { box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); }
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
        
        /* --- Custom Scrollbar --- */
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #1e293b; }
        ::-webkit-scrollbar-thumb { background: #4a5568; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #60a5fa; }

        /* --- Animations --- */
        .animate-fade-in-up { animation: fadeInUp 0.8s ease-out forwards; opacity: 0; }
        .animate-fade-in-left { animation: fadeInLeft 0.8s ease-out forwards; opacity: 0; }
        .animate-fade-in-right { animation: fadeInRight 0.8s ease-out forwards; opacity: 0; }
        .animate-scale-in { animation: scaleIn 0.6s ease-out forwards; opacity: 0; }
        .delay-1 { animation-delay: 0.1s; }
        .delay-2 { animation-delay: 0.2s; }
        .delay-3 { animation-delay: 0.3s; }
        .delay-4 { animation-delay: 0.4s; }
        .delay-5 { animation-delay: 0.5s; }

        /* --- Glassmorphism Navbar --- */
        .navbar {
            background: rgba(30, 41, 59, 0.7) !important;
            backdrop-filter: blur(10px);
            border-bottom: 1px solid rgba(148, 163, 184, 0.1);
        }
        .navbar-brand {
            color: #60a5fa !important;
            font-weight: 700;
            text-shadow: 0 0 10px rgba(96, 165, 250, 0.5);
        }

        /* --- Enhanced Card Styling --- */
        .card {
            background: rgba(30, 41, 59, 0.9);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(148, 163, 184, 0.1);
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            transition: transform 0.3s ease, box-shadow 0.3s ease, border-color 0.3s ease;
            margin-bottom: 20px;
        }
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.5);
            border-color: rgba(96, 165, 250, 0.3);
        }
        .card-header {
            border-radius: 15px 15px 0 0 !important;
            border: none;
            font-weight: 600;
            background: rgba(51, 65, 85, 0.8) !important;
            color: #f1f5f9 !important;
            padding: 1rem 1.25rem;
        }
        .card-body { color: #cbd5e1; }
        
        /* --- Table Styling --- */
        .table { color: #e2e8f0; border-collapse: separate; border-spacing: 0; }
        .table th, .table td {
            border: none;
            border-bottom: 1px solid rgba(148, 163, 184, 0.1);
            padding: 0.9rem;
        }
        .table th {
            background: transparent;
            color: #f1f5f9;
            font-weight: 600;
        }
        .table-responsive { max-height: 400px; overflow-y: auto; }
        
        /* --- Enhanced Stats Card --- */
        .stats-card-body .stat-item {
            display: flex;
            align-items: center;
            margin: 1rem 0;
            padding: 0.5rem;
            border-radius: 10px;
            background: rgba(0,0,0,0.1);
        }
        .stats-card-body .stat-item i {
            font-size: 1.75rem;
            margin-right: 15px;
            width: 40px;
            text-align: center;
            color: #94a3b8;
        }
        .stats-card-body .stat-item .stat-info {
            flex-grow: 1;
        }
        .stats-card-body .stat-item .stat-info span {
            display: block;
            font-size: 1.5rem;
            font-weight: 700;
            color: #60a5fa;
        }
        
        /* --- Buttons and Badges --- */
        .btn-override {
            margin: 2px;
            transition: all 0.3s ease;
            border: none;
            text-shadow: 0 0 8px rgba(0,0,0,0.5);
        }
        .btn-override:hover {
            transform: scale(1.05);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
        }
        .btn-primary {
            background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
            border: none; border-radius: 10px; color: white;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
        }
        .btn-primary:hover {
            background: linear-gradient(135deg, #2563eb 0%, #1e40af 100%);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(59, 130, 246, 0.4);
        }
        .badge { font-size: 0.8em; padding: 0.5em 0.75em; }

        /* --- Header Gradients and Colors --- */
        .card-header.bg-danger { animation: pulse 2s infinite; background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%) !important; }
        .card-header.bg-warning { background: linear-gradient(135deg, #d97706 0%, #b45309 100%) !important; }
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
                <i class="fas fa-shield-alt me-2"></i>CN-Agentic-IDS
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
        if password == 'admin123':  # Simple password for demo
            session['logged_in'] = True
            session['login_success'] = True
            return redirect(url_for('index'))
        else:
            return render_template_string(LOGIN_TEMPLATE, error='Invalid password')
    # Ensure login page renders correctly on GET
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/dashboard')
def index():
    # Redirect to login page if not logged in
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    firewall_entries = parse_log_file(FIREWALL_LOG)
    review_entries = parse_log_file(REVIEW_LOG)
    firewall_count = len(firewall_entries)
    review_count = len(review_entries)
    feedback_count = sum(1 for line in open(FEEDBACK_LOG) if line.strip()) if os.path.exists(FEEDBACK_LOG) else 0
    login_success = session.pop('login_success', False)
    feedback_success = session.pop('feedback_success', False)
    return render_template_string(HTML_TEMPLATE, firewall_entries=firewall_entries, review_entries=review_entries, firewall_count=firewall_count, review_count=review_count, feedback_count=feedback_count, login_success=login_success, feedback_success=feedback_success)

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
    return {'message': f'Override action {action} for IP {ip} logged.'}

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    ip = request.form.get('ip')
    feedback = request.form.get('feedback')
    log_message = f"{datetime.now().isoformat()} - FEEDBACK - IP: {ip} - {feedback}"
    with open(FEEDBACK_LOG, 'a') as f:
        f.write(log_message + '\n')
    session['feedback_success'] = True
    return redirect(url_for('index'))

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

@app.route('/blockchain_logs')
def blockchain_logs():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blockchain Logs - CN-Agentic-IDS Dashboard</title>
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
                <a href="/" class="btn btn-outline-light me-2"><i class="fas fa-home me-1"></i>Dashboard</a>
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
                <h5><i class="fas fa-link me-2"></i>Blockchain Logs</h5>
            </div>
            <div class="card-body">
                <p>Blockchain logs functionality coming soon.</p>
            </div>
        </div>
    </div>
</body>
</html>
""")
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

