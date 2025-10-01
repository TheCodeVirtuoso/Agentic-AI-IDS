from flask import Flask, render_template_string, request, redirect, url_for, session
import os
import json
from datetime import datetime
import pytz

app = Flask(__name__)
app.secret_key = 'cn-agentic-ids-secret-key'  # For session management

# Paths to log files
FIREWALL_LOG = 'firewall_rules.log'
REVIEW_LOG = 'review_queue.log'
FEEDBACK_LOG = 'feedback.log'

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
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        @keyframes fadeInLeft {
            from {
                opacity: 0;
                transform: translateX(-30px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }
        @keyframes fadeInRight {
            from {
                opacity: 0;
                transform: translateX(30px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }
        @keyframes scaleIn {
            from {
                opacity: 0;
                transform: scale(0.9);
            }
            to {
                opacity: 1;
                transform: scale(1);
            }
        }
        @keyframes glow {
            0%, 100% {
                box-shadow: 0 0 20px rgba(96, 165, 250, 0.3);
            }
            50% {
                box-shadow: 0 0 30px rgba(96, 165, 250, 0.6);
            }
        }
        body {
            background: linear-gradient(-45deg, #0f0f23, #1a1a2e, #16213e, #0f0f23);
            background-size: 400% 400%;
            animation: gradientBG 15s ease infinite;
            min-height: 100vh;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            color: #e2e8f0;
        }
        .navbar {
            animation: fadeInDown 1s ease-out;
        }
        .animate-fade-in-up {
            animation: fadeInUp 0.8s ease-out forwards;
            opacity: 0;
        }
        .animate-fade-in-left {
            animation: fadeInLeft 0.8s ease-out forwards;
            opacity: 0;
        }
        .animate-fade-in-right {
            animation: fadeInRight 0.8s ease-out forwards;
            opacity: 0;
        }
        .animate-scale-in {
            animation: scaleIn 0.6s ease-out forwards;
            opacity: 0;
        }
        .animate-glow {
            animation: glow 2s ease-in-out infinite;
        }
        .delay-1 { animation-delay: 0.1s; }
        .delay-2 { animation-delay: 0.2s; }
        .delay-3 { animation-delay: 0.3s; }
        .delay-4 { animation-delay: 0.4s; }
        .delay-5 { animation-delay: 0.5s; }
        .delay-6 { animation-delay: 0.6s; }
        .navbar-brand {
            color: #60a5fa !important;
            font-weight: 700;
        }
        .card {
            background: rgba(30, 41, 59, 0.95);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(148, 163, 184, 0.1);
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            transition: transform 0.3s ease, box-shadow 0.3s ease, border-color 0.3s ease;
            margin-bottom: 20px;
        }
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4);
            border-color: rgba(96, 165, 250, 0.3);
        }
        .card-header {
            border-radius: 15px 15px 0 0 !important;
            border: none;
            font-weight: 600;
            background: rgba(51, 65, 85, 0.8) !important;
            color: #f1f5f9 !important;
        }
        .card-body {
            color: #cbd5e1;
        }
        .table {
            color: #e2e8f0;
        }
        .table th {
            background: rgba(51, 65, 85, 0.8);
            border-color: rgba(148, 163, 184, 0.2);
            color: #f1f5f9;
            font-weight: 600;
        }
        .table td {
            border-color: rgba(148, 163, 184, 0.1);
            vertical-align: middle;
        }
        .table-responsive {
            max-height: 400px;
            overflow-y: auto;
        }
        .btn-override {
            margin: 2px;
            transition: all 0.3s ease;
            border: none;
        }
        .btn-override:hover {
            transform: scale(1.05);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
        }
        .badge {
            font-size: 0.8em;
            padding: 0.5em 0.75em;
        }
        .stats-card {
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            border: 1px solid rgba(96, 165, 250, 0.2);
        }
        .stats-card .card-body p {
            margin: 0.5rem 0;
            font-weight: 500;
            color: #e2e8f0;
        }
        .chart-container {
            background: rgba(30, 41, 59, 0.9);
            border: 1px solid rgba(148, 163, 184, 0.1);
            border-radius: 15px;
            padding: 1rem;
        }
        .form-control {
            background: rgba(51, 65, 85, 0.8);
            border: 1px solid rgba(148, 163, 184, 0.2);
            border-radius: 10px;
            color: #e2e8f0;
            transition: border-color 0.3s ease, box-shadow 0.3s ease;
        }
        .form-control:focus {
            background: rgba(51, 65, 85, 0.9);
            border-color: #60a5fa;
            color: #f1f5f9;
            box-shadow: 0 0 0 0.2rem rgba(96, 165, 250, 0.25);
        }
        .form-control::placeholder {
            color: #94a3b8;
        }
        .form-label {
            color: #cbd5e1;
            font-weight: 500;
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
            transition: all 0.3s ease;
        }
        .btn-outline-light:hover {
            background: rgba(148, 163, 184, 0.1);
            border-color: #60a5fa;
            color: #60a5fa;
        }
        /* Pulse animation for alerts */
        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }
            70% { box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); }
            100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
        }
        .card-header.bg-danger {
            animation: pulse 2s infinite;
            background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%) !important;
        }
        .card-header.bg-warning {
            background: linear-gradient(135deg, #d97706 0%, #b45309 100%) !important;
        }
        .card-header.bg-info {
            background: linear-gradient(135deg, #0891b2 0%, #0e7490 100%) !important;
        }
        .card-header.bg-success {
            background: linear-gradient(135deg, #059669 0%, #047857 100%) !important;
        }
        .card-header.bg-secondary {
            background: linear-gradient(135deg, #4b5563 0%, #374151 100%) !important;
        }
        .text-white {
            color: #f1f5f9 !important;
        }
        .text-dark {
            color: #1e293b !important;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1">
                <i class="fas fa-shield-alt me-2"></i>CN-Agentic-IDS Dashboard
            </span>
            <button class="btn btn-outline-light" onclick="location.reload()">
                <i class="fas fa-sync-alt me-1"></i>Refresh
            </button>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="row">
            <div class="col-md-6">
                <div class="card animate-fade-in-left delay-1">
                    <div class="card-header bg-danger text-white">
                        <h5><i class="fas fa-ban me-2"></i>Firewall Rules (Blocked IPs)</h5>
                    </div>
                    <div class="card-body table-responsive">
                        <table class="table table-striped">
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
            <div class="col-md-6">
                <div class="card animate-fade-in-right delay-2">
                    <div class="card-header bg-warning text-dark">
                        <h5><i class="fas fa-eye me-2"></i>Review Queue (Low/Medium Risk)</h5>
                    </div>
                    <div class="card-body table-responsive">
                        <table class="table table-striped">
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
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card stats-card animate-scale-in delay-3">
                    <div class="card-header bg-info text-white">
                        <h5><i class="fas fa-chart-bar me-2"></i>System Stats</h5>
                    </div>
                    <div class="card-body">
                        <p><i class="fas fa-fire me-2"></i>Total Firewall Rules: {{ firewall_count }}</p>
                        <p><i class="fas fa-list me-2"></i>Review Queue Items: {{ review_count }}</p>
                        <p><i class="fas fa-comments me-2"></i>Feedback Submitted: {{ feedback_count }}</p>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card animate-fade-in-up delay-4">
                    <div class="card-header bg-success text-white">
                        <h5><i class="fas fa-comment-dots me-2"></i>Provide Feedback</h5>
                    </div>
                    <div class="card-body">
                        <form method="post" action="/submit_feedback">
                            <div class="mb-3">
                                <label for="ip" class="form-label">IP Address</label>
                                <input type="text" class="form-control" id="ip" name="ip" required>
                            </div>
                            <div class="mb-3">
                                <label for="feedback" class="form-label">Feedback</label>
                                <textarea class="form-control" id="feedback" name="feedback" rows="3" required></textarea>
                            </div>
                            <button type="submit" class="btn btn-primary"><i class="fas fa-paper-plane me-2"></i>Submit Feedback</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-12">
                <div class="card chart-container animate-fade-in-up delay-5">
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
                title: title,
                text: text,
                icon: icon,
                timer: 2000,
                timerProgressBar: true,
                showConfirmButton: false,
                position: 'top-end',
                toast: true
            });
        }

        // Show popups on page load
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
                title: `Are you sure?`,
                text: `Do you want to ${action} IP ${ip}?`,
                icon: 'warning',
                showCancelButton: true,
                confirmButtonText: `Yes, ${action} it!`,
                cancelButtonText: 'Cancel'
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

        // Enhanced chart with animations
        const ctx = document.getElementById('activityChart').getContext('2d');
        const activityChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
                datasets: [{
                    label: 'Incidents Detected',
                    data: [12, 19, 3, 5, 2, 3],
                    borderColor: 'rgb(102, 126, 234)',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    tension: 0.4,
                    fill: true,
                    pointBackgroundColor: 'rgb(102, 126, 234)',
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2,
                    pointRadius: 6,
                    pointHoverRadius: 8
                }]
            },
            options: {
                responsive: true,
                animation: {
                    duration: 2000,
                    easing: 'easeInOutQuart'
                },
                plugins: {
                    title: {
                        display: true,
                        text: 'Monthly Incident Trends',
                        font: {
                            size: 16,
                            weight: 'bold'
                        }
                    },
                    legend: {
                        labels: {
                            usePointStyle: true
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0,0,0,0.05)'
                        }
                    },
                    x: {
                        grid: {
                            color: 'rgba(0,0,0,0.05)'
                        }
                    }
                }
            }
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

@app.route('/')
def index():
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == 'admin123':  # Simple password for demo
            session['logged_in'] = True
            session['login_success'] = True
            return redirect(url_for('index'))
        else:
            return render_template_string(LOGIN_TEMPLATE, error='Invalid password')
    return render_template_string(LOGIN_TEMPLATE)

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

if __name__ == '__main__':
    app.run(debug=True)
