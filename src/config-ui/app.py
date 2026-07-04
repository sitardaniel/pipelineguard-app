#!/usr/bin/env python3
"""
PipelineGuard Config UI

Simple web interface to select GitHub repos for scanning.
"""

import json
import os
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler

# Configuration
GITHUB_USERNAME = os.getenv('GITHUB_USERNAME', 'sitardaniel')
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '')  # Optional, for private repos
PORT = int(os.getenv('PORT', '8080'))
CONFIG_FILE = os.getenv('CONFIG_FILE', '/config/repos.txt')

def get_github_repos(username):
    """Fetch repos from GitHub API."""
    repos = []
    page = 1

    while True:
        url = f"https://api.github.com/users/{username}/repos?per_page=100&page={page}&sort=updated"
        headers = {'Accept': 'application/vnd.github.v3+json'}
        if GITHUB_TOKEN:
            headers['Authorization'] = f'token {GITHUB_TOKEN}'

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read())
                if not data:
                    break
                repos.extend(data)
                page += 1
                if len(data) < 100:
                    break
        except Exception as e:
            print(f"Error fetching repos: {e}")
            break

    return repos

def get_selected_repos():
    """Read currently selected repos from config."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []

def save_selected_repos(repos):
    """Save selected repos to config file."""
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        for repo in repos:
            f.write(repo + '\n')

HTML_TEMPLATE = '''<!DOCTYPE html>
<html>
<head>
    <title>PipelineGuard - Select Repos</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #fff;
            padding: 40px 20px;
        }
        .container { max-width: 800px; margin: 0 auto; }
        h1 {
            font-size: 2rem;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .subtitle { color: #888; margin-bottom: 30px; }
        .search-box {
            width: 100%;
            padding: 12px 16px;
            font-size: 16px;
            border: 2px solid #333;
            border-radius: 8px;
            background: #0f0f1a;
            color: #fff;
            margin-bottom: 20px;
        }
        .search-box:focus { outline: none; border-color: #4a9eff; }
        .repo-list {
            background: #0f0f1a;
            border-radius: 12px;
            overflow: hidden;
            max-height: 500px;
            overflow-y: auto;
        }
        .repo-item {
            display: flex;
            align-items: center;
            padding: 16px 20px;
            border-bottom: 1px solid #222;
            cursor: pointer;
            transition: background 0.2s;
        }
        .repo-item:hover { background: #1a1a2e; }
        .repo-item.selected { background: #1e3a5f; }
        .repo-item input {
            width: 20px;
            height: 20px;
            margin-right: 15px;
            cursor: pointer;
        }
        .repo-info { flex: 1; }
        .repo-name { font-weight: 600; font-size: 1.1rem; }
        .repo-desc { color: #888; font-size: 0.9rem; margin-top: 4px; }
        .repo-meta {
            display: flex;
            gap: 15px;
            margin-top: 6px;
            font-size: 0.8rem;
            color: #666;
        }
        .btn {
            background: #4a9eff;
            color: #fff;
            border: none;
            padding: 14px 28px;
            font-size: 16px;
            font-weight: 600;
            border-radius: 8px;
            cursor: pointer;
            margin-top: 20px;
            transition: background 0.2s;
        }
        .btn:hover { background: #3a8eef; }
        .btn:disabled { background: #444; cursor: not-allowed; }
        .status {
            margin-top: 15px;
            padding: 12px;
            border-radius: 8px;
            display: none;
        }
        .status.success { display: block; background: #1e4620; }
        .status.error { display: block; background: #4a1515; }
        .selected-count {
            background: #4a9eff;
            color: #fff;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.9rem;
        }
        .header-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>PipelineGuard</h1>
        <p class="subtitle">Select repositories to scan for security vulnerabilities</p>

        <input type="text" class="search-box" id="search" placeholder="Search repositories..." oninput="filterRepos()">

        <div class="header-row">
            <span id="selectedCount" class="selected-count">0 selected</span>
        </div>

        <div class="repo-list" id="repoList">
            <!-- Repos will be inserted here -->
        </div>

        <button class="btn" id="saveBtn" onclick="saveSelection()">Save Selection</button>
        <div class="status" id="status"></div>
    </div>

    <script>
        const repos = REPOS_JSON;
        const selected = SELECTED_JSON;

        function renderRepos(filter = '') {
            const list = document.getElementById('repoList');
            const filtered = repos.filter(r =>
                r.name.toLowerCase().includes(filter.toLowerCase()) ||
                (r.description && r.description.toLowerCase().includes(filter.toLowerCase()))
            );

            list.innerHTML = filtered.map(repo => {
                const isSelected = selected.includes(repo.html_url);
                return `
                    <label class="repo-item ${isSelected ? 'selected' : ''}" data-url="${repo.html_url}">
                        <input type="checkbox" ${isSelected ? 'checked' : ''} onchange="toggleRepo(this, '${repo.html_url}')">
                        <div class="repo-info">
                            <div class="repo-name">${repo.name}</div>
                            ${repo.description ? `<div class="repo-desc">${repo.description}</div>` : ''}
                            <div class="repo-meta">
                                <span>${repo.language || 'Unknown'}</span>
                                <span>${repo.stargazers_count} stars</span>
                                <span>Updated ${new Date(repo.updated_at).toLocaleDateString()}</span>
                            </div>
                        </div>
                    </label>
                `;
            }).join('');

            updateCount();
        }

        function toggleRepo(checkbox, url) {
            const item = checkbox.closest('.repo-item');
            if (checkbox.checked) {
                selected.push(url);
                item.classList.add('selected');
            } else {
                const idx = selected.indexOf(url);
                if (idx > -1) selected.splice(idx, 1);
                item.classList.remove('selected');
            }
            updateCount();
        }

        function updateCount() {
            document.getElementById('selectedCount').textContent = selected.length + ' selected';
        }

        function filterRepos() {
            renderRepos(document.getElementById('search').value);
        }

        function saveSelection() {
            const btn = document.getElementById('saveBtn');
            const status = document.getElementById('status');
            btn.disabled = true;
            btn.textContent = 'Saving...';

            fetch('/save', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({repos: selected})
            })
            .then(r => r.json())
            .then(data => {
                status.className = 'status success';
                status.textContent = 'Saved! Scanners will use these repos on next run.';
                btn.textContent = 'Save Selection';
                btn.disabled = false;
            })
            .catch(err => {
                status.className = 'status error';
                status.textContent = 'Error saving: ' + err;
                btn.textContent = 'Save Selection';
                btn.disabled = false;
            });
        }

        renderRepos();
    </script>
</body>
</html>
'''

class ConfigUIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status":"healthy"}')
            return

        # Fetch repos and render page
        repos = get_github_repos(GITHUB_USERNAME)
        selected = get_selected_repos()

        html = HTML_TEMPLATE.replace(
            'REPOS_JSON', json.dumps(repos)
        ).replace(
            'SELECTED_JSON', json.dumps(selected)
        )

        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def do_POST(self):
        if self.path == '/save':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body)

            repos = data.get('repos', [])
            save_selected_repos(repos)

            # Also update the Kubernetes ConfigMap if running in cluster
            try:
                update_configmap(repos)
            except Exception as e:
                print(f"Could not update ConfigMap: {e}")

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'ok', 'count': len(repos)}).encode())
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        print(f"{self.address_string()} - {format % args}")

def update_configmap(repos):
    """Update Kubernetes ConfigMap with selected repos."""
    try:
        from kubernetes import client, config
        try:
            config.load_incluster_config()
        except:
            config.load_kube_config()

        v1 = client.CoreV1Api()

        # Get current ConfigMap
        cm = v1.read_namespaced_config_map('scanner-config', 'pipelineguard')

        # Update TARGET_REPOS
        cm.data['TARGET_REPOS'] = '\n'.join(repos)

        # Patch ConfigMap
        v1.patch_namespaced_config_map('scanner-config', 'pipelineguard', cm)
        print(f"Updated ConfigMap with {len(repos)} repos")
    except ImportError:
        print("kubernetes package not installed, skipping ConfigMap update")

def main():
    print(f"Starting PipelineGuard Config UI on port {PORT}")
    print(f"GitHub username: {GITHUB_USERNAME}")
    server = HTTPServer(('0.0.0.0', PORT), ConfigUIHandler)
    server.serve_forever()

if __name__ == '__main__':
    main()
