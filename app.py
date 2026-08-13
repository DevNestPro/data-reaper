#!/usr/bin/env python3
"""
Automated Web Vulnerability Assessment Tool - Flask Backend
WARNING: For authorized security testing only. Use only on systems you own
or have explicit written permission to test.
"""

from flask import Flask, request, jsonify, send_from_directory
import os
import sys

# Absolute paths so the app works regardless of CWD
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, 'frontend')

# Add core module to path
sys.path.insert(0, BASE_DIR)

from core.auditor import AuditManager

# YAHAN static_url_path='' ADD KIYA GAYA HAI JISSE CSS/JS LOAD HONGE
app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path='')

# Initialize the audit manager
audit_manager = AuditManager()


@app.route('/')
def index():
    """Serve the main dashboard."""
    return send_from_directory(FRONTEND_DIR, 'index.html')


@app.route('/api/start_audit', methods=['POST'])
def start_audit():
    """
    Start a new SQL injection audit.
    Expects JSON: {"target_url": "http://example.com/page.php?id=1"}
    """
    try:
        data = request.get_json()
        if not data or 'target_url' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing required field: target_url'
            }), 400

        target_url = data['target_url'].strip()
        
        # Basic URL validation
        if not target_url.startswith(('http://', 'https://')):
            return jsonify({
                'success': False,
                'error': 'Invalid URL. Must start with http:// or https://'
            }), 400

        result = audit_manager.start_audit(target_url)
        return jsonify(result)

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Server error: {str(e)}'
        }), 500


@app.route('/api/audit_status', methods=['GET'])
def audit_status():
    """Get current audit status and live output."""
    return jsonify(audit_manager.get_status())


@app.route('/api/stop_audit', methods=['POST'])
def stop_audit():
    """Stop the currently running audit."""
    return jsonify(audit_manager.stop_audit())


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    sqlmap_available = audit_manager.check_sqlmap()
    return jsonify({
        'status': 'healthy',
        'sqlmap_available': sqlmap_available
    })


if __name__ == '__main__':
    print("[*] Starting Vulnerability Assessment Dashboard...")
    print("[*] Ensure sqlmap is installed: sudo apt install sqlmap")
    print("[*] Access the dashboard at http://127.0.0.1:5000")
    print("[!] WARNING: Only use on authorized targets!\n")
    
    app.run(host='127.0.0.1', port=5000, debug=False, threaded=True)