"""
Flask web frontend for the merchant checker tool.
Provides a simple web interface to check merchant websites and download reports.
"""
import os
import tempfile
import uuid
from flask import Flask, render_template, request, flash, redirect, url_for, send_file, jsonify
from werkzeug.utils import secure_filename
import subprocess
import json
from pathlib import Path

app = Flask(__name__)
app.secret_key = 'merchant-checker-secret-key-change-in-production'

# Configuration
UPLOAD_FOLDER = 'uploads'
REPORTS_FOLDER = 'reports'
ALLOWED_EXTENSIONS = {'csv', 'txt'}

# Create directories if they don't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def run_merchant_checker(urls=None, input_file=None, output_prefix=None):
    """Run the merchant checker script and return the results."""
    if not output_prefix:
        output_prefix = f"report_{uuid.uuid4().hex[:8]}"
    
    output_path = os.path.join(REPORTS_FOLDER, output_prefix)
    
    # Build command
    cmd = ['python', 'merchant_checker.py', '--out', output_path]
    
    if urls:
        for url in urls:
            cmd.extend(['--url', url.strip()])
    elif input_file:
        cmd.extend(['--input', input_file])
    
    try:
        # Run the merchant checker
        result = subprocess.run(cmd, 
                              capture_output=True, 
                              text=True, 
                              cwd=os.path.dirname(os.path.abspath(__file__)))
        
        if result.returncode == 0:
            return {
                'success': True,
                'output_prefix': output_prefix,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
        else:
            return {
                'success': False,
                'error': result.stderr or result.stdout,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
    except Exception as e:
        return {
            'success': False,
            'error': f"Failed to run merchant checker: {str(e)}"
        }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_merchants():
    urls = []
    input_file = None
    
    # Get URLs from text input
    url_input = request.form.get('urls', '').strip()
    if url_input:
        urls = [url.strip() for url in url_input.split('\n') if url.strip()]
    
    # Check for uploaded file
    if 'file' in request.files:
        file = request.files['file']
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4().hex}_{filename}")
            file.save(filepath)
            input_file = filepath
    
    if not urls and not input_file:
        flash('Please provide either URLs or upload a CSV file.', 'error')
        return redirect(url_for('index'))
    
    # Run the checker
    result = run_merchant_checker(urls=urls, input_file=input_file)
    
    # Clean up uploaded file
    if input_file and os.path.exists(input_file):
        os.remove(input_file)
    
    if result['success']:
        flash('Analysis completed successfully!', 'success')
        return render_template('results.html', 
                             output_prefix=result['output_prefix'],
                             stdout=result['stdout'])
    else:
        flash(f'Analysis failed: {result["error"]}', 'error')
        return render_template('results.html', 
                             error=result['error'],
                             stdout=result.get('stdout'),
                             stderr=result.get('stderr'))

@app.route('/download/<output_prefix>/<file_type>')
def download_report(output_prefix, file_type):
    """Download generated reports."""
    if file_type not in ['csv', 'jsonl', 'logs']:
        flash('Invalid file type requested.', 'error')
        return redirect(url_for('index'))
    
    if file_type == 'logs':
        filename = f"{output_prefix}_logs.txt"
    else:
        filename = f"{output_prefix}.{file_type}"
    
    filepath = os.path.join(REPORTS_FOLDER, filename)
    
    if not os.path.exists(filepath):
        flash(f'Report file not found: {filename}', 'error')
        return redirect(url_for('index'))
    
    return send_file(filepath, as_attachment=True, download_name=filename)

@app.route('/status/<output_prefix>')
def get_status(output_prefix):
    """Check if report files are ready."""
    csv_path = os.path.join(REPORTS_FOLDER, f"{output_prefix}.csv")
    jsonl_path = os.path.join(REPORTS_FOLDER, f"{output_prefix}.jsonl")
    logs_path = os.path.join(REPORTS_FOLDER, f"{output_prefix}_logs.txt")
    
    return jsonify({
        'csv_ready': os.path.exists(csv_path),
        'jsonl_ready': os.path.exists(jsonl_path),
        'logs_ready': os.path.exists(logs_path)
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)