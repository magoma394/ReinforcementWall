"""
Flask dashboard for ReinforceWall.

Real-time visualization of training progress, attack detection, and agent performance.
"""

import json
import os
from pathlib import Path
from flask import Flask, render_template, jsonify, request
from datetime import datetime
import glob

app = Flask(__name__)
app.config['SECRET_KEY'] = 'reinforcewall-dashboard-secret-key'

# Paths
BASE_DIR = Path(__file__).parent.parent
METRICS_DIR = BASE_DIR / "data" / "metrics"
MODELS_DIR = BASE_DIR / "models" / "checkpoints"


@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('index.html')


@app.route('/api/metrics')
def get_metrics():
    """Get latest metrics data."""
    try:
        # Find latest metrics JSON file
        metrics_files = list(METRICS_DIR.glob("metrics_*.json"))
        if not metrics_files:
            return jsonify({'error': 'No metrics found'}), 404
        
        latest_file = max(metrics_files, key=os.path.getctime)
        
        with open(latest_file, 'r') as f:
            data = json.load(f)
        
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats')
def get_stats():
    """Get training statistics."""
    try:
        # Find latest training stats
        stats_files = list(METRICS_DIR.glob("training_stats_*.json"))
        if not stats_files:
            return jsonify({'error': 'No training stats found'}), 404
        
        latest_file = max(stats_files, key=os.path.getctime)
        
        with open(latest_file, 'r') as f:
            data = json.load(f)
        
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/models')
def get_models():
    """Get list of available models."""
    try:
        model_files = list(MODELS_DIR.glob("*.pth"))
        models = []
        for model_file in sorted(model_files, key=os.path.getctime, reverse=True):
            models.append({
                'name': model_file.name,
                'path': str(model_file),
                'size': model_file.stat().st_size,
                'modified': datetime.fromtimestamp(model_file.stat().st_mtime).isoformat()
            })
        return jsonify({'models': models})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/attack-distribution')
def get_attack_distribution():
    """Get attack type distribution from latest metrics."""
    try:
        metrics_files = list(METRICS_DIR.glob("metrics_*.json"))
        if not metrics_files:
            return jsonify({'error': 'No metrics found'}), 404
        
        latest_file = max(metrics_files, key=os.path.getctime)
        
        with open(latest_file, 'r') as f:
            data = json.load(f)
        
        # Calculate attack distribution
        attack_dist = {}
        if 'episodes' in data:
            for episode in data['episodes']:
                # This is simplified - in real implementation, track attack types
                pass
        
        return jsonify({'distribution': attack_dist})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/health')
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })


if __name__ == '__main__':
    # Create templates and static directories if they don't exist
    templates_dir = Path(__file__).parent / 'templates'
    static_dir = Path(__file__).parent / 'static'
    templates_dir.mkdir(exist_ok=True)
    static_dir.mkdir(exist_ok=True)
    
    app.run(debug=True, host='0.0.0.0', port=5000)

