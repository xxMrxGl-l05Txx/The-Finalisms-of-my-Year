"""
Enhanced API server with comprehensive endpoints and security features
"""
from flask import Flask, jsonify, request, Response, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
import os
import sys
import logging
import time
from datetime import datetime, timedelta
from functools import wraps
import hashlib
import secrets

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import ConfigManager
from core.database import DatabaseManager
from core.exceptions import APIError
from reporting.enhanced_report_generator import EnhancedSecurityReportGenerator

logger = logging.getLogger(__name__)

app = Flask(__name__)

# Initialize rate limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per minute"]
)

def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_server = app.config.get('api_server')
        if not api_server or not api_server.config.api.enable_authentication:
            return f(*args, **kwargs)
        
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key != api_server.config.api.api_key:
            return jsonify({"error": "Invalid or missing API key"}), 401
        
        return f(*args, **kwargs)
    return decorated_function

class EnhancedSecurityAPIServer:
    """Enhanced API server with comprehensive security monitoring endpoints"""
    
    def __init__(self, config_manager: ConfigManager, db_manager: DatabaseManager):
        self.config_manager = config_manager
        self.db_manager = db_manager
        self.config = config_manager.get_config().api
        self.report_generator = EnhancedSecurityReportGenerator(db_manager)
        
        # API statistics
        self.api_stats = {
            'requests_total': 0,
            'requests_by_endpoint': {},
            'errors_total': 0,
            'start_time': time.time()
        }
        
        # Setup Flask app
        self._setup_app()
        
        logger.info("Enhanced API server initialized")
    
    def _setup_app(self):
        """Setup Flask application with middleware"""
        # Enable CORS if configured
        if self.config.enable_cors:
            CORS(app)
        
        # Configure rate limiting
        if self.config.enable_rate_limiting:
            limiter.limit(f"{self.config.rate_limit_per_minute} per minute")(app)
        
        # Add request middleware
        @app.before_request
        def before_request():
            self.api_stats['requests_total'] += 1
            endpoint = request.endpoint or 'unknown'
            self.api_stats['requests_by_endpoint'][endpoint] = (
                self.api_stats['requests_by_endpoint'].get(endpoint, 0) + 1
            )
        
        # Add error handler
        @app.errorhandler(Exception)
        def handle_error(error):
            self.api_stats['errors_total'] += 1
            logger.error(f"API error: {error}")
            return jsonify({"error": "Internal server error"}), 500
        
        # Store reference to self in app config
        app.config['api_server'] = self
    
    def start(self):
        """Start the API server"""
        logger.info(f"Starting enhanced API server on {self.config.host}:{self.config.port}")
        app.run(
            host=self.config.host, 
            port=self.config.port,
            debug=False,
            threaded=True
        )

# API Routes

@app.route('/api/v1/status', methods=['GET'])
@limiter.limit("10 per minute")
def get_status():
    """Get system status and health information"""
    try:
        api_server = app.config['api_server']
        
        # Get database statistics
        db_stats = api_server.db_manager.get_statistics()
        
        # Calculate uptime
        uptime = time.time() - api_server.api_stats['start_time']
        
        status = {
            "status": "healthy",
            "version": "2.0.0",
            "timestamp": datetime.now().isoformat(),
            "uptime_seconds": uptime,
            "database": {
                "connected": True,
                "statistics": db_stats
            },
            "api": {
                "requests_total": api_server.api_stats['requests_total'],
                "errors_total": api_server.api_stats['errors_total'],
                "endpoints": api_server.api_stats['requests_by_endpoint']
            }
        }
        
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/alerts', methods=['GET'])
@require_api_key
@limiter.limit("50 per minute")
def get_alerts():
    """Get alerts with advanced filtering and pagination"""
    try:
        api_server = app.config['api_server']
        
        # Parse query parameters
        limit = min(int(request.args.get('limit', 100)), 1000)  # Max 1000
        offset = int(request.args.get('offset', 0))
        severity = request.args.get('severity')
        status = request.args.get('status')
        alert_type = request.args.get('type')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # Convert dates to timestamps
        start_time = None
        end_time = None
        
        if start_date:
            start_time = datetime.fromisoformat(start_date).timestamp()
        if end_date:
            end_time = datetime.fromisoformat(end_date).timestamp()
        
        # Get alerts from database
        alerts = api_server.db_manager.get_alerts(
            limit=limit,
            offset=offset,
            severity=severity,
            status=status,
            start_time=start_time,
            end_time=end_time
        )
        
        # Filter by type if specified
        if alert_type:
            alerts = [a for a in alerts if a.get('type') == alert_type]
        
        # Calculate pagination info
        total_count = len(alerts) + offset  # Approximate
        has_more = len(alerts) == limit
        
        return jsonify({
            "alerts": alerts,
            "pagination": {
                "limit": limit,
                "offset": offset,
                "count": len(alerts),
                "has_more": has_more
            },
            "filters": {
                "severity": severity,
                "status": status,
                "type": alert_type,
                "start_date": start_date,
                "end_date": end_date
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/alerts/<alert_id>', methods=['GET'])
@require_api_key
def get_alert_details(alert_id):
    """Get detailed information about a specific alert"""
    try:
        api_server = app.config['api_server']
        
        alerts = api_server.db_manager.get_alerts(limit=1)
        alert = next((a for a in alerts if a['id'] == alert_id), None)
        
        if not alert:
            return jsonify({"error": "Alert not found"}), 404
        
        return jsonify({"alert": alert})
        
    except Exception as e:
        logger.error(f"Error getting alert details: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/alerts/<alert_id>/status', methods=['PUT'])
@require_api_key
def update_alert_status(alert_id):
    """Update alert status (acknowledge, resolve, etc.)"""
    try:
        api_server = app.config['api_server']
        
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400
        
        data = request.get_json()
        new_status = data.get('status')
        
        if new_status not in ['new', 'acknowledged', 'resolved', 'false_positive']:
            return jsonify({"error": "Invalid status"}), 400
        
        # Update in database
        timestamp = time.time()
        acknowledged_at = timestamp if new_status == 'acknowledged' else None
        resolved_at = timestamp if new_status == 'resolved' else None
        
        success = api_server.db_manager.update_alert_status(
            alert_id, new_status, acknowledged_at, resolved_at
        )
        
        if success:
            return jsonify({"message": "Alert status updated successfully"})
        else:
            return jsonify({"error": "Alert not found or update failed"}), 404
            
    except Exception as e:
        logger.error(f"Error updating alert status: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/metrics', methods=['GET'])
@require_api_key
@limiter.limit("30 per minute")
def get_metrics():
    """Get system metrics with time range filtering"""
    try:
        api_server = app.config['api_server']
        
        # Parse query parameters
        limit = min(int(request.args.get('limit', 100)), 1000)
        hours = int(request.args.get('hours', 24))
        
        # Calculate time range
        end_time = time.time()
        start_time = end_time - (hours * 3600)
        
        # Get metrics from database
        metrics = api_server.db_manager.get_metrics(
            limit=limit,
            start_time=start_time,
            end_time=end_time
        )
        
        return jsonify({
            "metrics": metrics,
            "time_range": {
                "start_time": start_time,
                "end_time": end_time,
                "hours": hours
            },
            "count": len(metrics)
        })
        
    except Exception as e:
        logger.error(f"Error getting metrics: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/dashboard/summary', methods=['GET'])
@require_api_key
def get_dashboard_summary():
    """Get dashboard summary with key metrics and statistics"""
    try:
        api_server = app.config['api_server']
        
        # Get recent alerts (last 24 hours)
        last_24h = time.time() - (24 * 3600)
        recent_alerts = api_server.db_manager.get_alerts(
            limit=1000,
            start_time=last_24h
        )
        
        # Calculate summary statistics
        total_alerts = len(recent_alerts)
        new_alerts = len([a for a in recent_alerts if a.get('status') == 'new'])
        critical_alerts = len([a for a in recent_alerts if a.get('severity') == 'CRITICAL'])
        high_alerts = len([a for a in recent_alerts if a.get('severity') == 'HIGH'])
        
        # Get latest metrics
        latest_metrics = api_server.db_manager.get_metrics(limit=1)
        current_metrics = latest_metrics[0] if latest_metrics else {}
        
        # Calculate risk score
        risk_score = min(100, (critical_alerts * 20) + (high_alerts * 10) + (new_alerts * 5))
        
        summary = {
            "alerts": {
                "total_24h": total_alerts,
                "new": new_alerts,
                "critical": critical_alerts,
                "high": high_alerts
            },
            "system": {
                "cpu_percent": current_metrics.get('cpu_percent', 0),
                "memory_percent": current_metrics.get('memory_percent', 0),
                "disk_percent": current_metrics.get('disk_percent', 0)
            },
            "risk_score": risk_score,
            "timestamp": datetime.now().isoformat()
        }
        
        return jsonify(summary)
        
    except Exception as e:
        logger.error(f"Error getting dashboard summary: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/reports/generate', methods=['POST'])
@require_api_key
@limiter.limit("5 per minute")
def generate_report():
    """Generate a comprehensive security report"""
    try:
        api_server = app.config['api_server']
        
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400
        
        data = request.get_json()
        report_type = data.get('type', 'summary')
        days = data.get('days', 30)
        format_type = data.get('format', 'html')
        
        if report_type == 'summary':
            if format_type == 'html':
                report_path = api_server.report_generator.generate_summary_report(days=days)
            elif format_type == 'csv':
                report_path = api_server.report_generator.generate_csv_report(days=days)
            elif format_type == 'json':
                report_path = api_server.report_generator.generate_json_report(days=days)
            else:
                return jsonify({"error": "Unsupported format"}), 400
        else:
            return jsonify({"error": "Unsupported report type"}), 400
        
        if report_path:
            return jsonify({
                "message": "Report generated successfully",
                "report_path": str(report_path),
                "download_url": f"/api/v1/reports/download/{os.path.basename(report_path)}"
            })
        else:
            return jsonify({"error": "Failed to generate report"}), 500
            
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/reports/download/<filename>', methods=['GET'])
@require_api_key
def download_report(filename):
    """Download a generated report"""
    try:
        api_server = app.config['api_server']
        reports_dir = api_server.report_generator.output_dir
        file_path = os.path.join(reports_dir, filename)
        
        if not os.path.exists(file_path):
            return jsonify({"error": "Report not found"}), 404
        
        # Determine MIME type based on extension
        if filename.endswith('.csv'):
            mimetype = 'text/csv'
        elif filename.endswith('.json'):
            mimetype = 'application/json'
        elif filename.endswith('.html'):
            mimetype = 'text/html'
        else:
            mimetype = 'application/octet-stream'
        
        return send_file(
            file_path,
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        logger.error(f"Error downloading report: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/config', methods=['GET', 'PUT'])
@require_api_key
def manage_config():
    """Get or update system configuration"""
    try:
        api_server = app.config['api_server']
        
        if request.method == 'GET':
            config = api_server.config_manager.get_config()
            return jsonify({
                "config": {
                    "monitoring": config.monitoring.__dict__,
                    "alerting": config.alerting.__dict__,
                    "api": {k: v for k, v in config.api.__dict__.items() if k != 'api_key'},
                    "log_level": config.log_level,
                    "data_retention_days": config.data_retention_days
                }
            })
        
        elif request.method == 'PUT':
            if not request.is_json:
                return jsonify({"error": "Content-Type must be application/json"}), 400
            
            data = request.get_json()
            
            # Update configuration
            success = api_server.config_manager.update_config(**data)
            
            if success:
                return jsonify({"message": "Configuration updated successfully"})
            else:
                return jsonify({"error": "Failed to update configuration"}), 500
                
    except Exception as e:
        logger.error(f"Error managing config: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/system/health', methods=['GET'])
@limiter.limit("20 per minute")
def get_system_health():
    """Get comprehensive system health information"""
    try:
        import psutil
        
        # System information
        boot_time = psutil.boot_time()
        uptime = time.time() - boot_time
        
        health = {
            "system": {
                "hostname": os.uname().nodename,
                "platform": os.uname().sysname,
                "uptime_seconds": uptime,
                "boot_time": datetime.fromtimestamp(boot_time).isoformat()
            },
            "resources": {
                "cpu": {
                    "percent": psutil.cpu_percent(interval=1),
                    "count": psutil.cpu_count(),
                    "load_avg": os.getloadavg() if hasattr(os, 'getloadavg') else None
                },
                "memory": {
                    "percent": psutil.virtual_memory().percent,
                    "total": psutil.virtual_memory().total,
                    "available": psutil.virtual_memory().available
                },
                "disk": {
                    "percent": psutil.disk_usage('/').percent,
                    "total": psutil.disk_usage('/').total,
                    "free": psutil.disk_usage('/').free
                }
            },
            "network": {
                "connections": len(psutil.net_connections()),
                "io_counters": psutil.net_io_counters()._asdict()
            },
            "processes": {
                "count": len(psutil.pids()),
                "running": len([p for p in psutil.process_iter() if p.status() == 'running'])
            }
        }
        
        return jsonify(health)
        
    except Exception as e:
        logger.error(f"Error getting system health: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/statistics', methods=['GET'])
@require_api_key
def get_statistics():
    """Get comprehensive system statistics"""
    try:
        api_server = app.config['api_server']
        
        # Get database statistics
        db_stats = api_server.db_manager.get_statistics()
        
        # Calculate time-based statistics
        now = time.time()
        last_hour = now - 3600
        last_day = now - (24 * 3600)
        last_week = now - (7 * 24 * 3600)
        
        # Get alerts for different time periods
        alerts_last_hour = api_server.db_manager.get_alerts(start_time=last_hour)
        alerts_last_day = api_server.db_manager.get_alerts(start_time=last_day)
        alerts_last_week = api_server.db_manager.get_alerts(start_time=last_week)
        
        statistics = {
            "database": db_stats,
            "alerts": {
                "last_hour": len(alerts_last_hour),
                "last_day": len(alerts_last_day),
                "last_week": len(alerts_last_week)
            },
            "api": api_server.api_stats,
            "timestamp": datetime.now().isoformat()
        }
        
        return jsonify(statistics)
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return jsonify({"error": str(e)}), 500

# Legacy endpoint for backward compatibility
@app.route('/download-csv', methods=['GET'])
def download_csv_legacy():
    """Legacy CSV download endpoint"""
    try:
        api_server = app.config['api_server']
        days = request.args.get('days', default=30, type=int)
        
        csv_path = api_server.report_generator.generate_csv_report(days=days)
        
        if not csv_path or not os.path.exists(csv_path):
            return jsonify({"error": "Failed to generate CSV report"}), 500
        
        return send_file(
            csv_path,
            mimetype='text/csv',
            as_attachment=True,
            download_name=os.path.basename(csv_path)
        )
        
    except Exception as e:
        logger.error(f"Error generating CSV report: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    # Initialize components
    config_manager = ConfigManager()
    db_manager = DatabaseManager()
    
    # Create and start API server
    api_server = EnhancedSecurityAPIServer(config_manager, db_manager)
    app.config['api_server'] = api_server
    api_server.start()