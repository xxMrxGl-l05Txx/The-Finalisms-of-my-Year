"""
Enhanced report generator with multiple formats and advanced analytics
"""
import json
import os
import sys
import logging
import csv
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import seaborn as sns
from jinja2 import Template
import pandas as pd

# Set matplotlib backend for headless operation
import matplotlib
matplotlib.use('Agg')

from ..core.database import DatabaseManager
from ..core.exceptions import SecurityMonitoringError

logger = logging.getLogger(__name__)

class EnhancedSecurityReportGenerator:
    """Enhanced report generator with comprehensive analytics and multiple formats"""
    
    def __init__(self, db_manager: DatabaseManager, output_dir: str = None):
        self.db_manager = db_manager
        self.output_dir = Path(output_dir or "reports")
        self.output_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        (self.output_dir / "charts").mkdir(exist_ok=True)
        (self.output_dir / "data").mkdir(exist_ok=True)
        (self.output_dir / "templates").mkdir(exist_ok=True)
        
        # Initialize templates
        self._create_templates()
        
        logger.info("Enhanced report generator initialized")
    
    def _create_templates(self):
        """Create HTML templates for reports"""
        # Main report template
        main_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Monitoring Report - {{ report_date }}</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 40px; border-bottom: 3px solid #2c3e50; padding-bottom: 20px; }
        .header h1 { color: #2c3e50; margin: 0; font-size: 2.5em; }
        .header p { color: #7f8c8d; margin: 10px 0 0 0; font-size: 1.1em; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 40px; }
        .summary-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .summary-card h3 { margin: 0 0 10px 0; font-size: 1.2em; }
        .summary-card .value { font-size: 2.5em; font-weight: bold; margin: 10px 0; }
        .summary-card .label { font-size: 0.9em; opacity: 0.9; }
        .section { margin-bottom: 40px; }
        .section h2 { color: #2c3e50; border-left: 4px solid #3498db; padding-left: 15px; margin-bottom: 20px; }
        .chart-container { text-align: center; margin: 20px 0; }
        .chart-container img { max-width: 100%; height: auto; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .table-container { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: 600; color: #2c3e50; }
        tr:hover { background-color: #f8f9fa; }
        .severity-critical { background-color: #e74c3c; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; }
        .severity-high { background-color: #e67e22; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; }
        .severity-medium { background-color: #f39c12; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; }
        .severity-low { background-color: #27ae60; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; }
        .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; }
        .recommendations { background-color: #ecf0f1; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .recommendations h3 { color: #2c3e50; margin-top: 0; }
        .recommendations ul { margin: 0; padding-left: 20px; }
        .recommendations li { margin: 8px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Monitoring Report</h1>
            <p>Generated on {{ report_date }} | Period: {{ period_description }}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Total Alerts</h3>
                <div class="value">{{ summary.total_alerts }}</div>
                <div class="label">{{ period_description }}</div>
            </div>
            <div class="summary-card">
                <h3>Critical Alerts</h3>
                <div class="value">{{ summary.critical_alerts }}</div>
                <div class="label">Require immediate attention</div>
            </div>
            <div class="summary-card">
                <h3>Risk Score</h3>
                <div class="value">{{ summary.risk_score }}</div>
                <div class="label">Out of 100</div>
            </div>
            <div class="summary-card">
                <h3>Systems Monitored</h3>
                <div class="value">{{ summary.systems_count }}</div>
                <div class="label">Active monitoring</div>
            </div>
        </div>
        
        {% if charts %}
        <div class="section">
            <h2>Analytics and Trends</h2>
            {% for chart in charts %}
            <div class="chart-container">
                <h3>{{ chart.title }}</h3>
                <img src="{{ chart.path }}" alt="{{ chart.title }}">
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        {% if critical_alerts %}
        <div class="section">
            <h2>Critical Alerts</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Type</th>
                            <th>Severity</th>
                            <th>System</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for alert in critical_alerts %}
                        <tr>
                            <td>{{ alert.timestamp_formatted }}</td>
                            <td>{{ alert.type }}</td>
                            <td><span class="severity-{{ alert.severity.lower() }}">{{ alert.severity }}</span></td>
                            <td>{{ alert.system_name or 'Unknown' }}</td>
                            <td>{{ alert.details }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}
        
        {% if recommendations %}
        <div class="section">
            <h2>Recommendations</h2>
            <div class="recommendations">
                <h3>Immediate Actions Required</h3>
                <ul>
                    {% for rec in recommendations.immediate %}
                    <li>{{ rec }}</li>
                    {% endfor %}
                </ul>
                
                <h3>Long-term Improvements</h3>
                <ul>
                    {% for rec in recommendations.longterm %}
                    <li>{{ rec }}</li>
                    {% endfor %}
                </ul>
            </div>
        </div>
        {% endif %}
        
        <div class="footer">
            <p>This report was automatically generated by the Security Monitoring System</p>
            <p>For questions or concerns, please contact your security team</p>
        </div>
    </div>
</body>
</html>
        """
        
        template_path = self.output_dir / "templates" / "main_report.html"
        with open(template_path, 'w') as f:
            f.write(main_template)
    
    def _load_alerts(self, days: int = 30) -> List[Dict[str, Any]]:
        """Load alerts from the database"""
        try:
            if days > 0:
                start_time = (datetime.now() - timedelta(days=days)).timestamp()
                alerts = self.db_manager.get_alerts(
                    limit=10000,  # Large limit to get all alerts
                    start_time=start_time
                )
            else:
                alerts = self.db_manager.get_alerts(limit=10000)
            
            # Add formatted timestamp
            for alert in alerts:
                if alert.get('timestamp'):
                    alert['timestamp_formatted'] = datetime.fromtimestamp(
                        alert['timestamp']
                    ).strftime('%Y-%m-%d %H:%M:%S')
            
            return alerts
        except Exception as e:
            logger.error(f"Failed to load alerts: {e}")
            return []
    
    def _load_metrics(self, days: int = 30) -> List[Dict[str, Any]]:
        """Load metrics from the database"""
        try:
            if days > 0:
                start_time = (datetime.now() - timedelta(days=days)).timestamp()
                metrics = self.db_manager.get_metrics(
                    limit=10000,
                    start_time=start_time
                )
            else:
                metrics = self.db_manager.get_metrics(limit=10000)
            
            return metrics
        except Exception as e:
            logger.error(f"Failed to load metrics: {e}")
            return []
    
    def _generate_charts(self, alerts: List[Dict[str, Any]], 
                        metrics: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Generate charts for the report"""
        charts = []
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        try:
            # Set style for better-looking charts
            plt.style.use('seaborn-v0_8')
            sns.set_palette("husl")
            
            # 1. Alerts by severity pie chart
            if alerts:
                severity_counts = {}
                for alert in alerts:
                    severity = alert.get('severity', 'UNKNOWN')
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                if severity_counts:
                    fig, ax = plt.subplots(figsize=(10, 8))
                    colors = {'CRITICAL': '#e74c3c', 'HIGH': '#e67e22', 'MEDIUM': '#f39c12', 'LOW': '#27ae60'}
                    chart_colors = [colors.get(sev, '#95a5a6') for sev in severity_counts.keys()]
                    
                    wedges, texts, autotexts = ax.pie(
                        severity_counts.values(),
                        labels=severity_counts.keys(),
                        autopct='%1.1f%%',
                        colors=chart_colors,
                        startangle=90,
                        explode=[0.05 if sev in ['CRITICAL', 'HIGH'] else 0 for sev in severity_counts.keys()]
                    )
                    
                    ax.set_title('Alerts by Severity', fontsize=16, fontweight='bold', pad=20)
                    
                    chart_path = self.output_dir / "charts" / f"severity_distribution_{timestamp}.png"
                    plt.savefig(chart_path, dpi=300, bbox_inches='tight')
                    plt.close()
                    
                    charts.append({
                        'title': 'Alert Severity Distribution',
                        'path': f"charts/{chart_path.name}"
                    })
            
            # 2. Alerts timeline
            if alerts:
                # Group alerts by day
                daily_counts = {}
                for alert in alerts:
                    if alert.get('timestamp'):
                        date = datetime.fromtimestamp(alert['timestamp']).date()
                        daily_counts[date] = daily_counts.get(date, 0) + 1
                
                if daily_counts:
                    dates = sorted(daily_counts.keys())
                    counts = [daily_counts[date] for date in dates]
                    
                    fig, ax = plt.subplots(figsize=(12, 6))
                    ax.plot(dates, counts, marker='o', linewidth=2, markersize=6)
                    ax.set_title('Alerts Timeline', fontsize=16, fontweight='bold', pad=20)
                    ax.set_xlabel('Date')
                    ax.set_ylabel('Number of Alerts')
                    ax.grid(True, alpha=0.3)
                    
                    # Format x-axis
                    ax.xaxis.set_major_formatter(mdates.DateFormatter('%m/%d'))
                    ax.xaxis.set_major_locator(mdates.DayLocator(interval=max(1, len(dates)//10)))
                    plt.xticks(rotation=45)
                    
                    chart_path = self.output_dir / "charts" / f"alerts_timeline_{timestamp}.png"
                    plt.savefig(chart_path, dpi=300, bbox_inches='tight')
                    plt.close()
                    
                    charts.append({
                        'title': 'Alerts Over Time',
                        'path': f"charts/{chart_path.name}"
                    })
            
            # 3. System metrics chart
            if metrics:
                # Convert to DataFrame for easier manipulation
                df = pd.DataFrame(metrics)
                df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
                
                # Resample to hourly averages if we have a lot of data
                if len(df) > 100:
                    df = df.set_index('datetime').resample('1H').mean().reset_index()
                
                fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
                
                # CPU usage
                ax1.plot(df['datetime'], df['cpu_percent'], color='#e74c3c', linewidth=2)
                ax1.set_title('CPU Usage (%)', fontweight='bold')
                ax1.set_ylabel('Percentage')
                ax1.grid(True, alpha=0.3)
                
                # Memory usage
                ax2.plot(df['datetime'], df['memory_percent'], color='#3498db', linewidth=2)
                ax2.set_title('Memory Usage (%)', fontweight='bold')
                ax2.set_ylabel('Percentage')
                ax2.grid(True, alpha=0.3)
                
                # Disk usage
                ax3.plot(df['datetime'], df['disk_percent'], color='#f39c12', linewidth=2)
                ax3.set_title('Disk Usage (%)', fontweight='bold')
                ax3.set_ylabel('Percentage')
                ax3.grid(True, alpha=0.3)
                
                # Process count
                ax4.plot(df['datetime'], df['process_count'], color='#27ae60', linewidth=2)
                ax4.set_title('Process Count', fontweight='bold')
                ax4.set_ylabel('Count')
                ax4.grid(True, alpha=0.3)
                
                # Format x-axis for all subplots
                for ax in [ax1, ax2, ax3, ax4]:
                    ax.xaxis.set_major_formatter(mdates.DateFormatter('%m/%d %H:%M'))
                    plt.setp(ax.xaxis.get_majorticklabels(), rotation=45)
                
                plt.tight_layout()
                
                chart_path = self.output_dir / "charts" / f"system_metrics_{timestamp}.png"
                plt.savefig(chart_path, dpi=300, bbox_inches='tight')
                plt.close()
                
                charts.append({
                    'title': 'System Performance Metrics',
                    'path': f"charts/{chart_path.name}"
                })
            
        except Exception as e:
            logger.error(f"Error generating charts: {e}")
        
        return charts
    
    def _calculate_summary_stats(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate summary statistics"""
        total_alerts = len(alerts)
        critical_alerts = len([a for a in alerts if a.get('severity') == 'CRITICAL'])
        high_alerts = len([a for a in alerts if a.get('severity') == 'HIGH'])
        
        # Calculate risk score
        risk_score = min(100, (critical_alerts * 20) + (high_alerts * 10))
        
        # Count unique systems
        systems = set(a.get('system_name', 'Unknown') for a in alerts)
        systems_count = len(systems)
        
        return {
            'total_alerts': total_alerts,
            'critical_alerts': critical_alerts,
            'high_alerts': high_alerts,
            'risk_score': risk_score,
            'systems_count': systems_count
        }
    
    def _generate_recommendations(self, alerts: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Generate security recommendations based on alerts"""
        immediate = []
        longterm = []
        
        # Count alert types
        alert_types = {}
        for alert in alerts:
            alert_type = alert.get('type', 'unknown')
            alert_types[alert_type] = alert_types.get(alert_type, 0) + 1
        
        # Generate recommendations based on patterns
        if alert_types.get('lolbin_detection', 0) > 5:
            immediate.append("Investigate LOLBins detections - possible advanced persistent threat")
            longterm.append("Implement application whitelisting to prevent LOLBins abuse")
        
        if alert_types.get('high_cpu', 0) > 10:
            immediate.append("Investigate sustained high CPU usage - possible cryptomining or DoS attack")
            longterm.append("Implement CPU usage monitoring and alerting thresholds")
        
        if alert_types.get('high_memory', 0) > 10:
            immediate.append("Investigate memory usage patterns - possible memory leak or malware")
            longterm.append("Implement memory monitoring and automatic process termination")
        
        if len([a for a in alerts if a.get('severity') == 'CRITICAL']) > 0:
            immediate.append("Address all critical alerts immediately")
            immediate.append("Review and update incident response procedures")
        
        # Default recommendations
        if not immediate:
            immediate.append("Continue monitoring - no immediate threats detected")
        
        longterm.extend([
            "Regular security awareness training for staff",
            "Keep all systems updated with latest security patches",
            "Implement network segmentation and access controls",
            "Regular backup and disaster recovery testing"
        ])
        
        return {
            'immediate': immediate,
            'longterm': longterm
        }
    
    def generate_summary_report(self, days: int = 30) -> Optional[Path]:
        """Generate a comprehensive HTML summary report"""
        try:
            logger.info(f"Generating summary report for the past {days} days")
            
            # Load data
            alerts = self._load_alerts(days)
            metrics = self._load_metrics(days)
            
            if not alerts and not metrics:
                logger.warning("No data found for the specified period")
                return None
            
            # Generate charts
            charts = self._generate_charts(alerts, metrics)
            
            # Calculate statistics
            summary = self._calculate_summary_stats(alerts)
            
            # Get critical alerts
            critical_alerts = [a for a in alerts if a.get('severity') == 'CRITICAL'][:10]
            
            # Generate recommendations
            recommendations = self._generate_recommendations(alerts)
            
            # Prepare template data
            template_data = {
                'report_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'period_description': f"Last {days} days" if days > 0 else "All time",
                'summary': summary,
                'charts': charts,
                'critical_alerts': critical_alerts,
                'recommendations': recommendations
            }
            
            # Load and render template
            template_path = self.output_dir / "templates" / "main_report.html"
            with open(template_path, 'r') as f:
                template = Template(f.read())
            
            rendered_html = template.render(**template_data)
            
            # Save report
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_filename = f"security_summary_{timestamp}.html"
            report_path = self.output_dir / report_filename
            
            with open(report_path, 'w') as f:
                f.write(rendered_html)
            
            logger.info(f"Summary report generated: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"Error generating summary report: {e}")
            return None
    
    def generate_csv_report(self, days: int = 30) -> Optional[Path]:
        """Generate a comprehensive CSV report"""
        try:
            logger.info(f"Generating CSV report for the past {days} days")
            
            alerts = self._load_alerts(days)
            
            if not alerts:
                logger.warning("No alerts found for the specified period")
                return None
            
            # Prepare CSV data
            csv_data = []
            for alert in alerts:
                row = {
                    'timestamp': alert.get('timestamp_formatted', ''),
                    'id': alert.get('id', ''),
                    'type': alert.get('type', ''),
                    'severity': alert.get('severity', ''),
                    'binary': alert.get('binary', ''),
                    'command': alert.get('command', ''),
                    'process_id': alert.get('process_id', ''),
                    'user_name': alert.get('user_name', ''),
                    'system_name': alert.get('system_name', ''),
                    'mitre_id': alert.get('mitre_id', ''),
                    'mitre_link': alert.get('mitre_link', ''),
                    'details': alert.get('details', ''),
                    'status': alert.get('status', '')
                }
                csv_data.append(row)
            
            # Write CSV file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            csv_filename = f"security_report_{timestamp}.csv"
            csv_path = self.output_dir / csv_filename
            
            with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                if csv_data:
                    fieldnames = csv_data[0].keys()
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(csv_data)
            
            logger.info(f"CSV report generated: {csv_path}")
            return csv_path
            
        except Exception as e:
            logger.error(f"Error generating CSV report: {e}")
            return None
    
    def generate_json_report(self, days: int = 30) -> Optional[Path]:
        """Generate a comprehensive JSON report"""
        try:
            logger.info(f"Generating JSON report for the past {days} days")
            
            alerts = self._load_alerts(days)
            metrics = self._load_metrics(days)
            
            # Prepare report data
            report_data = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'period_days': days,
                    'period_description': f"Last {days} days" if days > 0 else "All time",
                    'generator_version': '2.0.0'
                },
                'summary': self._calculate_summary_stats(alerts),
                'alerts': alerts,
                'metrics': metrics[-100:] if len(metrics) > 100 else metrics,  # Last 100 metrics
                'recommendations': self._generate_recommendations(alerts),
                'statistics': {
                    'alerts_by_type': {},
                    'alerts_by_severity': {},
                    'alerts_by_system': {}
                }
            }
            
            # Calculate additional statistics
            for alert in alerts:
                alert_type = alert.get('type', 'unknown')
                severity = alert.get('severity', 'UNKNOWN')
                system = alert.get('system_name', 'Unknown')
                
                report_data['statistics']['alerts_by_type'][alert_type] = (
                    report_data['statistics']['alerts_by_type'].get(alert_type, 0) + 1
                )
                report_data['statistics']['alerts_by_severity'][severity] = (
                    report_data['statistics']['alerts_by_severity'].get(severity, 0) + 1
                )
                report_data['statistics']['alerts_by_system'][system] = (
                    report_data['statistics']['alerts_by_system'].get(system, 0) + 1
                )
            
            # Write JSON file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_filename = f"security_report_{timestamp}.json"
            json_path = self.output_dir / json_filename
            
            with open(json_path, 'w', encoding='utf-8') as jsonfile:
                json.dump(report_data, jsonfile, indent=2, default=str)
            
            logger.info(f"JSON report generated: {json_path}")
            return json_path
            
        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")
            return None
    
    def cleanup_old_reports(self, retention_days: int = 30):
        """Clean up old report files"""
        try:
            cutoff_time = datetime.now() - timedelta(days=retention_days)
            
            for file_path in self.output_dir.rglob("*"):
                if file_path.is_file():
                    file_time = datetime.fromtimestamp(file_path.stat().st_mtime)
                    if file_time < cutoff_time:
                        file_path.unlink()
                        logger.debug(f"Deleted old report file: {file_path}")
            
            logger.info(f"Cleaned up reports older than {retention_days} days")
            
        except Exception as e:
            logger.error(f"Error cleaning up old reports: {e}")