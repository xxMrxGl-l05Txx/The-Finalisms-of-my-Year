"""
Enhanced alert dispatcher with multiple notification channels and rate limiting
"""
import json
import logging
import os
import time
import smtplib
import requests
from datetime import datetime, timedelta
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from typing import Dict, List, Any, Optional
from collections import defaultdict, deque
import threading
from queue import Queue, Empty

from ..core.config import ConfigManager
from ..core.database import DatabaseManager
from ..core.exceptions import AlertingError

logger = logging.getLogger(__name__)

class RateLimiter:
    """Rate limiter for alerts to prevent spam"""
    
    def __init__(self, max_alerts_per_hour: int = 100):
        self.max_alerts_per_hour = max_alerts_per_hour
        self.alert_timestamps = deque()
        self.lock = threading.Lock()
    
    def can_send_alert(self) -> bool:
        """Check if we can send an alert based on rate limits"""
        with self.lock:
            now = time.time()
            hour_ago = now - 3600
            
            # Remove timestamps older than 1 hour
            while self.alert_timestamps and self.alert_timestamps[0] < hour_ago:
                self.alert_timestamps.popleft()
            
            # Check if we're under the limit
            if len(self.alert_timestamps) < self.max_alerts_per_hour:
                self.alert_timestamps.append(now)
                return True
            
            return False

class AlertCooldown:
    """Manages cooldown periods for similar alerts"""
    
    def __init__(self, cooldown_seconds: int = 300):
        self.cooldown_seconds = cooldown_seconds
        self.last_alerts = {}
        self.lock = threading.Lock()
    
    def can_send_alert(self, alert_type: str, alert_key: str = None) -> bool:
        """Check if we can send an alert based on cooldown"""
        with self.lock:
            key = f"{alert_type}:{alert_key}" if alert_key else alert_type
            now = time.time()
            
            if key in self.last_alerts:
                if now - self.last_alerts[key] < self.cooldown_seconds:
                    return False
            
            self.last_alerts[key] = now
            return True

class EmailNotifier:
    """Email notification handler"""
    
    def __init__(self, config):
        self.smtp_server = config.email_smtp_server
        self.smtp_port = config.email_smtp_port
        self.username = config.email_username
        self.password = config.email_password
        self.enabled = config.enable_email_alerts and all([
            self.smtp_server, self.username, self.password
        ])
    
    def send_notification(self, alert: Dict[str, Any]) -> bool:
        """Send email notification"""
        if not self.enabled:
            return False
        
        try:
            msg = MimeMultipart()
            msg['From'] = self.username
            msg['To'] = self.username  # Send to self for now
            msg['Subject'] = f"Security Alert: {alert.get('type', 'Unknown')}"
            
            # Create email body
            body = self._create_email_body(alert)
            msg.attach(MimeText(body, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            
            logger.info(f"Email alert sent for {alert.get('id')}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False
    
    def _create_email_body(self, alert: Dict[str, Any]) -> str:
        """Create HTML email body"""
        severity = alert.get('severity', 'UNKNOWN')
        severity_color = {
            'CRITICAL': '#FF0000',
            'HIGH': '#FF6600',
            'MEDIUM': '#FFAA00',
            'LOW': '#00AA00'
        }.get(severity, '#666666')
        
        return f"""
        <html>
        <body>
            <h2 style="color: {severity_color};">Security Alert - {severity}</h2>
            <table border="1" cellpadding="5" cellspacing="0">
                <tr><td><strong>Alert ID:</strong></td><td>{alert.get('id', 'N/A')}</td></tr>
                <tr><td><strong>Type:</strong></td><td>{alert.get('type', 'N/A')}</td></tr>
                <tr><td><strong>Severity:</strong></td><td style="color: {severity_color};">{severity}</td></tr>
                <tr><td><strong>Timestamp:</strong></td><td>{datetime.fromtimestamp(alert.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
                <tr><td><strong>System:</strong></td><td>{alert.get('system_name', 'N/A')}</td></tr>
                <tr><td><strong>Details:</strong></td><td>{alert.get('details', 'N/A')}</td></tr>
                <tr><td><strong>Binary:</strong></td><td>{alert.get('binary', 'N/A')}</td></tr>
                <tr><td><strong>Command:</strong></td><td><code>{alert.get('command', 'N/A')}</code></td></tr>
            </table>
            <p><strong>Recommended Action:</strong> Investigate this alert immediately and take appropriate mitigation steps.</p>
        </body>
        </html>
        """

class WebhookNotifier:
    """Webhook notification handler"""
    
    def __init__(self, config):
        self.webhook_url = config.webhook_url
        self.enabled = config.enable_webhook_alerts and self.webhook_url
    
    def send_notification(self, alert: Dict[str, Any]) -> bool:
        """Send webhook notification"""
        if not self.enabled:
            return False
        
        try:
            payload = {
                'alert_id': alert.get('id'),
                'type': alert.get('type'),
                'severity': alert.get('severity'),
                'timestamp': alert.get('timestamp'),
                'details': alert.get('details'),
                'system': alert.get('system_name'),
                'binary': alert.get('binary'),
                'command': alert.get('command')
            }
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                logger.info(f"Webhook alert sent for {alert.get('id')}")
                return True
            else:
                logger.error(f"Webhook failed with status {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
            return False

class DesktopNotifier:
    """Desktop notification handler"""
    
    def __init__(self, config):
        self.enabled = config.enable_desktop_notifications
    
    def send_notification(self, alert: Dict[str, Any]) -> bool:
        """Send desktop notification"""
        if not self.enabled:
            return False
        
        try:
            # Try different notification methods based on platform
            import platform
            system = platform.system()
            
            title = f"Security Alert - {alert.get('severity', 'UNKNOWN')}"
            message = f"{alert.get('type', 'Unknown')}: {alert.get('details', '')}"
            
            if system == "Windows":
                return self._send_windows_notification(title, message)
            elif system == "Darwin":  # macOS
                return self._send_macos_notification(title, message)
            elif system == "Linux":
                return self._send_linux_notification(title, message)
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to send desktop notification: {e}")
            return False
    
    def _send_windows_notification(self, title: str, message: str) -> bool:
        """Send Windows notification"""
        try:
            import win10toast
            toaster = win10toast.ToastNotifier()
            toaster.show_toast(title, message, duration=10)
            return True
        except ImportError:
            # Fallback to basic notification
            try:
                import subprocess
                subprocess.run([
                    'powershell', '-Command',
                    f'Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show("{message}", "{title}")'
                ], check=True, capture_output=True)
                return True
            except:
                return False
    
    def _send_macos_notification(self, title: str, message: str) -> bool:
        """Send macOS notification"""
        try:
            import subprocess
            subprocess.run([
                'osascript', '-e',
                f'display notification "{message}" with title "{title}"'
            ], check=True, capture_output=True)
            return True
        except:
            return False
    
    def _send_linux_notification(self, title: str, message: str) -> bool:
        """Send Linux notification"""
        try:
            import subprocess
            subprocess.run([
                'notify-send', title, message
            ], check=True, capture_output=True)
            return True
        except:
            return False

class EnhancedAlertDispatcher:
    """Enhanced alert dispatcher with multiple channels and intelligent routing"""
    
    def __init__(self, config_manager: ConfigManager, db_manager: DatabaseManager):
        self.config_manager = config_manager
        self.db_manager = db_manager
        self.config = config_manager.get_config().alerting
        
        # Initialize rate limiting and cooldown
        self.rate_limiter = RateLimiter(self.config.max_alerts_per_hour)
        self.cooldown_manager = AlertCooldown(self.config.alert_cooldown_seconds)
        
        # Initialize notifiers
        self.notifiers = {}
        self._initialize_notifiers()
        
        # Alert queue for async processing
        self.alert_queue = Queue()
        self.processing_thread = None
        self.running = False
        
        # Statistics
        self.stats = {
            'total_alerts': 0,
            'alerts_sent': 0,
            'alerts_dropped': 0,
            'alerts_by_severity': defaultdict(int),
            'alerts_by_type': defaultdict(int),
            'notifier_stats': defaultdict(lambda: {'sent': 0, 'failed': 0})
        }
        
        logger.info("Enhanced alert dispatcher initialized")
    
    def _initialize_notifiers(self):
        """Initialize all notification channels"""
        try:
            if self.config.enable_email_alerts:
                self.notifiers['email'] = EmailNotifier(self.config)
            
            if self.config.enable_webhook_alerts:
                self.notifiers['webhook'] = WebhookNotifier(self.config)
            
            if self.config.enable_desktop_notifications:
                self.notifiers['desktop'] = DesktopNotifier(self.config)
            
            logger.info(f"Initialized {len(self.notifiers)} notifiers: {list(self.notifiers.keys())}")
            
        except Exception as e:
            logger.error(f"Error initializing notifiers: {e}")
    
    def start(self):
        """Start the alert processing thread"""
        if self.running:
            return
        
        self.running = True
        self.processing_thread = threading.Thread(target=self._process_alerts, daemon=True)
        self.processing_thread.start()
        logger.info("Alert dispatcher started")
    
    def stop(self):
        """Stop the alert processing thread"""
        self.running = False
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
        logger.info("Alert dispatcher stopped")
    
    def dispatch_alert(self, alert: Dict[str, Any]) -> bool:
        """Dispatch an alert through appropriate channels"""
        try:
            # Validate alert
            if not self._validate_alert(alert):
                logger.warning(f"Invalid alert format: {alert}")
                return False
            
            # Add to queue for async processing
            self.alert_queue.put(alert)
            self.stats['total_alerts'] += 1
            self.stats['alerts_by_severity'][alert.get('severity', 'UNKNOWN')] += 1
            self.stats['alerts_by_type'][alert.get('type', 'unknown')] += 1
            
            return True
            
        except Exception as e:
            logger.error(f"Error dispatching alert: {e}")
            return False
    
    def _process_alerts(self):
        """Process alerts from the queue"""
        while self.running:
            try:
                # Get alert from queue with timeout
                alert = self.alert_queue.get(timeout=1)
                
                # Process the alert
                self._process_single_alert(alert)
                
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing alert: {e}")
    
    def _process_single_alert(self, alert: Dict[str, Any]):
        """Process a single alert"""
        try:
            alert_id = alert.get('id', 'unknown')
            alert_type = alert.get('type', 'unknown')
            severity = alert.get('severity', 'UNKNOWN')
            
            # Check rate limiting
            if not self.rate_limiter.can_send_alert():
                logger.warning(f"Alert {alert_id} dropped due to rate limiting")
                self.stats['alerts_dropped'] += 1
                return
            
            # Check cooldown
            cooldown_key = f"{alert_type}:{alert.get('binary', '')}"
            if not self.cooldown_manager.can_send_alert(alert_type, cooldown_key):
                logger.debug(f"Alert {alert_id} dropped due to cooldown")
                self.stats['alerts_dropped'] += 1
                return
            
            # Determine which notifiers to use based on severity
            notifiers_to_use = self._select_notifiers(severity)
            
            # Send through selected notifiers
            success_count = 0
            for notifier_name in notifiers_to_use:
                if notifier_name in self.notifiers:
                    try:
                        success = self.notifiers[notifier_name].send_notification(alert)
                        if success:
                            success_count += 1
                            self.stats['notifier_stats'][notifier_name]['sent'] += 1
                        else:
                            self.stats['notifier_stats'][notifier_name]['failed'] += 1
                    except Exception as e:
                        logger.error(f"Error sending alert via {notifier_name}: {e}")
                        self.stats['notifier_stats'][notifier_name]['failed'] += 1
            
            if success_count > 0:
                self.stats['alerts_sent'] += 1
                logger.info(f"Alert {alert_id} sent via {success_count} notifiers")
            else:
                logger.warning(f"Alert {alert_id} failed to send via any notifier")
                self.stats['alerts_dropped'] += 1
            
        except Exception as e:
            logger.error(f"Error processing alert {alert.get('id', 'unknown')}: {e}")
    
    def _select_notifiers(self, severity: str) -> List[str]:
        """Select appropriate notifiers based on alert severity"""
        notifiers = []
        
        # Always use desktop notifications if enabled
        if 'desktop' in self.notifiers:
            notifiers.append('desktop')
        
        # Use email for HIGH and CRITICAL alerts
        if severity in ['HIGH', 'CRITICAL'] and 'email' in self.notifiers:
            notifiers.append('email')
        
        # Use webhook for all alerts if enabled
        if 'webhook' in self.notifiers:
            notifiers.append('webhook')
        
        return notifiers
    
    def _validate_alert(self, alert: Dict[str, Any]) -> bool:
        """Validate alert format"""
        required_fields = ['id', 'timestamp', 'type', 'severity']
        return all(field in alert for field in required_fields)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get dispatcher statistics"""
        return {
            'stats': dict(self.stats),
            'queue_size': self.alert_queue.qsize(),
            'running': self.running,
            'notifiers_enabled': list(self.notifiers.keys())
        }
    
    def dispatch_bulk_alerts(self, alerts: List[Dict[str, Any]]) -> List[bool]:
        """Dispatch multiple alerts"""
        results = []
        for alert in alerts:
            result = self.dispatch_alert(alert)
            results.append(result)
        return results