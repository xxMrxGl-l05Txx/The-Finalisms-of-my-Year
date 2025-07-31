"""
Enhanced service runner with improved orchestration and monitoring
"""
import os
import sys
import time
import logging
import threading
import signal
import argparse
import schedule
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import psutil

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import ConfigManager
from core.database import DatabaseManager
from core.exceptions import SecurityMonitoringError
from monitor.enhanced_monitor import EnhancedSecurityMonitor
from detection.enhanced_detector import EnhancedSecurityDetector
from alerting.enhanced_dispatcher import EnhancedAlertDispatcher
from api.enhanced_api import EnhancedSecurityAPIServer
from reporting.enhanced_report_generator import EnhancedSecurityReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_monitoring.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("EnhancedServiceRunner")

class HealthMonitor:
    """Monitors the health of all system components"""
    
    def __init__(self):
        self.component_health = {}
        self.last_check = time.time()
    
    def check_component_health(self, component_name: str, component) -> bool:
        """Check if a component is healthy"""
        try:
            if hasattr(component, 'get_performance_stats'):
                stats = component.get_performance_stats()
                self.component_health[component_name] = {
                    'status': 'healthy',
                    'last_check': time.time(),
                    'stats': stats
                }
                return True
            else:
                self.component_health[component_name] = {
                    'status': 'healthy',
                    'last_check': time.time(),
                    'stats': {}
                }
                return True
        except Exception as e:
            self.component_health[component_name] = {
                'status': 'unhealthy',
                'last_check': time.time(),
                'error': str(e)
            }
            return False
    
    def get_overall_health(self) -> Dict[str, Any]:
        """Get overall system health status"""
        healthy_components = sum(1 for h in self.component_health.values() if h['status'] == 'healthy')
        total_components = len(self.component_health)
        
        return {
            'overall_status': 'healthy' if healthy_components == total_components else 'degraded',
            'healthy_components': healthy_components,
            'total_components': total_components,
            'components': self.component_health,
            'last_check': self.last_check
        }

class EnhancedSecurityServiceRunner:
    """Enhanced service runner with comprehensive monitoring and management"""
    
    def __init__(self, config_file: str = "config.json"):
        # Initialize core components
        self.config_manager = ConfigManager(config_file)
        self.db_manager = DatabaseManager()
        self.config = self.config_manager.get_config()
        
        # Initialize monitoring components
        self.monitor = EnhancedSecurityMonitor(self.config_manager, self.db_manager)
        self.detector = EnhancedSecurityDetector(self.config_manager, self.db_manager)
        self.alert_dispatcher = EnhancedAlertDispatcher(self.config_manager, self.db_manager)
        self.api_server = EnhancedSecurityAPIServer(self.config_manager, self.db_manager)
        self.report_generator = EnhancedSecurityReportGenerator(self.db_manager)
        
        # Service state
        self.running = False
        self.threads = {}
        self.health_monitor = HealthMonitor()
        
        # Performance tracking
        self.service_stats = {
            'start_time': None,
            'cycles_completed': 0,
            'total_alerts_processed': 0,
            'total_reports_generated': 0,
            'last_cycle_time': 0,
            'average_cycle_time': 0
        }
        
        # Data storage
        self.metrics_history = []
        self.recent_alerts = []
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        logger.info("Enhanced security service runner initialized")
    
    def _signal_handler(self, sig, frame):
        """Handle termination signals gracefully"""
        logger.info(f"Received signal {sig}, initiating graceful shutdown...")
        self.stop()
    
    def _monitoring_loop(self):
        """Main monitoring loop with enhanced error handling"""
        logger.info("Enhanced monitoring loop started")
        
        while self.running:
            cycle_start = time.time()
            
            try:
                # Run monitoring cycle
                result = self.monitor.run_monitoring_cycle()
                
                if not result:
                    logger.warning("Monitoring cycle returned no results")
                    time.sleep(5)
                    continue
                
                # Store metrics
                metrics = result.get('metrics', {})
                if metrics:
                    self.metrics_history.append(metrics)
                    
                    # Keep history manageable
                    if len(self.metrics_history) > 1000:
                        self.metrics_history = self.metrics_history[-1000:]
                
                # Process alerts from monitoring
                monitoring_alerts = result.get('alerts', [])
                
                # Run threat detection
                try:
                    processes = result.get('processes', [])
                    detected_threats = self.detector.detect_threats(
                        self.metrics_history, 
                        self.recent_alerts,
                        processes
                    )
                    
                    # Combine all alerts
                    all_alerts = monitoring_alerts + detected_threats
                    
                except Exception as e:
                    logger.error(f"Error in threat detection: {e}")
                    all_alerts = monitoring_alerts
                
                # Dispatch alerts
                if all_alerts:
                    try:
                        self.alert_dispatcher.dispatch_bulk_alerts(all_alerts)
                        self.recent_alerts.extend(all_alerts)
                        self.service_stats['total_alerts_processed'] += len(all_alerts)
                        
                        # Keep recent alerts manageable
                        if len(self.recent_alerts) > 500:
                            self.recent_alerts = self.recent_alerts[-500:]
                            
                    except Exception as e:
                        logger.error(f"Error dispatching alerts: {e}")
                
                # Update performance statistics
                cycle_time = time.time() - cycle_start
                self.service_stats['cycles_completed'] += 1
                self.service_stats['last_cycle_time'] = cycle_time
                
                # Calculate average cycle time
                if self.service_stats['cycles_completed'] > 0:
                    total_time = time.time() - self.service_stats['start_time']
                    self.service_stats['average_cycle_time'] = (
                        total_time / self.service_stats['cycles_completed']
                    )
                
                # Check component health
                self.health_monitor.check_component_health('monitor', self.monitor)
                self.health_monitor.check_component_health('detector', self.detector)
                self.health_monitor.check_component_health('dispatcher', self.alert_dispatcher)
                
                logger.debug(f"Monitoring cycle completed in {cycle_time:.2f}s")
                
                # Sleep for configured interval
                sleep_time = max(1, self.config.monitoring.monitor_interval - cycle_time)
                time.sleep(sleep_time)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(10)  # Wait before retrying
    
    def _api_loop(self):
        """API server loop"""
        try:
            logger.info("Starting API server")
            self.api_server.start()
        except Exception as e:
            logger.error(f"Error in API server: {e}")
    
    def _reporting_loop(self):
        """Automated reporting loop"""
        logger.info("Reporting loop started")
        
        # Schedule daily reports
        schedule.every().day.at("06:00").do(self._generate_daily_report)
        
        # Schedule weekly reports
        schedule.every().monday.at("07:00").do(self._generate_weekly_report)
        
        # Schedule cleanup
        schedule.every().day.at("02:00").do(self._cleanup_old_data)
        
        while self.running:
            try:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Error in reporting loop: {e}")
                time.sleep(300)  # Wait 5 minutes before retrying
    
    def _generate_daily_report(self):
        """Generate daily security report"""
        try:
            logger.info("Generating daily security report")
            report_path = self.report_generator.generate_summary_report(days=1)
            
            if report_path:
                self.service_stats['total_reports_generated'] += 1
                logger.info(f"Daily report generated: {report_path}")
            else:
                logger.warning("Failed to generate daily report")
                
        except Exception as e:
            logger.error(f"Error generating daily report: {e}")
    
    def _generate_weekly_report(self):
        """Generate weekly security report"""
        try:
            logger.info("Generating weekly security report")
            report_path = self.report_generator.generate_summary_report(days=7)
            
            if report_path:
                self.service_stats['total_reports_generated'] += 1
                logger.info(f"Weekly report generated: {report_path}")
            else:
                logger.warning("Failed to generate weekly report")
                
        except Exception as e:
            logger.error(f"Error generating weekly report: {e}")
    
    def _cleanup_old_data(self):
        """Clean up old data based on retention policy"""
        try:
            logger.info("Starting data cleanup")
            
            # Clean up database
            retention_days = self.config.data_retention_days
            if self.config.enable_auto_cleanup:
                success = self.db_manager.cleanup_old_data(retention_days)
                if success:
                    logger.info(f"Database cleanup completed (retention: {retention_days} days)")
                else:
                    logger.warning("Database cleanup failed")
            
            # Clean up old reports
            self.report_generator.cleanup_old_reports(retention_days)
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
    
    def _health_check_loop(self):
        """Health monitoring loop"""
        logger.info("Health check loop started")
        
        while self.running:
            try:
                # Check system resources
                cpu_percent = psutil.cpu_percent(interval=1)
                memory_percent = psutil.virtual_memory().percent
                disk_percent = psutil.disk_usage('/').percent
                
                # Log warnings for high resource usage
                if cpu_percent > 90:
                    logger.warning(f"High CPU usage detected: {cpu_percent:.1f}%")
                
                if memory_percent > 90:
                    logger.warning(f"High memory usage detected: {memory_percent:.1f}%")
                
                if disk_percent > 95:
                    logger.warning(f"High disk usage detected: {disk_percent:.1f}%")
                
                # Check component health
                overall_health = self.health_monitor.get_overall_health()
                if overall_health['overall_status'] != 'healthy':
                    logger.warning(f"System health degraded: {overall_health}")
                
                time.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in health check: {e}")
                time.sleep(60)
    
    def start(self):
        """Start all service components"""
        if self.running:
            logger.warning("Service is already running")
            return
        
        logger.info("Starting enhanced security monitoring service...")
        self.running = True
        self.service_stats['start_time'] = time.time()
        
        try:
            # Start alert dispatcher
            self.alert_dispatcher.start()
            
            # Start monitoring thread
            self.threads['monitoring'] = threading.Thread(
                target=self._monitoring_loop, 
                daemon=True,
                name="MonitoringThread"
            )
            self.threads['monitoring'].start()
            
            # Start API server thread
            self.threads['api'] = threading.Thread(
                target=self._api_loop, 
                daemon=True,
                name="APIThread"
            )
            self.threads['api'].start()
            
            # Start reporting thread
            self.threads['reporting'] = threading.Thread(
                target=self._reporting_loop, 
                daemon=True,
                name="ReportingThread"
            )
            self.threads['reporting'].start()
            
            # Start health check thread
            self.threads['health'] = threading.Thread(
                target=self._health_check_loop, 
                daemon=True,
                name="HealthCheckThread"
            )
            self.threads['health'].start()
            
            logger.info("All service components started successfully")
            
        except Exception as e:
            logger.error(f"Error starting service components: {e}")
            self.stop()
            raise SecurityMonitoringError(f"Failed to start service: {e}")
    
    def stop(self):
        """Stop all service components gracefully"""
        if not self.running:
            return
        
        logger.info("Stopping enhanced security monitoring service...")
        self.running = False
        
        try:
            # Stop alert dispatcher
            self.alert_dispatcher.stop()
            
            # Wait for threads to terminate
            for name, thread in self.threads.items():
                if thread.is_alive():
                    logger.info(f"Waiting for {name} thread to terminate...")
                    thread.join(timeout=10)
                    
                    if thread.is_alive():
                        logger.warning(f"{name} thread did not terminate gracefully")
            
            # Final cleanup
            if self.config.enable_auto_cleanup:
                self._cleanup_old_data()
            
            # Log final statistics
            uptime = time.time() - self.service_stats['start_time']
            logger.info(f"Service stopped. Uptime: {uptime:.1f}s, Cycles: {self.service_stats['cycles_completed']}")
            
        except Exception as e:
            logger.error(f"Error during service shutdown: {e}")
        
        logger.info("Enhanced security monitoring service stopped")
    
    def get_service_status(self) -> Dict[str, Any]:
        """Get comprehensive service status"""
        uptime = time.time() - self.service_stats['start_time'] if self.service_stats['start_time'] else 0
        
        return {
            'running': self.running,
            'uptime_seconds': uptime,
            'statistics': self.service_stats,
            'health': self.health_monitor.get_overall_health(),
            'threads': {name: thread.is_alive() for name, thread in self.threads.items()},
            'configuration': {
                'monitoring_interval': self.config.monitoring.monitor_interval,
                'data_retention_days': self.config.data_retention_days,
                'auto_cleanup_enabled': self.config.enable_auto_cleanup
            }
        }
    
    def run(self):
        """Run the service with proper error handling"""
        try:
            self.start()
            
            # Keep main thread alive
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received")
        except Exception as e:
            logger.error(f"Unexpected error in service runner: {e}")
        finally:
            self.stop()

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Enhanced Security Monitoring Service")
    parser.add_argument("--config", default="config.json", help="Configuration file path")
    parser.add_argument("--daemon", action="store_true", help="Run as daemon/service")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    args = parser.parse_args()
    
    # Set log level
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # Create and run service
    try:
        service = EnhancedSecurityServiceRunner(args.config)
        service.run()
    except Exception as e:
        logger.error(f"Failed to start service: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()