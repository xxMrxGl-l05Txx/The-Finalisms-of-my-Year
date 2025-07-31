"""
Enhanced security monitoring with comprehensive system analysis
"""
import json
import os
import time
import logging
import psutil
import platform
import socket
import subprocess
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import hashlib
import re

from ..core.config import ConfigManager
from ..core.database import DatabaseManager
from ..core.exceptions import MonitoringError

logger = logging.getLogger(__name__)

@dataclass
class ProcessInfo:
    """Information about a running process"""
    pid: int
    name: str
    exe: str
    cmdline: List[str]
    username: str
    cpu_percent: float
    memory_percent: float
    create_time: float
    connections: List[Dict[str, Any]]

@dataclass
class NetworkConnection:
    """Information about a network connection"""
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    status: str
    pid: int

@dataclass
class FileSystemEvent:
    """Information about a file system event"""
    path: str
    event_type: str
    timestamp: float
    process_name: str
    process_pid: int

class EnhancedSecurityMonitor:
    """Enhanced security monitor with comprehensive system analysis"""
    
    def __init__(self, config_manager: ConfigManager, db_manager: DatabaseManager):
        self.config_manager = config_manager
        self.db_manager = db_manager
        self.config = config_manager.get_config()
        
        # Load LOLBins rules
        self.lolbins_rules = self._load_lolbins_rules()
        
        # Monitoring state
        self.running = False
        self.last_metrics = {}
        self.baseline_metrics = {}
        self.suspicious_processes = set()
        self.monitored_paths = set()
        
        # Performance tracking
        self.performance_history = []
        
        # Initialize baseline
        self._establish_baseline()
        
        logger.info("Enhanced security monitor initialized")
    
    def _load_lolbins_rules(self) -> List[Dict[str, Any]]:
        """Load LOLBins detection rules"""
        rules_file = Path(__file__).parent / "lolbins_rules.json"
        try:
            with open(rules_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading LOLBins rules: {e}")
            return []
    
    def _establish_baseline(self):
        """Establish baseline system metrics"""
        try:
            baseline_samples = []
            for _ in range(10):
                metrics = self._collect_basic_metrics()
                baseline_samples.append(metrics)
                time.sleep(1)
            
            # Calculate baseline averages
            self.baseline_metrics = {
                'cpu_percent': sum(m['cpu_percent'] for m in baseline_samples) / len(baseline_samples),
                'memory_percent': sum(m['memory_percent'] for m in baseline_samples) / len(baseline_samples),
                'disk_percent': sum(m['disk_percent'] for m in baseline_samples) / len(baseline_samples),
                'process_count': sum(m['process_count'] for m in baseline_samples) / len(baseline_samples),
                'network_connections': sum(m['network_connections'] for m in baseline_samples) / len(baseline_samples)
            }
            
            logger.info(f"Baseline established: {self.baseline_metrics}")
        except Exception as e:
            logger.error(f"Error establishing baseline: {e}")
            self.baseline_metrics = {}
    
    def _collect_basic_metrics(self) -> Dict[str, Any]:
        """Collect basic system metrics"""
        try:
            # CPU and memory
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Network
            network_io = psutil.net_io_counters()
            network_connections = len(psutil.net_connections())
            
            # Processes
            process_count = len(psutil.pids())
            
            return {
                'timestamp': time.time(),
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'disk_percent': disk.percent,
                'network_bytes_sent': network_io.bytes_sent,
                'network_bytes_recv': network_io.bytes_recv,
                'network_connections': network_connections,
                'process_count': process_count,
                'load_average': os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]
            }
        except Exception as e:
            logger.error(f"Error collecting basic metrics: {e}")
            return {}
    
    def _collect_process_information(self) -> List[ProcessInfo]:
        """Collect detailed process information"""
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 
                                           'cpu_percent', 'memory_percent', 'create_time']):
                try:
                    proc_info = proc.info
                    
                    # Get network connections for this process
                    connections = []
                    try:
                        for conn in proc.connections():
                            connections.append({
                                'local_address': conn.laddr.ip if conn.laddr else '',
                                'local_port': conn.laddr.port if conn.laddr else 0,
                                'remote_address': conn.raddr.ip if conn.raddr else '',
                                'remote_port': conn.raddr.port if conn.raddr else 0,
                                'status': conn.status
                            })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    
                    process_info = ProcessInfo(
                        pid=proc_info['pid'],
                        name=proc_info['name'] or '',
                        exe=proc_info['exe'] or '',
                        cmdline=proc_info['cmdline'] or [],
                        username=proc_info['username'] or '',
                        cpu_percent=proc_info['cpu_percent'] or 0,
                        memory_percent=proc_info['memory_percent'] or 0,
                        create_time=proc_info['create_time'] or 0,
                        connections=connections
                    )
                    
                    processes.append(process_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                    
        except Exception as e:
            logger.error(f"Error collecting process information: {e}")
        
        return processes
    
    def _analyze_lolbins_activity(self, processes: List[ProcessInfo]) -> List[Dict[str, Any]]:
        """Analyze processes for LOLBins activity"""
        alerts = []
        
        for process in processes:
            for rule in self.lolbins_rules:
                binary_name = rule.get('binary', '').lower()
                
                # Check if process matches LOLBin
                if (binary_name in process.name.lower() or 
                    binary_name in process.exe.lower()):
                    
                    # Check command line for suspicious patterns
                    cmdline_str = ' '.join(process.cmdline).lower()
                    
                    for pattern in rule.get('command_patterns', []):
                        if pattern.lower() in cmdline_str:
                            alert = {
                                'id': f"lolbin-{process.pid}-{int(time.time())}",
                                'timestamp': time.time(),
                                'type': 'lolbin_detection',
                                'severity': self._determine_severity(rule, pattern),
                                'binary': process.name,
                                'command': ' '.join(process.cmdline),
                                'process_id': process.pid,
                                'user_name': process.username,
                                'system_name': platform.node(),
                                'mitre_id': rule.get('mitre_attack_id'),
                                'mitre_link': rule.get('mitre_link'),
                                'details': f"Suspicious {binary_name} execution detected: {rule.get('description', '')}",
                                'metadata': {
                                    'rule': rule,
                                    'pattern_matched': pattern,
                                    'process_info': asdict(process)
                                }
                            }
                            alerts.append(alert)
                            break
        
        return alerts
    
    def _determine_severity(self, rule: Dict[str, Any], pattern: str) -> str:
        """Determine alert severity based on rule and pattern"""
        # High-risk patterns
        high_risk_patterns = [
            'downloadstring', 'invoke-expression', 'iex', 'encoded',
            'bypass', 'hidden', 'noprofile', 'javascript:', 'http://', 'https://'
        ]
        
        # Check if pattern contains high-risk indicators
        pattern_lower = pattern.lower()
        if any(risk_pattern in pattern_lower for risk_pattern in high_risk_patterns):
            return 'CRITICAL'
        
        # Check parent process hints for additional context
        parent_hints = rule.get('parent_process_hints', [])
        if parent_hints:
            return 'HIGH'
        
        return 'MEDIUM'
    
    def _analyze_anomalies(self, current_metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze current metrics for anomalies"""
        alerts = []
        
        if not self.baseline_metrics:
            return alerts
        
        try:
            # CPU anomaly detection
            cpu_deviation = abs(current_metrics['cpu_percent'] - self.baseline_metrics['cpu_percent'])
            if cpu_deviation > 30:  # 30% deviation from baseline
                alerts.append({
                    'id': f"anomaly-cpu-{int(time.time())}",
                    'timestamp': time.time(),
                    'type': 'cpu_anomaly',
                    'severity': 'HIGH' if cpu_deviation > 50 else 'MEDIUM',
                    'details': f"CPU usage anomaly detected: {current_metrics['cpu_percent']:.1f}% (baseline: {self.baseline_metrics['cpu_percent']:.1f}%)",
                    'metadata': {
                        'current_value': current_metrics['cpu_percent'],
                        'baseline_value': self.baseline_metrics['cpu_percent'],
                        'deviation': cpu_deviation
                    }
                })
            
            # Memory anomaly detection
            memory_deviation = abs(current_metrics['memory_percent'] - self.baseline_metrics['memory_percent'])
            if memory_deviation > 25:  # 25% deviation from baseline
                alerts.append({
                    'id': f"anomaly-memory-{int(time.time())}",
                    'timestamp': time.time(),
                    'type': 'memory_anomaly',
                    'severity': 'HIGH' if memory_deviation > 40 else 'MEDIUM',
                    'details': f"Memory usage anomaly detected: {current_metrics['memory_percent']:.1f}% (baseline: {self.baseline_metrics['memory_percent']:.1f}%)",
                    'metadata': {
                        'current_value': current_metrics['memory_percent'],
                        'baseline_value': self.baseline_metrics['memory_percent'],
                        'deviation': memory_deviation
                    }
                })
            
            # Process count anomaly
            process_deviation = abs(current_metrics['process_count'] - self.baseline_metrics['process_count'])
            if process_deviation > 50:  # 50 process deviation
                alerts.append({
                    'id': f"anomaly-processes-{int(time.time())}",
                    'timestamp': time.time(),
                    'type': 'process_anomaly',
                    'severity': 'MEDIUM',
                    'details': f"Process count anomaly detected: {current_metrics['process_count']} (baseline: {self.baseline_metrics['process_count']:.0f})",
                    'metadata': {
                        'current_value': current_metrics['process_count'],
                        'baseline_value': self.baseline_metrics['process_count'],
                        'deviation': process_deviation
                    }
                })
                
        except Exception as e:
            logger.error(f"Error analyzing anomalies: {e}")
        
        return alerts
    
    def _check_thresholds(self, metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check if metrics exceed configured thresholds"""
        alerts = []
        config = self.config.monitoring
        
        # CPU threshold
        if metrics.get('cpu_percent', 0) > config.cpu_threshold:
            alerts.append({
                'id': f"threshold-cpu-{int(time.time())}",
                'timestamp': time.time(),
                'type': 'high_cpu',
                'severity': 'HIGH' if metrics['cpu_percent'] > 95 else 'MEDIUM',
                'details': f"CPU usage above threshold: {metrics['cpu_percent']:.1f}% (threshold: {config.cpu_threshold}%)",
                'value': metrics['cpu_percent']
            })
        
        # Memory threshold
        if metrics.get('memory_percent', 0) > config.memory_threshold:
            alerts.append({
                'id': f"threshold-memory-{int(time.time())}",
                'timestamp': time.time(),
                'type': 'high_memory',
                'severity': 'HIGH' if metrics['memory_percent'] > 95 else 'MEDIUM',
                'details': f"Memory usage above threshold: {metrics['memory_percent']:.1f}% (threshold: {config.memory_threshold}%)",
                'value': metrics['memory_percent']
            })
        
        # Disk threshold
        if metrics.get('disk_percent', 0) > config.disk_threshold:
            alerts.append({
                'id': f"threshold-disk-{int(time.time())}",
                'timestamp': time.time(),
                'type': 'high_disk',
                'severity': 'HIGH' if metrics['disk_percent'] > 98 else 'MEDIUM',
                'details': f"Disk usage above threshold: {metrics['disk_percent']:.1f}% (threshold: {config.disk_threshold}%)",
                'value': metrics['disk_percent']
            })
        
        return alerts
    
    def _analyze_network_activity(self, processes: List[ProcessInfo]) -> List[Dict[str, Any]]:
        """Analyze network activity for suspicious patterns"""
        alerts = []
        
        try:
            # Check for processes with unusual network activity
            for process in processes:
                if len(process.connections) > 10:  # Process with many connections
                    # Check for connections to suspicious ports or addresses
                    suspicious_connections = []
                    
                    for conn in process.connections:
                        # Check for connections to common malware ports
                        suspicious_ports = [4444, 5555, 6666, 7777, 8080, 9999]
                        if conn.get('remote_port') in suspicious_ports:
                            suspicious_connections.append(conn)
                        
                        # Check for connections to private IP ranges from public processes
                        remote_ip = conn.get('remote_address', '')
                        if remote_ip and not self._is_private_ip(remote_ip):
                            if process.name.lower() in ['cmd.exe', 'powershell.exe', 'certutil.exe']:
                                suspicious_connections.append(conn)
                    
                    if suspicious_connections:
                        alerts.append({
                            'id': f"network-suspicious-{process.pid}-{int(time.time())}",
                            'timestamp': time.time(),
                            'type': 'suspicious_network_activity',
                            'severity': 'HIGH',
                            'binary': process.name,
                            'process_id': process.pid,
                            'details': f"Suspicious network activity detected from {process.name} (PID: {process.pid})",
                            'metadata': {
                                'process_info': asdict(process),
                                'suspicious_connections': suspicious_connections
                            }
                        })
        
        except Exception as e:
            logger.error(f"Error analyzing network activity: {e}")
        
        return alerts
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is in private range"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False
    
    def _collect_system_info(self) -> Dict[str, Any]:
        """Collect comprehensive system information"""
        try:
            boot_time = psutil.boot_time()
            
            system_info = {
                'hostname': platform.node(),
                'os_name': platform.system(),
                'os_version': platform.version(),
                'cpu_count': psutil.cpu_count(),
                'total_memory': psutil.virtual_memory().total,
                'disk_size': psutil.disk_usage('/').total,
                'last_boot': boot_time,
                'uptime_seconds': time.time() - boot_time,
                'architecture': platform.architecture()[0],
                'processor': platform.processor(),
                'python_version': platform.python_version()
            }
            
            return system_info
        except Exception as e:
            logger.error(f"Error collecting system info: {e}")
            return {}
    
    def run_monitoring_cycle(self) -> Dict[str, Any]:
        """Run a complete monitoring cycle with enhanced analysis"""
        cycle_start = time.time()
        
        try:
            logger.debug("Starting enhanced monitoring cycle")
            
            # Collect basic metrics
            metrics = self._collect_basic_metrics()
            if not metrics:
                raise MonitoringError("Failed to collect basic metrics")
            
            # Store metrics in database
            self.db_manager.insert_metrics(metrics)
            
            # Collect process information
            processes = self._collect_process_information()
            
            # Analyze for various types of threats
            all_alerts = []
            
            # Threshold-based alerts
            threshold_alerts = self._check_thresholds(metrics)
            all_alerts.extend(threshold_alerts)
            
            # LOLBins detection
            if self.config.monitoring.enable_lolbin_detection:
                lolbin_alerts = self._analyze_lolbins_activity(processes)
                all_alerts.extend(lolbin_alerts)
            
            # Anomaly detection
            anomaly_alerts = self._analyze_anomalies(metrics)
            all_alerts.extend(anomaly_alerts)
            
            # Network analysis
            network_alerts = self._analyze_network_activity(processes)
            all_alerts.extend(network_alerts)
            
            # Store alerts in database
            for alert in all_alerts:
                self.db_manager.insert_alert(alert)
            
            # Update performance tracking
            cycle_time = time.time() - cycle_start
            self.performance_history.append({
                'timestamp': time.time(),
                'cycle_time': cycle_time,
                'metrics_collected': len(metrics),
                'processes_analyzed': len(processes),
                'alerts_generated': len(all_alerts)
            })
            
            # Keep only last 100 performance records
            if len(self.performance_history) > 100:
                self.performance_history = self.performance_history[-100:]
            
            self.last_metrics = metrics
            
            result = {
                'metrics': metrics,
                'alerts': all_alerts,
                'processes_analyzed': len(processes),
                'cycle_time': cycle_time,
                'system_info': self._collect_system_info()
            }
            
            logger.debug(f"Monitoring cycle completed in {cycle_time:.2f}s, {len(all_alerts)} alerts generated")
            return result
            
        except Exception as e:
            logger.error(f"Error in monitoring cycle: {e}")
            raise MonitoringError(f"Monitoring cycle failed: {e}")
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get monitoring performance statistics"""
        if not self.performance_history:
            return {}
        
        cycle_times = [p['cycle_time'] for p in self.performance_history]
        
        return {
            'average_cycle_time': sum(cycle_times) / len(cycle_times),
            'max_cycle_time': max(cycle_times),
            'min_cycle_time': min(cycle_times),
            'total_cycles': len(self.performance_history),
            'last_cycle_time': cycle_times[-1] if cycle_times else 0
        }
    
    def start(self):
        """Start the monitoring system"""
        self.running = True
        logger.info("Enhanced security monitor started")
    
    def stop(self):
        """Stop the monitoring system"""
        self.running = False
        logger.info("Enhanced security monitor stopped")