"""
Database management for the security monitoring system
"""
import sqlite3
import json
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Manages SQLite database for storing alerts and metrics"""
    
    def __init__(self, db_path: str = "security_monitoring.db"):
        self.db_path = Path(db_path)
        self.lock = threading.Lock()
        self._init_database()
    
    def _init_database(self):
        """Initialize database with required tables"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Create alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    binary TEXT,
                    command TEXT,
                    process_id INTEGER,
                    user_name TEXT,
                    system_name TEXT,
                    mitre_id TEXT,
                    mitre_link TEXT,
                    details TEXT,
                    status TEXT DEFAULT 'new',
                    acknowledged_at REAL,
                    resolved_at REAL,
                    false_positive BOOLEAN DEFAULT 0,
                    metadata TEXT,
                    created_at REAL DEFAULT (julianday('now'))
                )
            ''')
            
            # Create metrics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    cpu_percent REAL,
                    memory_percent REAL,
                    disk_percent REAL,
                    network_bytes INTEGER,
                    process_count INTEGER,
                    active_connections INTEGER,
                    metadata TEXT,
                    created_at REAL DEFAULT (julianday('now'))
                )
            ''')
            
            # Create incidents table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT NOT NULL,
                    status TEXT DEFAULT 'open',
                    created_at REAL DEFAULT (julianday('now')),
                    updated_at REAL DEFAULT (julianday('now')),
                    resolved_at REAL,
                    assigned_to TEXT,
                    tags TEXT,
                    related_alerts TEXT
                )
            ''')
            
            # Create system_info table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT,
                    os_name TEXT,
                    os_version TEXT,
                    cpu_count INTEGER,
                    total_memory INTEGER,
                    disk_size INTEGER,
                    last_boot REAL,
                    updated_at REAL DEFAULT (julianday('now'))
                )
            ''')
            
            # Create indexes for better performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp)')
            
            conn.commit()
            logger.info("Database initialized successfully")
    
    @contextmanager
    def _get_connection(self):
        """Get database connection with proper locking"""
        with self.lock:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            finally:
                conn.close()
    
    def insert_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Insert a new alert into the database"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO alerts (
                        id, timestamp, type, severity, binary, command,
                        process_id, user_name, system_name, mitre_id, mitre_link,
                        details, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert_data.get('id'),
                    alert_data.get('timestamp'),
                    alert_data.get('type'),
                    alert_data.get('severity'),
                    alert_data.get('binary'),
                    alert_data.get('command'),
                    alert_data.get('process_id'),
                    alert_data.get('user_name'),
                    alert_data.get('system_name'),
                    alert_data.get('mitre_id'),
                    alert_data.get('mitre_link'),
                    alert_data.get('details'),
                    json.dumps(alert_data.get('metadata', {}))
                ))
                
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error inserting alert: {e}")
            return False
    
    def get_alerts(self, limit: int = 100, offset: int = 0, 
                   severity: Optional[str] = None, 
                   status: Optional[str] = None,
                   start_time: Optional[float] = None,
                   end_time: Optional[float] = None) -> List[Dict[str, Any]]:
        """Get alerts with optional filtering"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                query = "SELECT * FROM alerts WHERE 1=1"
                params = []
                
                if severity:
                    query += " AND severity = ?"
                    params.append(severity)
                
                if status:
                    query += " AND status = ?"
                    params.append(status)
                
                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time)
                
                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time)
                
                query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                alerts = []
                for row in rows:
                    alert = dict(row)
                    if alert['metadata']:
                        alert['metadata'] = json.loads(alert['metadata'])
                    alerts.append(alert)
                
                return alerts
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            return []
    
    def update_alert_status(self, alert_id: str, status: str, 
                           acknowledged_at: Optional[float] = None,
                           resolved_at: Optional[float] = None) -> bool:
        """Update alert status"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                update_fields = ["status = ?"]
                params = [status]
                
                if acknowledged_at:
                    update_fields.append("acknowledged_at = ?")
                    params.append(acknowledged_at)
                
                if resolved_at:
                    update_fields.append("resolved_at = ?")
                    params.append(resolved_at)
                
                params.append(alert_id)
                
                query = f"UPDATE alerts SET {', '.join(update_fields)} WHERE id = ?"
                cursor.execute(query, params)
                
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error updating alert status: {e}")
            return False
    
    def insert_metrics(self, metrics_data: Dict[str, Any]) -> bool:
        """Insert system metrics"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO metrics (
                        timestamp, cpu_percent, memory_percent, disk_percent,
                        network_bytes, process_count, active_connections, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    metrics_data.get('timestamp'),
                    metrics_data.get('cpu_percent'),
                    metrics_data.get('memory_percent'),
                    metrics_data.get('disk_percent'),
                    metrics_data.get('network_bytes'),
                    metrics_data.get('process_count'),
                    metrics_data.get('active_connections'),
                    json.dumps(metrics_data.get('metadata', {}))
                ))
                
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error inserting metrics: {e}")
            return False
    
    def get_metrics(self, limit: int = 1000, 
                    start_time: Optional[float] = None,
                    end_time: Optional[float] = None) -> List[Dict[str, Any]]:
        """Get system metrics"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                query = "SELECT * FROM metrics WHERE 1=1"
                params = []
                
                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time)
                
                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time)
                
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                metrics = []
                for row in rows:
                    metric = dict(row)
                    if metric['metadata']:
                        metric['metadata'] = json.loads(metric['metadata'])
                    metrics.append(metric)
                
                return metrics
        except Exception as e:
            logger.error(f"Error getting metrics: {e}")
            return []
    
    def cleanup_old_data(self, retention_days: int = 30) -> bool:
        """Clean up old data based on retention policy"""
        try:
            cutoff_time = (datetime.now() - timedelta(days=retention_days)).timestamp()
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Clean up old alerts
                cursor.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff_time,))
                alerts_deleted = cursor.rowcount
                
                # Clean up old metrics
                cursor.execute("DELETE FROM metrics WHERE timestamp < ?", (cutoff_time,))
                metrics_deleted = cursor.rowcount
                
                conn.commit()
                
                logger.info(f"Cleanup completed: {alerts_deleted} alerts, {metrics_deleted} metrics deleted")
                return True
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                stats = {}
                
                # Alert statistics
                cursor.execute("SELECT COUNT(*) FROM alerts")
                stats['total_alerts'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'new'")
                stats['new_alerts'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
                stats['alerts_by_severity'] = dict(cursor.fetchall())
                
                # Metrics statistics
                cursor.execute("SELECT COUNT(*) FROM metrics")
                stats['total_metrics'] = cursor.fetchone()[0]
                
                # Recent activity
                cursor.execute("""
                    SELECT COUNT(*) FROM alerts 
                    WHERE timestamp > ?
                """, ((datetime.now() - timedelta(hours=24)).timestamp(),))
                stats['alerts_last_24h'] = cursor.fetchone()[0]
                
                return stats
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}