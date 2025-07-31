"""
Configuration management for the security monitoring system
"""
import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

@dataclass
class MonitoringConfig:
    """Configuration for monitoring parameters"""
    cpu_threshold: float = 80.0
    memory_threshold: float = 80.0
    disk_threshold: float = 90.0
    network_threshold: int = 1000000
    monitor_interval: int = 60
    enable_lolbin_detection: bool = True
    enable_process_monitoring: bool = True
    enable_file_monitoring: bool = True
    enable_registry_monitoring: bool = True

@dataclass
class AlertingConfig:
    """Configuration for alerting system"""
    enable_email_alerts: bool = False
    enable_sms_alerts: bool = False
    enable_desktop_notifications: bool = True
    enable_webhook_alerts: bool = False
    alert_cooldown_seconds: int = 300
    max_alerts_per_hour: int = 100
    email_smtp_server: Optional[str] = None
    email_smtp_port: int = 587
    email_username: Optional[str] = None
    email_password: Optional[str] = None
    webhook_url: Optional[str] = None

@dataclass
class APIConfig:
    """Configuration for API server"""
    host: str = "0.0.0.0"
    port: int = 5000
    enable_cors: bool = True
    enable_rate_limiting: bool = True
    rate_limit_per_minute: int = 100
    enable_authentication: bool = False
    api_key: Optional[str] = None

@dataclass
class SystemConfig:
    """Main system configuration"""
    monitoring: MonitoringConfig
    alerting: AlertingConfig
    api: APIConfig
    log_level: str = "INFO"
    data_retention_days: int = 30
    enable_auto_cleanup: bool = True
    backup_enabled: bool = True
    backup_interval_hours: int = 24

class ConfigManager:
    """Manages system configuration"""
    
    def __init__(self, config_file: str = "config.json"):
        self.config_file = Path(config_file)
        self.config = self._load_config()
        
    def _load_config(self) -> SystemConfig:
        """Load configuration from file or create default"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    
                return SystemConfig(
                    monitoring=MonitoringConfig(**data.get('monitoring', {})),
                    alerting=AlertingConfig(**data.get('alerting', {})),
                    api=APIConfig(**data.get('api', {})),
                    log_level=data.get('log_level', 'INFO'),
                    data_retention_days=data.get('data_retention_days', 30),
                    enable_auto_cleanup=data.get('enable_auto_cleanup', True),
                    backup_enabled=data.get('backup_enabled', True),
                    backup_interval_hours=data.get('backup_interval_hours', 24)
                )
            except Exception as e:
                logger.error(f"Error loading config: {e}")
                return self._create_default_config()
        else:
            return self._create_default_config()
    
    def _create_default_config(self) -> SystemConfig:
        """Create default configuration"""
        config = SystemConfig(
            monitoring=MonitoringConfig(),
            alerting=AlertingConfig(),
            api=APIConfig()
        )
        self.save_config(config)
        return config
    
    def save_config(self, config: SystemConfig = None) -> bool:
        """Save configuration to file"""
        if config is None:
            config = self.config
            
        try:
            config_dict = {
                'monitoring': asdict(config.monitoring),
                'alerting': asdict(config.alerting),
                'api': asdict(config.api),
                'log_level': config.log_level,
                'data_retention_days': config.data_retention_days,
                'enable_auto_cleanup': config.enable_auto_cleanup,
                'backup_enabled': config.backup_enabled,
                'backup_interval_hours': config.backup_interval_hours
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config_dict, f, indent=2)
            
            self.config = config
            logger.info("Configuration saved successfully")
            return True
        except Exception as e:
            logger.error(f"Error saving config: {e}")
            return False
    
    def get_config(self) -> SystemConfig:
        """Get current configuration"""
        return self.config
    
    def update_config(self, **kwargs) -> bool:
        """Update configuration with new values"""
        try:
            for key, value in kwargs.items():
                if hasattr(self.config, key):
                    setattr(self.config, key, value)
                elif hasattr(self.config.monitoring, key):
                    setattr(self.config.monitoring, key, value)
                elif hasattr(self.config.alerting, key):
                    setattr(self.config.alerting, key, value)
                elif hasattr(self.config.api, key):
                    setattr(self.config.api, key, value)
            
            return self.save_config()
        except Exception as e:
            logger.error(f"Error updating config: {e}")
            return False