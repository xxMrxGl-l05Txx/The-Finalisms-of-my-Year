# Security Monitoring and Alerting System

A comprehensive, enterprise-grade security monitoring, detection, and alerting system for identifying and responding to security incidents with advanced threat detection capabilities.

## Components

- **Enhanced Monitor**: Advanced system monitoring with LOLBins detection, process analysis, and behavioral monitoring
- **Enhanced Detection**: Machine learning-powered threat detection with pattern analysis and correlation
- **Enhanced Alerting**: Multi-channel alert dispatcher with rate limiting and intelligent routing
- **Enhanced API**: Comprehensive RESTful API with authentication, rate limiting, and advanced endpoints
- **Enhanced Reporting**: Professional report generation with charts, analytics, and multiple formats
- **Configuration Management**: Centralized configuration with hot-reload capabilities
- **Database Management**: SQLite-based storage with automatic cleanup and optimization
- **Health Monitoring**: Real-time system health monitoring and performance tracking

## Features

### Advanced Monitoring
- Real-time system resource monitoring (CPU, Memory, Disk, Network)
- LOLBins (Living Off The Land Binaries) detection with MITRE ATT&CK mapping
- Process behavior analysis and anomaly detection
- Network activity monitoring and suspicious connection detection
- Statistical anomaly detection with baseline establishment
- Trend analysis and pattern recognition

### Intelligent Alerting
- Multi-channel notifications (Desktop, Email, Webhook, SMS)
- Rate limiting and cooldown management to prevent alert spam
- Severity-based alert routing and escalation
- Alert correlation and incident grouping
- Customizable alert templates and formatting

### Comprehensive API
- RESTful API with OpenAPI/Swagger documentation
- Authentication and authorization with API keys
- Rate limiting and request throttling
- Real-time metrics and health endpoints
- Bulk operations and batch processing
- WebSocket support for real-time updates

### Professional Reporting
- HTML reports with interactive charts and analytics
- CSV exports for data analysis and compliance
- JSON reports for programmatic access
- Automated daily and weekly report generation
- Custom report templates and branding
- Executive summary dashboards

### Enterprise Features
- High availability and fault tolerance
- Horizontal scaling support
- Backup and disaster recovery
- Audit logging and compliance reporting
- Role-based access control
- Integration with SIEM systems

## Quick Start

1. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Initialize the system:
   ```
   python -m backend.utils.enhanced_service_runner --config config.json
   ```

3. Access the web interface at `http://localhost:8080`

4. Access the API at `http://localhost:5000/api/v1/`

## Configuration

The system uses a centralized configuration file (`config.json`) with the following sections:

### Monitoring Configuration
```json
{
  "monitoring": {
    "cpu_threshold": 80.0,
    "memory_threshold": 80.0,
    "disk_threshold": 90.0,
    "monitor_interval": 60,
    "enable_lolbin_detection": true,
    "enable_process_monitoring": true
  }
}
```

### Alerting Configuration
```json
{
  "alerting": {
    "enable_desktop_notifications": true,
    "enable_email_alerts": false,
    "alert_cooldown_seconds": 300,
    "max_alerts_per_hour": 100
  }
}
```

### API Configuration
```json
{
  "api": {
    "host": "0.0.0.0",
    "port": 5000,
    "enable_cors": true,
    "enable_rate_limiting": true,
    "enable_authentication": false
  }
}
```

## Installation Options

### Standard Installation
```bash
git clone <repository-url>
cd security-monitoring-system
pip install -r requirements.txt
python -m backend.utils.enhanced_service_runner
```

### Windows Service Installation
```batch
install_as_service.bat
```

### Docker Installation
```bash
docker build -t security-monitoring .
docker run -d -p 5000:5000 -p 8080:8080 security-monitoring
```

### Development Setup
```bash
pip install -r requirements.txt
pip install -e .
python -m pytest tests/
```

## API Documentation

The enhanced API provides comprehensive endpoints for system interaction:

### Core Endpoints
- `GET /api/v1/status` - System status and health
- `GET /api/v1/alerts` - List alerts with filtering
- `GET /api/v1/alerts/{id}` - Get specific alert details
- `PUT /api/v1/alerts/{id}/status` - Update alert status
- `GET /api/v1/metrics` - System metrics with time range
- `GET /api/v1/dashboard/summary` - Dashboard summary data

### Reporting Endpoints
- `POST /api/v1/reports/generate` - Generate custom reports
- `GET /api/v1/reports/download/{filename}` - Download reports
- `GET /api/v1/statistics` - Comprehensive system statistics

### Configuration Endpoints
- `GET /api/v1/config` - Get current configuration
- `PUT /api/v1/config` - Update configuration
- `GET /api/v1/system/health` - Detailed system health

### Authentication
API endpoints support optional API key authentication:
```bash
curl -H "X-API-Key: your-api-key" http://localhost:5000/api/v1/alerts
```

## Frontend Interface

The system includes a modern React-based web interface with:

- Real-time dashboard with live metrics
- Alert management and investigation tools
- Interactive charts and analytics
- Report generation and download
- System configuration interface
- Mobile-responsive design

### Starting the Frontend
```bash
cd frontend/lolbas-defender-alert-main
npm install
npm run dev
```

## Monitoring Capabilities

### LOLBins Detection
The system monitors for suspicious use of legitimate binaries:
- PowerShell with encoded commands
- Certutil for file downloads
- Regsvr32 for script execution
- WMIC for remote execution
- Bitsadmin for persistence

### Behavioral Analysis
- Statistical anomaly detection
- Trend analysis and pattern recognition
- Process behavior profiling
- Network activity correlation
- Resource usage analysis

### Threat Intelligence
- MITRE ATT&CK technique mapping
- IOC (Indicators of Compromise) matching
- Threat pattern recognition
- Attack chain reconstruction
- Risk scoring and prioritization

## Alerting and Notifications

### Notification Channels
- **Desktop Notifications**: Native OS notifications
- **Email Alerts**: SMTP-based email notifications
- **Webhook Integration**: HTTP POST to external systems
- **SMS Alerts**: Integration with SMS gateways

### Alert Management
- Severity-based routing and escalation
- Alert correlation and deduplication
- Automatic acknowledgment and resolution
- False positive learning and suppression
- Custom alert templates and formatting

## Reporting and Analytics

### Report Types
- **Executive Summary**: High-level security posture overview
- **Technical Details**: Detailed technical analysis and recommendations
- **Compliance Reports**: Regulatory compliance and audit trails
- **Trend Analysis**: Historical trends and pattern analysis
- **Incident Reports**: Detailed incident investigation reports

### Export Formats
- HTML with interactive charts
- CSV for data analysis
- JSON for programmatic access
- PDF for executive distribution

## Performance and Scalability

### System Requirements
- **Minimum**: 2 CPU cores, 4GB RAM, 10GB disk space
- **Recommended**: 4 CPU cores, 8GB RAM, 50GB disk space
- **Enterprise**: 8+ CPU cores, 16GB+ RAM, 100GB+ disk space

### Performance Optimizations
- Efficient database indexing and query optimization
- Asynchronous processing and threading
- Memory-efficient data structures
- Configurable monitoring intervals
- Automatic data cleanup and archival

### Scalability Features
- Horizontal scaling with load balancing
- Database sharding and replication
- Distributed monitoring agents
- Cloud-native deployment options
- Microservices architecture

## Security Features

### Data Protection
- Encrypted data storage and transmission
- Secure API authentication and authorization
- Audit logging and access tracking
- Data retention and privacy controls
- Backup encryption and secure storage

### System Hardening
- Principle of least privilege
- Input validation and sanitization
- Rate limiting and DDoS protection
- Secure configuration defaults
- Regular security updates and patches

## Troubleshooting

### Common Issues

1. **High CPU Usage**
   - Increase monitoring interval
   - Disable unnecessary monitoring features
   - Check for system resource constraints

2. **Database Errors**
   - Check disk space availability
   - Verify database file permissions
   - Run database integrity checks

3. **Alert Delivery Issues**
   - Verify notification channel configuration
   - Check network connectivity
   - Review rate limiting settings

### Log Files
- Main log: `security_monitoring.log`
- API log: `api_server.log`
- Database log: `database.log`
- Alert log: `alerts.log`

### Debug Mode
```bash
python -m backend.utils.enhanced_service_runner --log-level DEBUG
```

## Development and Customization

### Adding Custom Detectors
```python
from backend.detection.enhanced_detector import EnhancedSecurityDetector

class CustomDetector(EnhancedSecurityDetector):
    def detect_custom_threat(self, data):
        # Custom detection logic
        pass
```

### Custom Alert Channels
```python
from backend.alerting.enhanced_dispatcher import EnhancedAlertDispatcher

class CustomNotifier:
    def send_notification(self, alert):
        # Custom notification logic
        pass
```

### API Extensions
```python
from backend.api.enhanced_api import app

@app.route('/api/v1/custom/endpoint')
def custom_endpoint():
    return jsonify({"message": "Custom endpoint"})
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

### Development Guidelines
- Follow PEP 8 style guidelines
- Write comprehensive tests
- Document all public APIs
- Use type hints where appropriate
- Follow security best practices

## Support and Maintenance

### Regular Maintenance Tasks
- Monitor system performance and resource usage
- Review and update detection rules
- Backup configuration and data
- Update dependencies and security patches
- Review and analyze security reports

### Support Channels
- GitHub Issues for bug reports and feature requests
- Documentation wiki for detailed guides
- Community forum for discussions
- Professional support for enterprise deployments

## License

MIT License - see LICENSE file for details

## Changelog

### Version 2.0.0
- Complete system rewrite with enhanced architecture
- Advanced threat detection with machine learning
- Multi-channel alerting with intelligent routing
- Professional reporting with interactive charts
- Comprehensive API with authentication
- Modern web interface with real-time updates
- Enterprise features and scalability improvements

### Version 1.0.0
- Initial release with basic monitoring
- Simple alerting and reporting
- Basic API endpoints
- Windows service support

## Acknowledgments

- MITRE ATT&CK framework for threat intelligence
- LOLBAS project for LOLBins detection rules
- Open source security community for best practices
- Contributors and beta testers
