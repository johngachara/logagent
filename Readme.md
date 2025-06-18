# Log Security Agent - Node.js Edition (Not final documentation just an overview)

A real-time log analysis and threat detection system that monitors web server logs, detects security threats using pattern matching and AI-powered final decision making, automatically blocks malicious IPs via iptables, and sends alerts to your Android/Apple device via Pushover.

## 🛡️ How It Works

The Log Security Agent operates as an intelligent multi-layered security system:

1. **Pattern Detection Engine**: Monitors web server logs in real-time using regex patterns to identify potential threats (SQL injection, XSS, path traversal, command injection, SSRF, etc.)

2. **LLM-Powered Final Decision**: When threats are detected, the system forwards them to **Groq's Llama-3.3-70b-versatile model** for intelligent analysis to reduce false positives and make the final threat determination

3. **Automated IP Blocking**: IPs with threat scores ≥8/10 are automatically blocked using iptables rules to protect your server infrastructure

4. **Smart Alerting**: Pushover notifications are sent directly to your Mobile device for immediate threat awareness

5. **Threat Intelligence**: Integrates with VirusTotal and AbuseIPDB for IP reputation checking and enhanced context

## 🚀 Features

### 🔍 **Advanced Threat Detection**
- **Regex Pattern Matching**: Detects SQL injection, XSS, path traversal, command injection, SSRF, NoSQL injection, LDAP injection, and brute force attacks
- **LLM Final Decision**: Groq Llama-3.3-70b-versatile model makes intelligent final threat assessments
- **Configurable Thresholds**:
   - LLM Analysis: ≥7/10 threat score
   - Alert Notifications: ≥9/10 threat score
   - Automatic IP Blocking: ≥8/10 threat score
- **Custom Pattern Engine**: Easily extensible with custom threat patterns

### 🤖 **AI-Powered Intelligence**
- **Primary**: Groq API with Llama-3.3-70b-versatile (fast and efficient)
- **Secondary**: OpenAI models via GitHub free model inferences (fallback option)
- **False Positive Reduction**: AI context analysis prevents unnecessary blocking
- **Threat Reasoning**: Detailed explanations for each threat decision
- **Adaptive Learning**: Contextual understanding of legitimate vs malicious requests

### 🛡️ **Automated Protection**
- **iptables Integration**: Automatic IP blocking for high-risk threats
- **Linux Server Protection**: Designed specifically for Linux server environments
- **Web Server Compatibility**: Optimized for Nginx and Apache logs (works with any web server)
- **Real-time Response**: Immediate threat mitigation within seconds

### 📱 **Smart Notifications**
- **Pushover Integration**: Direct notifications to your Mobile device
- **Rich Alert Content**: IP details, threat type, confidence score, and reasoning
- **Rate Limiting**: Prevents notification spam while ensuring critical alerts
- **Threat Intelligence**: Includes IP reputation and geolocation data

### 🔗 **Threat Intelligence**
- **VirusTotal Integration**: IP reputation and malware analysis
- **AbuseIPDB Integration**: Abuse confidence scoring and reporting history
- **CVE Lookups**: Known vulnerability pattern matching
- **Geolocation Data**: IP origin tracking and ASN information

## 📋 Sample Log Analysis

Based on sample logs, here's how the system processes threats:

```json
{
  "ip": "196.251.85.193",
  "threat_type": "sensitive_file_access",
  "url": "/.env HTTP/1.1",
  "confidence": 5,
  "llm_decision": "MALICIOUS",
  "final_confidence": 8,
  "reasoning": "Attempting to access sensitive .env file with bad IP reputation",
  "action": "BLOCKED"
}
```

The agent detected a `.env` file access attempt, forwarded it to Groq for analysis, received a MALICIOUS verdict with confidence 8/10, and automatically blocked the IP via iptables.

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone <repo-url>
cd log-security-agent

# Run the deployment script
chmod +x start.sh
./start.sh
```

### 2. Configuration

Edit `config.yaml` with your API keys:

```yaml
apis:
  groq_key: "gsk_your-groq-api-key"  # Primary LLM provider
  openai_key: "ghp_your-github-token"  # GitHub free models (optional)
  virustotal_key: "your-virustotal-key"
  abuseipdb_key: "your-abuseipdb-key"
  pushover_token: "your-pushover-app-token"
  pushover_user: "your-pushover-user-key"

thresholds:
  minimum_score: 3        # Minimum score to log
  llm_analysis: 7         # Score to trigger LLM analysis
  alert_threshold: 8      # Score to send Pushover notifications
  block_threshold: 8      # Score to block IP via iptables
  brute_force_attempts: 5 # Failed login attempts

llm:
  provider: "groq"        # Primary: groq, Fallback: openai
  model: "llama-3.3-70b-versatile"
  fallback_model: "gpt-4o-mini"
```

### 3. Start the Agent

```bash
# Development mode
npm start

# Production with systemd
sudo systemctl start log-security-agent
sudo systemctl enable log-security-agent
sudo systemctl status log-security-agent
```

## 🔧 API Keys Setup

### Groq API Key (Primary LLM)
1. Visit https://console.groq.com/
2. Create account and generate API key
3. Add to config: `groq_key: "gsk-..."`
4. Model: `llama-3.3-70b-versatile` (default)

### GitHub Models (OpenAI Fallback)
1. Generate GitHub Personal Access Token
2. Enable GitHub Models beta access
3. Add to config: `openai_key: "ghp_..."`
4. Free tier includes GPT-4o-mini access

### Pushover Notifications
1. Create account at https://pushover.net/
2. Create new application to get App Token
3. Get your User Key from dashboard
4. Install Pushover app on Android device
5. Add to config:
   ```yaml
   pushover_token: "your-app-token"
   pushover_user_key: "your-user-key"
   ```

### VirusTotal API Key (v3)
1. Register at https://www.virustotal.com/
2. Navigate to profile → API Key
3. Add to config: `virustotal_key: "your-key"`

### AbuseIPDB API Key
1. Register at https://www.abuseipdb.com/
2. Navigate to account → API
3. Add to config: `abuseipdb_key: "your-key"`

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Server    │───▶│   Log Parser     │───▶│ Pattern Matcher │
│ Nginx/Apache    │    │  (chokidar)      │    │ (Regex Engine)  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                        │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ iptables Block  │◀───│ Main Orchestrator│◀───│ Groq LLM Judge  │
│ (Auto Protect)  │    │   (main.js)      │    │ (Final Decision)│
└─────────────────┘    └──────────────────┘    └─────────────────┘
        │                       │                        │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Pushover Alert  │    │ Threat Intel     │    │ Threat Queue    │
│ (Mobile Phone) │    │ (VT/AbuseIPDB)   │    │ (Rate Limited)  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🖥️ Future Development - SIEM Interface

**Planned Enhancement**: Converting portions of the system into an Express.js web application to provide:

- **Web Dashboard**: Real-time threat visualization and statistics
- **Historical Analysis**: Searchable log database with trend analysis
- **Manual IP Management**: Whitelist/blacklist management interface
- **Configuration GUI**: Web-based configuration management
- **API Endpoints**: RESTful API for threat data and system control
- **Multi-Server Support**: Centralized monitoring for multiple servers

This will transform the agent from a standalone monitor into a comprehensive SIEM (Security Information and Event Management) solution.

## 🐳 Docker Integration (Planned)

**Learning Docker**: Planning to containerize the application for:

- **Container Deployment**: Easy deployment within existing project containers
- **Isolated Environment**: Contained security monitoring without system conflicts
- **Scalability**: Multi-container deployments for large infrastructures
- **Portability**: Consistent deployment across different server environments
- **Development**: Simplified development and testing environments

## ⚙️ Configuration Options

### Threat Thresholds
```yaml
thresholds:
  minimum_score: 3        # Log threshold
  llm_analysis: 7         # LLM analysis trigger
  alert_threshold: 9      # Pushover notification  
  block_threshold: 8      # iptables blocking
  brute_force_attempts: 5 # Login attempt limit
  block_ip_threshold : 8
```

### Supported Log Formats
- **Apache Common Log Format**
- **Apache Combined Log Format**
- **Nginx Access Logs**
- **Custom Formats** (modify `log_parser.js`)

### LLM Configuration
```yaml
llm:
  provider: "groq"                    # groq or openai
  model: "llama-3.3-70b-versatile"   # Groq model
  fallback_model: "gpt-4o-mini"      # GitHub model
  max_tokens: 1000
  temperature: 0.1
```

## 📊 Monitoring and Maintenance

### Real-time Monitoring
```bash
# Systemd logs
sudo journalctl -u log-security-agent -f

# Application logs  
tail -f agent.log

# Blocked IPs
sudo iptables -L INPUT -n | grep DROP
```

### Performance Tuning
- **Threshold Adjustment**: Modify scores based on your environment
- **Pattern Customization**: Add/remove threat patterns in `rules/patterns.json`
- **Rate Limiting**: Adjust API call intervals for your usage limits
- **Whitelist Management**: Update `rules/whitelist.txt` for legitimate traffic

## 🔧 Customization

### Add Custom Threat Patterns
Edit `rules/patterns.json`:
```json
{
  "custom_backdoor": {
    "patterns": ["(?i)(backdoor|shell|webshell)"],
    "score": 9,
    "description": "Potential backdoor access attempt"
  }
}
```

### Modify Detection Logic
Edit `threat_detector.js` to add custom detection functions or scoring algorithms.

### iptables Integration
The system automatically manages iptables rules:
```bash
# View blocked IPs
sudo iptables -L INPUT -n

# Manual IP block
sudo iptables -I INPUT -s 192.168.1.100 -j DROP

# Unblock IP
sudo iptables -D INPUT -s 192.168.1.100 -j DROP
```

## 🚀 Production Deployment

### Security Considerations
- **API Key Security**: Use environment variables for sensitive keys
- **Log Rotation**: Implement logrotate for agent logs
- **Firewall Rules**: Ensure iptables persistence across reboots
- **Resource Monitoring**: Monitor CPU/memory usage under load

### Linux Server Integration
```bash
# Create systemd service
sudo cp log-security-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable log-security-agent

# Configure log rotation
sudo cp logrotate.conf /etc/logrotate.d/log-security-agent

# Setup iptables persistence
sudo apt-get install iptables-persistent
sudo netfilter-persistent save
```

## 🐛 Troubleshooting

### Common Issues
1. **Permission Denied**: Check log file read permissions
2. **iptables Errors**: Ensure sudo privileges for blocking functionality
3. **API Rate Limits**: Monitor Groq usage and adjust request intervals
4. **False Positives**: Fine-tune thresholds or expand whitelist
5. **Memory Usage**: Monitor system resources during peak traffic

### Debug Mode
```bash
# Enable verbose logging
DEBUG=* npm start

# Check LLM connectivity
node test-llm.js

# Validate log parsing
node test-parser.js /path/to/logfile
```

## 📈 System Requirements

- **Node.js**: v16+
- **Linux**: Ubuntu 20.04+ (tested), CentOS 8+, Debian 11+
- **Memory**: 512MB minimum, 2GB recommended for high traffic
- **Storage**: 10GB for logs and threat database
- **Network**: Stable internet for API calls (Groq, threat intelligence)
- **Permissions**: sudo access for iptables management

## 🔒 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/enhancement`)
3. Commit changes (`git commit -am 'Add new feature'`)
4. Push to branch (`git push origin feature/enhancement`)
5. Create Pull Request

Please follow existing code style and include tests for new features.

## 📞 Support

For issues, questions, and feature requests:
- **GitHub Issues**: Technical problems and bug reports

---

**Note**: This project is actively being developed and tested in production Linux server environments. The LLM-powered decision making significantly reduces false positives while maintaining strong security protection for web applications and server infrastructure.