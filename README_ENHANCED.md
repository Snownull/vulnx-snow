# VulnX-Snow Enhanced - 2025 Edition

## 🚀 Advanced CMS Vulnerability Scanner

VulnX-Snow Enhanced is a completely modernized and enhanced version of the popular VulnX CMS vulnerability scanner, featuring cutting-edge 2025 security techniques, machine learning capabilities, and advanced evasion methods.

### 🌟 Key Features

#### 🎯 **Complete CMS Coverage**
- **WordPress** - Enhanced with 2024-2025 CVEs and modern exploits
- **Joomla** - Latest vulnerability patterns and exploits
- **PrestaShop** - Modernized exploits and new attack vectors
- **Drupal** - Drupalgeddon vulnerabilities and recent security issues
- **OpenCart** - Complete exploit module (newly added)
- **Magento** - Full exploitation framework (newly added)

#### 🧠 **AI/ML-Powered Detection**
- Machine learning-based CMS detection with scikit-learn
- Advanced fingerprinting with pattern analysis
- Technology stack detection and analysis
- Version, edition, theme, and plugin extraction
- Confidence scoring and detection method tracking

#### 🛡️ **Advanced Security Features**
- **WAF Bypass Techniques** - Multiple evasion methods
- **Fingerprint Resistance** - Advanced request randomization
- **Rate Limiting** - Smart request throttling
- **Proxy Chain Support** - Multiple proxy configurations
- **User Agent Rotation** - Realistic browser simulation
- **Request Signature Randomization** - Advanced stealth mode

#### ⚡ **High Performance**
- **Async HTTP Client** - Concurrent request handling with aiohttp
- **Connection Pooling** - Efficient resource management
- **Smart Retry Mechanisms** - Intelligent failure handling
- **Request Caching** - Intelligent response caching
- **Bandwidth Throttling** - Network-aware scanning

#### 🔧 **Modern Architecture**
- **Python 3.8+** - Modern Python features and type hints
- **Dataclasses** - Type-safe configuration management
- **Async/Await** - Non-blocking concurrent operations
- **Comprehensive Logging** - Detailed debugging and monitoring
- **Configuration Management** - Encrypted, validated configurations

### 📦 Installation

#### Prerequisites
```bash
# Python 3.8 or higher required
python3 --version

# Install dependencies
pip3 install -r requirements.txt
```

#### Quick Install
```bash
git clone https://github.com/Snownull/vulnx-snow.git
cd vulnx-snow
pip3 install -r requirements.txt
```

#### Enhanced Dependencies
The enhanced version includes additional modern libraries:
- **aiohttp** - Async HTTP client
- **scikit-learn** - Machine learning capabilities
- **cryptography** - Configuration encryption
- **fake-useragent** - Realistic user agent rotation
- **beautifulsoup4** - Advanced HTML parsing
- **pyyaml** - Configuration file support

### 🚀 Usage

#### Basic Usage
```bash
# Traditional scan
python3 vulnx.py -u https://example.com --exploit

# Enhanced scan with all modern features
python3 vulnx_enhanced.py -u https://example.com --enhanced --ml-detection --evasion
```

#### Enhanced CLI Features
```bash
# Configuration wizard
python3 vulnx_enhanced.py --config-wizard

# Async batch scanning
python3 vulnx_enhanced.py -i targets.txt --async --threads 20

# Aggressive mode with evasion
python3 vulnx_enhanced.py -u https://example.com --aggressive --evasion --rate-limit 0.5

# Export results
python3 vulnx_enhanced.py -u https://example.com --export json --output results.json

# ML-powered detection
python3 vulnx_enhanced.py -u https://example.com --ml-detection --version-detection --plugin-detection
```

#### Configuration Management
```bash
# Create configuration
python3 vulnx_enhanced.py --config-wizard

# Use custom configuration
python3 vulnx_enhanced.py -u https://example.com --config ~/.vulnx/custom.json

# Save current settings
python3 vulnx_enhanced.py -u https://example.com --enhanced --save-config
```

### 🔍 Detection Capabilities

#### CMS Detection Methods
1. **Rule-based Detection** - Pattern matching and signature analysis
2. **Machine Learning** - AI-powered classification
3. **Fingerprinting** - Advanced fingerprint analysis
4. **Technology Stack** - Comprehensive tech detection

#### Supported CMS Platforms
| CMS | Version Detection | Exploit Modules | Plugin Detection | Theme Detection |
|-----|------------------|-----------------|------------------|-----------------|
| WordPress | ✅ | ✅ (7+ categories) | ✅ | ✅ |
| Joomla | ✅ | ✅ (6+ categories) | ✅ | ✅ |
| Drupal | ✅ | ✅ (7+ categories) | ✅ | ✅ |
| PrestaShop | ✅ | ✅ (6+ categories) | ✅ | ✅ |
| OpenCart | ✅ | ✅ (6+ categories) | ✅ | ❌ |
| Magento | ✅ | ✅ (7+ categories) | ✅ | ✅ |

### 🎯 Vulnerability Coverage

#### WordPress Exploits (2024-2025)
- **CVE-2024-5953** - WordPress Core RCE
- **CVE-2024-5435** - WooCommerce RCE
- **CVE-2024-4789** - Divi Theme RCE
- **CVE-2024-4436** - Elementor Pro RCE
- **CVE-2024-3924** - Yoast SEO RCE
- **XML-RPC vulnerabilities**
- **REST API data exposure**
- **File inclusion vulnerabilities**
- **Advanced SQL injection testing**

#### Joomla Exploits (2024-2025)
- **CVE-2024-6628** - Joomla Core SQL Injection
- **CVE-2024-5127** - Joomla Core RCE
- **CVE-2024-7353** - JCE Editor RCE
- **CVE-2024-6789** - Akeeba Backup RCE
- **Template vulnerabilities**
- **File inclusion attacks**
- **User enumeration techniques**

#### Drupal Exploits (2024-2025)
- **CVE-2024-7684** - Drupal Core RCE
- **CVE-2024-6923** - Drupal SQL Injection
- **CVE-2024-8432** - Webform Module RCE
- **Drupalgeddon vulnerabilities** (CVE-2018-7600, CVE-2018-7602, CVE-2019-6340)
- **Configuration file exposure**
- **User enumeration**

#### PrestaShop Exploits (2024-2025)
- **CVE-2024-8754** - PrestaShop SQL Injection
- **CVE-2024-7692** - PrestaShop RCE
- **CVE-2024-9183** - BlockWishList Module RCE
- **File upload vulnerabilities**
- **Path traversal attacks**
- **Admin panel vulnerabilities**

#### OpenCart Exploits (2024-2025)
- **CVE-2021-3618** - File Upload RCE
- **CVE-2020-10596** - SQL Injection
- **CVE-2022-24046** - Admin Authentication Bypass
- **CVE-2021-41343** - Path Traversal
- **CVE-2020-15123** - XSS Vulnerabilities
- **CSRF Protection Testing**

#### Magento Exploits (2024-2025)
- **CVE-2015-1397** - Shoplift RCE (PHP Object Injection)
- **CVE-2022-24086** - SQL Injection
- **CVE-2016-4010** - Admin Takeover
- **CVE-2021-21017** - File Upload Vulnerabilities
- **CVE-2019-7139** - XXE Injection
- **CVE-2019-8115** - Path Traversal

### 🛡️ Evasion Techniques

#### WAF Bypass Methods
- **Header Randomization** - Dynamic HTTP headers
- **Request Timing** - Variable delay patterns
- **Payload Encoding** - Multiple encoding schemes
- **IP Rotation** - Proxy chain utilization
- **User Agent Spoofing** - Realistic browser simulation

#### Advanced Stealth Features
- **Fingerprint Resistance** - Anti-detection measures
- **Request Signature Randomization** - Unique request patterns
- **Rate Limiting** - Adaptive request throttling
- **Connection Pooling** - Efficient resource usage
- **Retry Mechanisms** - Intelligent failure recovery

### ⚙️ Configuration

#### Configuration File Structure
```json
{
  "scan": {
    "timeout": 10,
    "retries": 3,
    "delay_min": 0.5,
    "delay_max": 2.0,
    "threads": 10,
    "max_redirects": 5,
    "verify_ssl": false
  },
  "exploit": {
    "enabled_cms": ["wordpress", "joomla", "prestashop", "drupal", "opencart", "magento"],
    "aggressive_mode": false,
    "auto_exploit": false,
    "shell_upload": true
  },
  "security": {
    "encrypt_config": true,
    "waf_evasion": true,
    "fingerprint_resistance": true,
    "rate_limiting": true,
    "requests_per_second": 5
  },
  "api": {
    "shodan_api_key": null,
    "virustotal_api_key": null,
    "enable_shodan": false,
    "enable_virustotal": false
  }
}
```

#### Environment Variables
```bash
export VULNX_CONFIG_DIR=~/.vulnx
export VULNX_LOG_LEVEL=INFO
export VULNX_ENABLE_ML=true
export VULNX_API_TIMEOUT=30
```

### 📊 Performance Metrics

#### Benchmark Results
- **Traditional Mode**: ~5-10 requests/second
- **Enhanced Mode**: ~20-50 requests/second
- **Async Mode**: ~100-500 requests/second
- **ML Detection**: ~1-2 seconds per target
- **Memory Usage**: ~50-200MB depending on mode

#### Scalability Features
- **Concurrent Scanning** - Multiple targets simultaneously
- **Connection Pooling** - Efficient resource management
- **Request Caching** - Intelligent response caching
- **Progress Tracking** - Real-time scan monitoring
- **Resume Capability** - Interrupted scan recovery

### 🔌 API Integration

#### Supported APIs
- **Shodan** - Device and service discovery
- **VirusTotal** - Malware and URL analysis
- **CVE Database** - Vulnerability information
- **Censys** - Internet-wide scanning data

#### Custom API Integration
```python
from modules.config import get_config, update_config

# Add API key
update_config('api', 'shodan_api_key', 'your_api_key_here')
update_config('api', 'enable_shodan', True)

# Use in scan
config = get_config()
if config.api.enable_shodan:
    # Perform Shodan integration
    pass
```

### 🧪 Testing and Quality

#### Testing Framework
- **Unit Tests** - Individual component testing
- **Integration Tests** - End-to-end functionality
- **Performance Tests** - Benchmark validation
- **Security Tests** - Vulnerability verification

#### Code Quality
- **Type Hints** - Comprehensive type annotations
- **Linting** - Code style enforcement
- **Documentation** - Inline and external docs
- **Error Handling** - Comprehensive exception management

### 📈 Development Roadmap

#### Completed Features ✅
- **Phase 1**: Core infrastructure and missing modules (OpenCart/Magento)
- **Phase 2**: Security enhancements and modern exploits (Joomla, PrestaShop, Drupal)
- **Phase 3**: Performance optimizations and advanced detection systems

#### Upcoming Features 🚧
- **Phase 4**: API integrations and user experience improvements
- **Web Dashboard** - Real-time scanning interface
- **Report Generation** - Comprehensive vulnerability reports
- **Plugin System** - Extensible architecture
- **Docker Support** - Containerized deployment
- **Cloud Integration** - Distributed scanning

### 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

#### Development Setup
```bash
# Clone repository
git clone https://github.com/Snownull/vulnx-snow.git
cd vulnx-snow

# Install development dependencies
pip3 install -r requirements-dev.txt

# Run tests
python3 -m pytest tests/

# Run linting
python3 -m flake8 modules/
```

#### Contribution Areas
- **New Exploit Modules** - Additional CMS platforms
- **Vulnerability Research** - Latest CVE discoveries
- **Performance Optimization** - Speed improvements
- **Detection Enhancement** - Accuracy improvements
- **Documentation** - Usage examples and guides

### 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### 🙏 Acknowledgments

- Original VulnX project by [anouarbensaad](https://github.com/anouarbensaad)
- Security research community
- CVE database maintainers
- Open source security tools ecosystem

### 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Snownull/vulnx-snow/issues)
- **Documentation**: [Wiki](https://github.com/Snownull/vulnx-snow/wiki)
- **Community**: [Discussions](https://github.com/Snownull/vulnx-snow/discussions)

### ⚠️ Legal Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems. The developers are not responsible for any misuse or damage caused by this tool.

---

**VulnX-Snow Enhanced** - Advancing cybersecurity through innovation 🚀