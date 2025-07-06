#!/usr/bin/env python3

"""
VulnX Configuration Management System
Advanced configuration management with validation and security features
Author: Enhanced by AI for VulnX-Snow 2025
"""

from __future__ import annotations
import os
import json
import yaml
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
import configparser
from cryptography.fernet import Fernet
import hashlib

logger = logging.getLogger(__name__)

@dataclass
class ScanConfig:
    """Scan configuration settings"""
    timeout: int = 10
    retries: int = 3
    delay_min: float = 0.5
    delay_max: float = 2.0
    threads: int = 10
    user_agents: List[str] = field(default_factory=lambda: [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    ])
    max_redirects: int = 5
    verify_ssl: bool = False

@dataclass
class ExploitConfig:
    """Exploit configuration settings"""
    enabled_cms: List[str] = field(default_factory=lambda: [
        'wordpress', 'joomla', 'prestashop', 'drupal', 'opencart', 'magento'
    ])
    aggressive_mode: bool = False
    auto_exploit: bool = False
    shell_upload: bool = True
    payload_obfuscation: bool = False
    steganography: bool = False

@dataclass
class OutputConfig:
    """Output configuration settings"""
    format: str = 'json'
    file_path: Optional[str] = None
    console_output: bool = True
    log_level: str = 'INFO'
    colored_output: bool = True
    export_formats: List[str] = field(default_factory=lambda: ['json', 'xml', 'csv'])

@dataclass
class ProxyConfig:
    """Proxy configuration settings"""
    enabled: bool = False
    http_proxy: Optional[str] = None
    https_proxy: Optional[str] = None
    socks_proxy: Optional[str] = None
    proxy_list: List[str] = field(default_factory=list)
    rotate_proxies: bool = False
    proxy_timeout: int = 10

@dataclass
class APIConfig:
    """API integration configuration"""
    shodan_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    censys_api_key: Optional[str] = None
    nvd_api_key: Optional[str] = None
    enable_shodan: bool = False
    enable_virustotal: bool = False
    enable_censys: bool = False
    enable_nvd: bool = False

@dataclass
class SecurityConfig:
    """Security configuration settings"""
    encrypt_config: bool = True
    mask_sensitive_data: bool = True
    secure_random: bool = True
    fingerprint_resistance: bool = True
    waf_evasion: bool = True
    rate_limiting: bool = True
    requests_per_second: int = 5

@dataclass
class VulnXConfig:
    """Main VulnX configuration"""
    scan: ScanConfig = field(default_factory=ScanConfig)
    exploit: ExploitConfig = field(default_factory=ExploitConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    api: APIConfig = field(default_factory=APIConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            'scan': self.scan.__dict__,
            'exploit': self.exploit.__dict__,
            'output': self.output.__dict__,
            'proxy': self.proxy.__dict__,
            'api': self.api.__dict__,
            'security': self.security.__dict__
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VulnXConfig':
        """Create configuration from dictionary"""
        return cls(
            scan=ScanConfig(**data.get('scan', {})),
            exploit=ExploitConfig(**data.get('exploit', {})),
            output=OutputConfig(**data.get('output', {})),
            proxy=ProxyConfig(**data.get('proxy', {})),
            api=APIConfig(**data.get('api', {})),
            security=SecurityConfig(**data.get('security', {}))
        )

class ConfigManager:
    """Advanced configuration manager with encryption and validation"""
    
    def __init__(self, config_dir: Optional[str] = None):
        self.config_dir = Path(config_dir or os.path.expanduser('~/.vulnx'))
        self.config_dir.mkdir(exist_ok=True)
        
        self.config_file = self.config_dir / 'config.json'
        self.encrypted_config_file = self.config_dir / 'config.enc'
        self.key_file = self.config_dir / '.key'
        
        self.config = VulnXConfig()
        self._encryption_key = None
        
    def _generate_key(self) -> bytes:
        """Generate encryption key"""
        key = Fernet.generate_key()
        with open(self.key_file, 'wb') as f:
            f.write(key)
        os.chmod(self.key_file, 0o600)  # Restrict permissions
        return key
    
    def _load_key(self) -> bytes:
        """Load encryption key"""
        if not self.key_file.exists():
            return self._generate_key()
        
        with open(self.key_file, 'rb') as f:
            return f.read()
    
    def _encrypt_data(self, data: str) -> bytes:
        """Encrypt configuration data"""
        if not self._encryption_key:
            self._encryption_key = self._load_key()
        
        fernet = Fernet(self._encryption_key)
        return fernet.encrypt(data.encode())
    
    def _decrypt_data(self, encrypted_data: bytes) -> str:
        """Decrypt configuration data"""
        if not self._encryption_key:
            self._encryption_key = self._load_key()
        
        fernet = Fernet(self._encryption_key)
        return fernet.decrypt(encrypted_data).decode()
    
    def load_config(self, encrypted: bool = True) -> VulnXConfig:
        """Load configuration from file"""
        try:
            if encrypted and self.encrypted_config_file.exists():
                with open(self.encrypted_config_file, 'rb') as f:
                    encrypted_data = f.read()
                
                decrypted_data = self._decrypt_data(encrypted_data)
                config_data = json.loads(decrypted_data)
                
            elif self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
            else:
                logger.info("No configuration file found, using defaults")
                return self.config
            
            self.config = VulnXConfig.from_dict(config_data)
            logger.info(f"Configuration loaded from {self.config_dir}")
            
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            logger.info("Using default configuration")
        
        return self.config
    
    def save_config(self, config: Optional[VulnXConfig] = None, encrypted: bool = True) -> None:
        """Save configuration to file"""
        if config:
            self.config = config
        
        try:
            config_data = self.config.to_dict()
            
            # Mask sensitive data if enabled
            if self.config.security.mask_sensitive_data:
                config_data = self._mask_sensitive_data(config_data)
            
            config_json = json.dumps(config_data, indent=2)
            
            if encrypted and self.config.security.encrypt_config:
                encrypted_data = self._encrypt_data(config_json)
                with open(self.encrypted_config_file, 'wb') as f:
                    f.write(encrypted_data)
                os.chmod(self.encrypted_config_file, 0o600)
                
                # Remove unencrypted file if it exists
                if self.config_file.exists():
                    self.config_file.unlink()
            else:
                with open(self.config_file, 'w') as f:
                    f.write(config_json)
                os.chmod(self.config_file, 0o600)
            
            logger.info(f"Configuration saved to {self.config_dir}")
            
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
    
    def _mask_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Mask sensitive data in configuration"""
        sensitive_keys = [
            'api_key', 'password', 'token', 'secret', 'key',
            'shodan_api_key', 'virustotal_api_key', 'censys_api_key', 'nvd_api_key'
        ]
        
        masked_data = data.copy()
        
        def mask_recursive(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if any(sensitive in key.lower() for sensitive in sensitive_keys):
                        if value:
                            obj[key] = '*' * 8
                    else:
                        mask_recursive(value)
            elif isinstance(obj, list):
                for item in obj:
                    mask_recursive(item)
        
        mask_recursive(masked_data)
        return masked_data
    
    def validate_config(self, config: VulnXConfig) -> List[str]:
        """Validate configuration settings"""
        errors = []
        
        # Validate scan settings
        if config.scan.timeout <= 0:
            errors.append("Scan timeout must be positive")
        
        if config.scan.retries < 0:
            errors.append("Scan retries cannot be negative")
        
        if config.scan.threads <= 0:
            errors.append("Thread count must be positive")
        
        # Validate proxy settings
        if config.proxy.enabled:
            if not any([config.proxy.http_proxy, config.proxy.https_proxy, 
                       config.proxy.socks_proxy, config.proxy.proxy_list]):
                errors.append("Proxy enabled but no proxy configuration provided")
        
        # Validate API settings
        if config.api.enable_shodan and not config.api.shodan_api_key:
            errors.append("Shodan enabled but no API key provided")
        
        if config.api.enable_virustotal and not config.api.virustotal_api_key:
            errors.append("VirusTotal enabled but no API key provided")
        
        # Validate output settings
        valid_formats = ['json', 'xml', 'csv', 'html', 'txt']
        if config.output.format not in valid_formats:
            errors.append(f"Invalid output format: {config.output.format}")
        
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if config.output.log_level not in valid_log_levels:
            errors.append(f"Invalid log level: {config.output.log_level}")
        
        return errors
    
    def update_config(self, section: str, key: str, value: Any) -> None:
        """Update specific configuration value"""
        try:
            config_dict = self.config.to_dict()
            if section in config_dict:
                config_dict[section][key] = value
                self.config = VulnXConfig.from_dict(config_dict)
                logger.info(f"Updated {section}.{key} = {value}")
            else:
                logger.error(f"Invalid configuration section: {section}")
        except Exception as e:
            logger.error(f"Error updating configuration: {e}")
    
    def get_config_value(self, section: str, key: str) -> Any:
        """Get specific configuration value"""
        try:
            config_dict = self.config.to_dict()
            return config_dict.get(section, {}).get(key)
        except Exception as e:
            logger.error(f"Error getting configuration value: {e}")
            return None
    
    def export_config(self, format: str = 'json', file_path: Optional[str] = None) -> str:
        """Export configuration in specified format"""
        config_data = self.config.to_dict()
        
        if format.lower() == 'json':
            output = json.dumps(config_data, indent=2)
        elif format.lower() == 'yaml':
            output = yaml.dump(config_data, default_flow_style=False)
        elif format.lower() == 'ini':
            config_parser = configparser.ConfigParser()
            for section, values in config_data.items():
                config_parser[section] = {}
                for key, value in values.items():
                    config_parser[section][str(key)] = str(value)
            
            from io import StringIO
            output_io = StringIO()
            config_parser.write(output_io)
            output = output_io.getvalue()
        else:
            raise ValueError(f"Unsupported export format: {format}")
        
        if file_path:
            with open(file_path, 'w') as f:
                f.write(output)
            logger.info(f"Configuration exported to {file_path}")
        
        return output
    
    def import_config(self, file_path: str, format: str = 'json') -> None:
        """Import configuration from file"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            if format.lower() == 'json':
                config_data = json.loads(content)
            elif format.lower() == 'yaml':
                config_data = yaml.safe_load(content)
            elif format.lower() == 'ini':
                config_parser = configparser.ConfigParser()
                config_parser.read_string(content)
                
                config_data = {}
                for section in config_parser.sections():
                    config_data[section] = dict(config_parser[section])
            else:
                raise ValueError(f"Unsupported import format: {format}")
            
            self.config = VulnXConfig.from_dict(config_data)
            
            # Validate imported configuration
            errors = self.validate_config(self.config)
            if errors:
                logger.warning(f"Configuration validation errors: {errors}")
            
            logger.info(f"Configuration imported from {file_path}")
            
        except Exception as e:
            logger.error(f"Error importing configuration: {e}")
    
    def create_config_wizard(self) -> VulnXConfig:
        """Interactive configuration wizard"""
        print("VulnX Configuration Wizard")
        print("=" * 30)
        
        config = VulnXConfig()
        
        # Scan configuration
        print("\n[Scan Configuration]")
        try:
            config.scan.timeout = int(input(f"Request timeout ({config.scan.timeout}): ") or config.scan.timeout)
            config.scan.threads = int(input(f"Thread count ({config.scan.threads}): ") or config.scan.threads)
            config.scan.retries = int(input(f"Retry attempts ({config.scan.retries}): ") or config.scan.retries)
        except ValueError:
            print("Using default values for scan configuration")
        
        # Exploit configuration
        print("\n[Exploit Configuration]")
        aggressive = input(f"Enable aggressive mode? (y/N): ").lower()
        config.exploit.aggressive_mode = aggressive in ['y', 'yes']
        
        auto_exploit = input(f"Enable auto exploitation? (y/N): ").lower()
        config.exploit.auto_exploit = auto_exploit in ['y', 'yes']
        
        # API configuration
        print("\n[API Configuration]")
        shodan_key = input("Shodan API key (optional): ").strip()
        if shodan_key:
            config.api.shodan_api_key = shodan_key
            config.api.enable_shodan = True
        
        vt_key = input("VirusTotal API key (optional): ").strip()
        if vt_key:
            config.api.virustotal_api_key = vt_key
            config.api.enable_virustotal = True
        
        # Output configuration
        print("\n[Output Configuration]")
        output_format = input("Output format (json/xml/csv): ").lower() or 'json'
        if output_format in ['json', 'xml', 'csv']:
            config.output.format = output_format
        
        log_level = input("Log level (DEBUG/INFO/WARNING/ERROR): ").upper() or 'INFO'
        if log_level in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            config.output.log_level = log_level
        
        self.config = config
        print(f"\nConfiguration created successfully!")
        
        save = input("Save configuration? (Y/n): ").lower()
        if save not in ['n', 'no']:
            self.save_config()
        
        return config

# Global configuration manager instance
config_manager = ConfigManager()

def get_config() -> VulnXConfig:
    """Get current configuration"""
    return config_manager.config

def load_config(config_dir: Optional[str] = None) -> VulnXConfig:
    """Load configuration from file"""
    if config_dir:
        global config_manager
        config_manager = ConfigManager(config_dir)
    
    return config_manager.load_config()

def save_config(config: Optional[VulnXConfig] = None) -> None:
    """Save configuration to file"""
    config_manager.save_config(config)

def update_config(section: str, key: str, value: Any) -> None:
    """Update configuration value"""
    config_manager.update_config(section, key, value)