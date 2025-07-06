#!/usr/bin/env python3

"""
Advanced CMS Detection System
ML-powered CMS detection with fingerprinting and pattern analysis
Author: Enhanced by AI for VulnX-Snow 2025
"""

from __future__ import annotations
import re
import json
import hashlib
import random
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from pathlib import Path
import logging
from urllib.parse import urljoin, urlparse
import numpy as np
from collections import Counter
import time

# Try to import ML libraries
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, classification_report
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logger.warning("ML libraries not available. Using rule-based detection only.")

logger = logging.getLogger(__name__)

@dataclass
class CMSSignature:
    """CMS signature for detection"""
    name: str
    confidence: float
    version: Optional[str] = None
    indicators: List[str] = field(default_factory=list)
    fingerprints: Dict[str, str] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)

@dataclass
class DetectionResult:
    """CMS detection result"""
    cms_type: str
    confidence: float
    version: Optional[str] = None
    edition: Optional[str] = None
    theme: Optional[str] = None
    plugins: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    fingerprints: Dict[str, Any] = field(default_factory=dict)
    detection_methods: List[str] = field(default_factory=list)

class CMSFingerprints:
    """Advanced CMS fingerprinting database"""
    
    def __init__(self):
        self.fingerprints = {
            'wordpress': {
                'meta_patterns': [
                    r'<meta name="generator" content="WordPress.*?(\d+\.\d+(?:\.\d+)?)',
                    r'wp-content',
                    r'wp-includes',
                    r'wp-admin'
                ],
                'header_patterns': [
                    r'X-Pingback',
                    r'X-WP-TotalCache',
                    r'X-Powered-By.*WordPress'
                ],
                'content_patterns': [
                    r'wp-content/themes/',
                    r'wp-content/plugins/',
                    r'wp-includes/js/',
                    r'wp-json/',
                    r'xmlrpc\.php',
                    r'wp-login\.php',
                    r'wp-admin/',
                    r'wp-cron\.php'
                ],
                'js_patterns': [
                    r'wp-includes/js/wp-embed\.min\.js',
                    r'wp-includes/js/jquery/jquery\.js',
                    r'wp-content/themes/.*?/.*?\.js'
                ],
                'css_patterns': [
                    r'wp-content/themes/.*?/style\.css',
                    r'wp-includes/css/'
                ],
                'version_patterns': [
                    r'wp-includes/js/wp-embed\.min\.js\?ver=(\d+\.\d+(?:\.\d+)?)',
                    r'wp-includes/css/.*?ver=(\d+\.\d+(?:\.\d+)?)',
                    r'<meta name="generator" content="WordPress (\d+\.\d+(?:\.\d+)?)'
                ],
                'file_paths': [
                    '/wp-config.php',
                    '/wp-admin/',
                    '/wp-content/',
                    '/wp-includes/',
                    '/xmlrpc.php',
                    '/wp-login.php',
                    '/readme.html',
                    '/license.txt'
                ],
                'response_headers': [
                    'X-Pingback',
                    'X-WP-TotalCache',
                    'X-Powered-By'
                ]
            },
            'joomla': {
                'meta_patterns': [
                    r'<meta name="generator" content="Joomla!.*?(\d+\.\d+(?:\.\d+)?)',
                    r'/media/system/js/',
                    r'/administrator/',
                    r'com_content'
                ],
                'content_patterns': [
                    r'/media/system/js/',
                    r'/modules/mod_',
                    r'/components/com_',
                    r'/administrator/',
                    r'option=com_',
                    r'Itemid=',
                    r'task='
                ],
                'js_patterns': [
                    r'/media/system/js/mootools',
                    r'/media/system/js/core',
                    r'/media/jui/js/'
                ],
                'version_patterns': [
                    r'<meta name="generator" content="Joomla! - Open Source Content Management.*?(\d+\.\d+(?:\.\d+)?)',
                    r'/media/system/js/.*?(\d+\.\d+(?:\.\d+)?)'
                ],
                'file_paths': [
                    '/administrator/',
                    '/configuration.php',
                    '/htaccess.txt',
                    '/web.config.txt',
                    '/README.txt',
                    '/LICENSE.txt'
                ]
            },
            'drupal': {
                'meta_patterns': [
                    r'<meta name="generator" content="Drupal.*?(\d+\.?\d*)',
                    r'Drupal\.settings',
                    r'/sites/default/',
                    r'/misc/drupal\.js'
                ],
                'content_patterns': [
                    r'Drupal\.settings',
                    r'/sites/default/',
                    r'/misc/drupal\.js',
                    r'/modules/',
                    r'/themes/',
                    r'drupal_add_css',
                    r'drupal_add_js'
                ],
                'js_patterns': [
                    r'/misc/drupal\.js',
                    r'/misc/jquery\.js',
                    r'Drupal\.behaviors'
                ],
                'version_patterns': [
                    r'<meta name="generator" content="Drupal (\d+\.?\d*)',
                    r'VERSION = "(\d+\.\d+)"'
                ],
                'file_paths': [
                    '/CHANGELOG.txt',
                    '/COPYRIGHT.txt',
                    '/INSTALL.txt',
                    '/LICENSE.txt',
                    '/MAINTAINERS.txt',
                    '/UPGRADE.txt',
                    '/sites/default/',
                    '/misc/',
                    '/modules/',
                    '/themes/'
                ]
            },
            'prestashop': {
                'meta_patterns': [
                    r'<meta name="generator" content="PrestaShop',
                    r'/modules/',
                    r'/themes/',
                    r'prestashop'
                ],
                'content_patterns': [
                    r'/modules/',
                    r'/themes/',
                    r'/cache/',
                    r'/config/',
                    r'/controllers/',
                    r'prestashop',
                    r'id_product',
                    r'id_category'
                ],
                'version_patterns': [
                    r'_PS_VERSION_.*?(\d+\.\d+\.\d+)',
                    r'prestashop.*?(\d+\.\d+\.\d+)'
                ],
                'file_paths': [
                    '/config/config.inc.php',
                    '/cache/',
                    '/modules/',
                    '/themes/',
                    '/admin/',
                    '/controllers/',
                    '/classes/'
                ]
            },
            'opencart': {
                'meta_patterns': [
                    r'Powered by OpenCart',
                    r'OpenCart',
                    r'/catalog/',
                    r'index\.php\?route='
                ],
                'content_patterns': [
                    r'/catalog/',
                    r'/admin/',
                    r'/system/',
                    r'/image/',
                    r'index\.php\?route=',
                    r'product_id=',
                    r'category_id='
                ],
                'version_patterns': [
                    r'OpenCart.*?(\d+\.\d+\.\d+)',
                    r'VERSION.*?(\d+\.\d+\.\d+)'
                ],
                'file_paths': [
                    '/admin/',
                    '/catalog/',
                    '/system/',
                    '/image/',
                    '/config.php',
                    '/admin/config.php'
                ]
            },
            'magento': {
                'meta_patterns': [
                    r'Magento',
                    r'/skin/',
                    r'/js/mage/',
                    r'Mage\.'
                ],
                'content_patterns': [
                    r'/skin/',
                    r'/js/mage/',
                    r'/media/',
                    r'/app/',
                    r'Mage\.',
                    r'catalog/product',
                    r'customer/account'
                ],
                'js_patterns': [
                    r'/js/mage/',
                    r'/js/prototype/',
                    r'/js/varien/'
                ],
                'version_patterns': [
                    r'Mage\.version\s*=\s*["\']([^"\']+)["\']',
                    r'Magento.*?(\d+\.\d+\.\d+)'
                ],
                'file_paths': [
                    '/app/',
                    '/skin/',
                    '/js/',
                    '/media/',
                    '/var/',
                    '/lib/',
                    '/errors/',
                    '/cron.php',
                    '/api.php'
                ]
            }
        }
        
        # Technology detection patterns
        self.technology_patterns = {
            'php': [
                r'\.php',
                r'X-Powered-By.*PHP',
                r'PHPSESSID'
            ],
            'mysql': [
                r'mysql',
                r'MariaDB'
            ],
            'apache': [
                r'Server: Apache',
                r'X-Powered-By.*Apache'
            ],
            'nginx': [
                r'Server: nginx',
                r'X-Powered-By.*nginx'
            ],
            'cloudflare': [
                r'cf-ray',
                r'cloudflare',
                r'__cfduid'
            ],
            'jquery': [
                r'jquery',
                r'jQuery'
            ],
            'bootstrap': [
                r'bootstrap',
                r'Bootstrap'
            ]
        }

class MLCMSDetector:
    """Machine Learning-based CMS detector"""
    
    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.vectorizer = None
        self.model_path = model_path or 'models/cms_detector.joblib'
        self.is_trained = False
        
        if ML_AVAILABLE:
            self._load_or_create_model()
    
    def _load_or_create_model(self):
        """Load existing model or create new one"""
        try:
            if Path(self.model_path).exists():
                self.model = joblib.load(self.model_path)
                self.is_trained = True
                logger.info("ML model loaded successfully")
            else:
                self._create_model()
        except Exception as e:
            logger.error(f"Error loading ML model: {e}")
            self._create_model()
    
    def _create_model(self):
        """Create new ML model"""
        try:
            # Create pipeline with TF-IDF and Naive Bayes
            self.model = Pipeline([
                ('tfidf', TfidfVectorizer(max_features=5000, stop_words='english')),
                ('classifier', MultinomialNB())
            ])
            
            # Train with sample data if available
            training_data = self._get_training_data()
            if training_data:
                self._train_model(training_data)
            
        except Exception as e:
            logger.error(f"Error creating ML model: {e}")
            self.model = None
    
    def _get_training_data(self) -> Optional[Tuple[List[str], List[str]]]:
        """Get training data for ML model"""
        # Sample training data (in real implementation, this would be much larger)
        samples = [
            ("wp-content wp-includes wp-admin WordPress", "wordpress"),
            ("Joomla administrator com_content modules", "joomla"),
            ("Drupal sites/default misc/drupal.js", "drupal"),
            ("PrestaShop modules themes config", "prestashop"),
            ("OpenCart catalog admin system route", "opencart"),
            ("Magento skin js/mage app", "magento"),
            ("wp-json xmlrpc.php wp-login.php", "wordpress"),
            ("media/system/js Joomla! administrator", "joomla"),
            ("Drupal.settings Drupal.behaviors", "drupal"),
            ("prestashop id_product id_category", "prestashop"),
            ("index.php?route= product_id category_id", "opencart"),
            ("Mage. catalog/product customer/account", "magento")
        ]
        
        if len(samples) < 6:  # Not enough training data
            return None
        
        texts, labels = zip(*samples)
        return list(texts), list(labels)
    
    def _train_model(self, training_data: Tuple[List[str], List[str]]):
        """Train the ML model"""
        try:
            texts, labels = training_data
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                texts, labels, test_size=0.2, random_state=42
            )
            
            # Train model
            self.model.fit(X_train, y_train)
            
            # Test model
            y_pred = self.model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            logger.info(f"ML model trained with accuracy: {accuracy:.2f}")
            
            # Save model
            Path(self.model_path).parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(self.model, self.model_path)
            
            self.is_trained = True
            
        except Exception as e:
            logger.error(f"Error training ML model: {e}")
            self.is_trained = False
    
    def predict(self, content: str) -> Optional[Tuple[str, float]]:
        """Predict CMS type using ML model"""
        if not ML_AVAILABLE or not self.model or not self.is_trained:
            return None
        
        try:
            # Predict CMS type
            prediction = self.model.predict([content])[0]
            
            # Get confidence score
            if hasattr(self.model, 'predict_proba'):
                probabilities = self.model.predict_proba([content])[0]
                confidence = max(probabilities)
            else:
                confidence = 0.5  # Default confidence
            
            return prediction, confidence
            
        except Exception as e:
            logger.error(f"ML prediction error: {e}")
            return None
    
    def update_model(self, new_samples: List[Tuple[str, str]]):
        """Update model with new training samples"""
        if not ML_AVAILABLE or not self.model:
            return
        
        try:
            texts, labels = zip(*new_samples)
            
            # Retrain model with new data
            self.model.fit(texts, labels)
            
            # Save updated model
            joblib.dump(self.model, self.model_path)
            
            logger.info(f"Model updated with {len(new_samples)} new samples")
            
        except Exception as e:
            logger.error(f"Error updating ML model: {e}")

class AdvancedCMSDetector:
    """Advanced CMS detection system"""
    
    def __init__(self, use_ml: bool = True):
        self.fingerprints = CMSFingerprints()
        self.ml_detector = MLCMSDetector() if use_ml and ML_AVAILABLE else None
        self.detection_cache = {}
        
    def detect_cms(self, 
                   content: str, 
                   headers: Dict[str, str], 
                   url: str,
                   additional_data: Optional[Dict[str, Any]] = None) -> DetectionResult:
        """Comprehensive CMS detection"""
        
        # Check cache first
        content_hash = hashlib.md5(content.encode()).hexdigest()[:16]
        if content_hash in self.detection_cache:
            return self.detection_cache[content_hash]
        
        # Multiple detection methods
        detection_methods = []
        cms_scores = {}
        
        # 1. Rule-based detection
        rule_results = self._rule_based_detection(content, headers, url)
        for cms, score in rule_results.items():
            cms_scores[cms] = cms_scores.get(cms, 0) + score * 0.4
        detection_methods.append('rule_based')
        
        # 2. ML-based detection
        if self.ml_detector:
            ml_result = self.ml_detector.predict(content)
            if ml_result:
                cms, confidence = ml_result
                cms_scores[cms] = cms_scores.get(cms, 0) + confidence * 0.3
                detection_methods.append('machine_learning')
        
        # 3. Fingerprint-based detection
        fingerprint_results = self._fingerprint_detection(content, headers)
        for cms, score in fingerprint_results.items():
            cms_scores[cms] = cms_scores.get(cms, 0) + score * 0.2
        detection_methods.append('fingerprinting')
        
        # 4. Technology stack analysis
        tech_results = self._technology_detection(content, headers)
        for cms, score in tech_results.items():
            cms_scores[cms] = cms_scores.get(cms, 0) + score * 0.1
        detection_methods.append('technology_stack')
        
        # Select best match
        if cms_scores:
            best_cms = max(cms_scores, key=cms_scores.get)
            confidence = min(cms_scores[best_cms], 1.0)
            
            # Get additional details
            version = self._extract_version(content, headers, best_cms)
            edition = self._extract_edition(content, headers, best_cms)
            theme = self._extract_theme(content, best_cms)
            plugins = self._extract_plugins(content, best_cms)
            technologies = self._extract_technologies(content, headers)
            fingerprints = self._generate_fingerprints(content, headers, url)
            
            result = DetectionResult(
                cms_type=best_cms,
                confidence=confidence,
                version=version,
                edition=edition,
                theme=theme,
                plugins=plugins,
                technologies=technologies,
                fingerprints=fingerprints,
                detection_methods=detection_methods
            )
        else:
            # Unknown CMS
            result = DetectionResult(
                cms_type='unknown',
                confidence=0.0,
                detection_methods=detection_methods
            )
        
        # Cache result
        self.detection_cache[content_hash] = result
        
        return result
    
    def _rule_based_detection(self, content: str, headers: Dict[str, str], url: str) -> Dict[str, float]:
        """Rule-based CMS detection"""
        scores = {}
        
        for cms, patterns in self.fingerprints.fingerprints.items():
            score = 0.0
            total_patterns = 0
            
            # Check meta patterns
            for pattern in patterns.get('meta_patterns', []):
                total_patterns += 1
                if re.search(pattern, content, re.IGNORECASE):
                    score += 0.3
            
            # Check content patterns
            for pattern in patterns.get('content_patterns', []):
                total_patterns += 1
                if re.search(pattern, content, re.IGNORECASE):
                    score += 0.2
            
            # Check header patterns
            header_text = ' '.join(f"{k}: {v}" for k, v in headers.items())
            for pattern in patterns.get('header_patterns', []):
                total_patterns += 1
                if re.search(pattern, header_text, re.IGNORECASE):
                    score += 0.25
            
            # Check JS patterns
            for pattern in patterns.get('js_patterns', []):
                total_patterns += 1
                if re.search(pattern, content, re.IGNORECASE):
                    score += 0.15
            
            # Check CSS patterns
            for pattern in patterns.get('css_patterns', []):
                total_patterns += 1
                if re.search(pattern, content, re.IGNORECASE):
                    score += 0.1
            
            # Normalize score
            if total_patterns > 0:
                scores[cms] = score / total_patterns
        
        return scores
    
    def _fingerprint_detection(self, content: str, headers: Dict[str, str]) -> Dict[str, float]:
        """Fingerprint-based detection"""
        scores = {}
        
        # Generate content fingerprint
        content_fingerprint = self._generate_content_fingerprint(content)
        header_fingerprint = self._generate_header_fingerprint(headers)
        
        # Known fingerprints (in real implementation, this would be a large database)
        known_fingerprints = {
            'wordpress': {
                'content_hashes': ['a1b2c3d4', 'e5f6g7h8'],
                'header_hashes': ['i9j0k1l2', 'm3n4o5p6']
            },
            'joomla': {
                'content_hashes': ['q7r8s9t0', 'u1v2w3x4'],
                'header_hashes': ['y5z6a7b8', 'c9d0e1f2']
            }
        }
        
        for cms, fingerprints in known_fingerprints.items():
            score = 0.0
            
            if content_fingerprint[:8] in fingerprints.get('content_hashes', []):
                score += 0.5
            
            if header_fingerprint[:8] in fingerprints.get('header_hashes', []):
                score += 0.3
            
            if score > 0:
                scores[cms] = score
        
        return scores
    
    def _technology_detection(self, content: str, headers: Dict[str, str]) -> Dict[str, float]:
        """Technology stack detection"""
        scores = {}
        technologies = []
        
        # Detect technologies
        all_text = content + ' ' + ' '.join(f"{k}: {v}" for k, v in headers.items())
        
        for tech, patterns in self.fingerprints.technology_patterns.items():
            for pattern in patterns:
                if re.search(pattern, all_text, re.IGNORECASE):
                    technologies.append(tech)
                    break
        
        # Map technologies to CMS likelihood
        tech_cms_mapping = {
            'php': {'wordpress': 0.3, 'joomla': 0.3, 'drupal': 0.3, 'prestashop': 0.2, 'opencart': 0.2, 'magento': 0.2},
            'mysql': {'wordpress': 0.2, 'joomla': 0.2, 'drupal': 0.2, 'prestashop': 0.2, 'opencart': 0.2, 'magento': 0.2},
            'jquery': {'wordpress': 0.1, 'joomla': 0.1, 'drupal': 0.05}
        }
        
        for tech in technologies:
            if tech in tech_cms_mapping:
                for cms, score in tech_cms_mapping[tech].items():
                    scores[cms] = scores.get(cms, 0) + score
        
        return scores
    
    def _extract_version(self, content: str, headers: Dict[str, str], cms: str) -> Optional[str]:
        """Extract CMS version"""
        if cms not in self.fingerprints.fingerprints:
            return None
        
        patterns = self.fingerprints.fingerprints[cms].get('version_patterns', [])
        
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Check headers for version
        for header, value in headers.items():
            if 'version' in header.lower() or cms in header.lower():
                version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', value)
                if version_match:
                    return version_match.group(1)
        
        return None
    
    def _extract_edition(self, content: str, headers: Dict[str, str], cms: str) -> Optional[str]:
        """Extract CMS edition"""
        edition_patterns = {
            'wordpress': [
                r'WordPress\.com',
                r'WordPress\.org'
            ],
            'magento': [
                r'Community Edition',
                r'Enterprise Edition',
                r'Commerce'
            ],
            'drupal': [
                r'Drupal Commerce',
                r'Drupal Gardens'
            ]
        }
        
        if cms in edition_patterns:
            for pattern in edition_patterns[cms]:
                if re.search(pattern, content, re.IGNORECASE):
                    return pattern
        
        return None
    
    def _extract_theme(self, content: str, cms: str) -> Optional[str]:
        """Extract active theme"""
        theme_patterns = {
            'wordpress': [
                r'wp-content/themes/([^/\'"]+)',
                r'template\s*:\s*["\']([^"\']+)["\']'
            ],
            'joomla': [
                r'/templates/([^/\'"]+)',
                r'template\s*=\s*["\']([^"\']+)["\']'
            ],
            'drupal': [
                r'/themes/([^/\'"]+)',
                r'theme\s*:\s*["\']([^"\']+)["\']'
            ]
        }
        
        if cms in theme_patterns:
            for pattern in theme_patterns[cms]:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    return match.group(1)
        
        return None
    
    def _extract_plugins(self, content: str, cms: str) -> List[str]:
        """Extract installed plugins"""
        plugins = []
        
        plugin_patterns = {
            'wordpress': [
                r'wp-content/plugins/([^/\'"]+)',
                r'wp_register_script\(["\']([^"\']+)["\']'
            ],
            'joomla': [
                r'/plugins/([^/\'"]+)',
                r'com_([a-zA-Z0-9_]+)'
            ],
            'drupal': [
                r'/modules/([^/\'"]+)',
                r'Drupal\.behaviors\.([a-zA-Z0-9_]+)'
            ]
        }
        
        if cms in plugin_patterns:
            for pattern in plugin_patterns[cms]:
                matches = re.findall(pattern, content, re.IGNORECASE)
                plugins.extend(matches)
        
        # Remove duplicates and common false positives
        plugins = list(set(plugins))
        false_positives = ['admin', 'common', 'core', 'system', 'default']
        plugins = [p for p in plugins if p.lower() not in false_positives]
        
        return plugins[:10]  # Limit to 10 plugins
    
    def _extract_technologies(self, content: str, headers: Dict[str, str]) -> List[str]:
        """Extract detected technologies"""
        technologies = []
        all_text = content + ' ' + ' '.join(f"{k}: {v}" for k, v in headers.items())
        
        for tech, patterns in self.fingerprints.technology_patterns.items():
            for pattern in patterns:
                if re.search(pattern, all_text, re.IGNORECASE):
                    technologies.append(tech)
                    break
        
        return technologies
    
    def _generate_fingerprints(self, content: str, headers: Dict[str, str], url: str) -> Dict[str, str]:
        """Generate fingerprints for the target"""
        return {
            'content_hash': hashlib.md5(content.encode()).hexdigest()[:16],
            'header_hash': self._generate_header_fingerprint(headers),
            'url_structure': self._analyze_url_structure(url),
            'dom_structure': self._analyze_dom_structure(content)
        }
    
    def _generate_content_fingerprint(self, content: str) -> str:
        """Generate content-based fingerprint"""
        # Remove dynamic content
        static_content = re.sub(r'\d{4}-\d{2}-\d{2}', '', content)  # Remove dates
        static_content = re.sub(r'\d+', '', static_content)  # Remove numbers
        static_content = re.sub(r'<script.*?</script>', '', static_content, flags=re.DOTALL)  # Remove scripts
        
        return hashlib.md5(static_content.encode()).hexdigest()
    
    def _generate_header_fingerprint(self, headers: Dict[str, str]) -> str:
        """Generate header-based fingerprint"""
        # Sort headers and create fingerprint
        sorted_headers = sorted(headers.items())
        header_string = '|'.join(f"{k}:{v}" for k, v in sorted_headers)
        return hashlib.md5(header_string.encode()).hexdigest()
    
    def _analyze_url_structure(self, url: str) -> str:
        """Analyze URL structure"""
        parsed = urlparse(url)
        
        # Extract patterns from path
        path_parts = [part for part in parsed.path.split('/') if part]
        
        # Common CMS URL patterns
        patterns = []
        if any('wp-' in part for part in path_parts):
            patterns.append('wordpress_pattern')
        if any('administrator' in part for part in path_parts):
            patterns.append('joomla_pattern')
        if 'node' in path_parts:
            patterns.append('drupal_pattern')
        
        return '|'.join(patterns)
    
    def _analyze_dom_structure(self, content: str) -> str:
        """Analyze DOM structure"""
        # Count different HTML elements
        element_counts = {}
        
        # Common HTML elements
        elements = ['div', 'span', 'p', 'a', 'img', 'script', 'link', 'meta']
        
        for element in elements:
            count = len(re.findall(f'<{element}(?:\s|>)', content, re.IGNORECASE))
            element_counts[element] = count
        
        # Create structure signature
        structure_parts = []
        for element, count in sorted(element_counts.items()):
            if count > 0:
                structure_parts.append(f"{element}:{min(count, 999)}")
        
        return '|'.join(structure_parts)
    
    def update_fingerprints(self, cms: str, content: str, headers: Dict[str, str]):
        """Update fingerprint database with new samples"""
        if self.ml_detector:
            # Extract features for ML training
            features = self._extract_ml_features(content, headers)
            self.ml_detector.update_model([(features, cms)])
    
    def _extract_ml_features(self, content: str, headers: Dict[str, str]) -> str:
        """Extract features for ML model"""
        # Combine relevant text features
        features = []
        
        # Extract key terms from content
        important_terms = re.findall(r'\b(?:wp-|drupal|joomla|prestashop|magento|opencart)\w*\b', content, re.IGNORECASE)
        features.extend(important_terms)
        
        # Extract from headers
        for header, value in headers.items():
            if any(term in header.lower() for term in ['server', 'powered', 'version', 'generator']):
                features.append(f"{header}:{value}")
        
        return ' '.join(features)
    
    def get_detection_stats(self) -> Dict[str, Any]:
        """Get detection statistics"""
        if not self.detection_cache:
            return {}
        
        cms_counts = Counter()
        confidence_scores = []
        
        for result in self.detection_cache.values():
            cms_counts[result.cms_type] += 1
            confidence_scores.append(result.confidence)
        
        return {
            'total_detections': len(self.detection_cache),
            'cms_distribution': dict(cms_counts),
            'average_confidence': np.mean(confidence_scores) if confidence_scores else 0,
            'cache_size': len(self.detection_cache)
        }

# Global detector instance
cms_detector = AdvancedCMSDetector()

def detect_cms(content: str, headers: Dict[str, str], url: str) -> DetectionResult:
    """Detect CMS type"""
    return cms_detector.detect_cms(content, headers, url)

def update_cms_fingerprints(cms: str, content: str, headers: Dict[str, str]):
    """Update CMS fingerprints"""
    cms_detector.update_fingerprints(cms, content, headers)