#!/usr/bin/env python3

"""
Enhanced VulnX CLI Interface
Modern CLI interface showcasing all enhanced features
Author: Enhanced by AI for VulnX-Snow 2025
"""

import sys
import argparse
import asyncio
import time
from pathlib import Path
from typing import List, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Import new modules
from modules.config import ConfigManager, VulnXConfig
from modules.http_client import HTTPClientManager
from modules.advanced_detection import AdvancedCMSDetector
from modules.detector import CMS

# Import existing modules
from common.colors import red, green, bg, G, R, W, Y, good, bad, run, info, end, que, bannerblue2
from common.requestUp import random_UserAgent
from common.banner import banner

def create_enhanced_parser():
    """Create enhanced argument parser"""
    parser = argparse.ArgumentParser(
        description='VulnX-Snow - Enhanced CMS Vulnerability Scanner 2025',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic scan with modern features
  python3 vulnx_enhanced.py -u https://example.com --enhanced

  # Aggressive scan with ML detection
  python3 vulnx_enhanced.py -u https://example.com --aggressive --ml-detection

  # Async batch scan
  python3 vulnx_enhanced.py -i targets.txt --async-mode --threads 20

  # Configuration wizard
  python3 vulnx_enhanced.py --config-wizard

  # Export results
  python3 vulnx_enhanced.py -u https://example.com --export json --output results.json
        '''
    )

    # Target options
    target_group = parser.add_argument_group('Target Options')
    target_group.add_argument('-u', '--url', help='Target URL to scan')
    target_group.add_argument('-i', '--input', help='Input file with target URLs')
    target_group.add_argument('-t', '--targets', nargs='+', help='Multiple target URLs')

    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument('--enhanced', action='store_true', 
                           help='Enable enhanced scanning features')
    scan_group.add_argument('--ml-detection', action='store_true',
                           help='Enable ML-based CMS detection')
    scan_group.add_argument('--aggressive', action='store_true',
                           help='Enable aggressive scanning mode')
    scan_group.add_argument('--async-mode', action='store_true',
                           help='Use async HTTP client for better performance')
    scan_group.add_argument('--threads', type=int, default=10,
                           help='Number of concurrent threads')
    scan_group.add_argument('--timeout', type=int, default=10,
                           help='Request timeout in seconds')
    scan_group.add_argument('--retries', type=int, default=3,
                           help='Number of retry attempts')

    # Detection options
    detection_group = parser.add_argument_group('Detection Options')
    detection_group.add_argument('--cms-only', action='store_true',
                                help='Only perform CMS detection')
    detection_group.add_argument('--version-detection', action='store_true',
                                help='Perform detailed version detection')
    detection_group.add_argument('--plugin-detection', action='store_true',
                                help='Detect installed plugins/modules')
    detection_group.add_argument('--theme-detection', action='store_true',
                                help='Detect active themes')

    # Exploit options
    exploit_group = parser.add_argument_group('Exploit Options')
    exploit_group.add_argument('-e', '--exploit', action='store_true',
                              help='Run vulnerability exploits')
    exploit_group.add_argument('--cms-types', nargs='+',
                              choices=['wordpress', 'joomla', 'drupal', 'prestashop', 'opencart', 'magento'],
                              help='Specific CMS types to test')
    exploit_group.add_argument('--auto-exploit', action='store_true',
                              help='Automatically exploit found vulnerabilities')

    # Evasion options
    evasion_group = parser.add_argument_group('Evasion Options')
    evasion_group.add_argument('--evasion', action='store_true',
                              help='Enable advanced evasion techniques')
    evasion_group.add_argument('--rate-limit', type=float,
                              help='Rate limiting (requests per second)')
    evasion_group.add_argument('--user-agent', help='Custom user agent')
    evasion_group.add_argument('--proxy', help='HTTP/HTTPS proxy')
    evasion_group.add_argument('--random-delay', action='store_true',
                              help='Add random delays between requests')

    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output', help='Output file path')
    output_group.add_argument('--format', choices=['json', 'xml', 'csv', 'html'],
                             default='json', help='Output format')
    output_group.add_argument('--export', choices=['json', 'xml', 'csv', 'html'],
                             help='Export results in specified format')
    output_group.add_argument('--verbose', '-v', action='store_true',
                             help='Verbose output')
    output_group.add_argument('--quiet', '-q', action='store_true',
                             help='Quiet mode')

    # Configuration options
    config_group = parser.add_argument_group('Configuration Options')
    config_group.add_argument('--config', help='Configuration file path')
    config_group.add_argument('--config-wizard', action='store_true',
                             help='Launch configuration wizard')
    config_group.add_argument('--save-config', action='store_true',
                             help='Save current settings to config')

    # Information options
    info_group = parser.add_argument_group('Information Options')
    info_group.add_argument('--stats', action='store_true',
                           help='Show scanning statistics')
    info_group.add_argument('--version', action='version',
                           version='VulnX-Snow Enhanced 3.0.0')

    return parser

def load_targets(args) -> List[str]:
    """Load target URLs from various sources"""
    targets = []
    
    if args.url:
        targets.append(args.url)
    
    if args.targets:
        targets.extend(args.targets)
    
    if args.input:
        try:
            with open(args.input, 'r') as f:
                file_targets = [line.strip() for line in f if line.strip()]
                targets.extend(file_targets)
        except FileNotFoundError:
            print(f"{R}[ERROR]{W} Input file not found: {args.input}")
            sys.exit(1)
    
    if not targets:
        print(f"{R}[ERROR]{W} No targets specified")
        sys.exit(1)
    
    return targets

def setup_configuration(args) -> VulnXConfig:
    """Setup configuration based on arguments"""
    config_manager = ConfigManager()
    
    # Load existing config or create new one
    if args.config:
        config_manager.import_config(args.config)
        config = config_manager.config
    elif Path('~/.vulnx/config.json').expanduser().exists():
        config = config_manager.load_config()
    else:
        config = VulnXConfig()
    
    # Update config with command line arguments
    if args.threads:
        config.scan.threads = args.threads
    if args.timeout:
        config.scan.timeout = args.timeout
    if args.retries:
        config.scan.retries = args.retries
    if args.aggressive:
        config.exploit.aggressive_mode = True
    if args.auto_exploit:
        config.exploit.auto_exploit = True
    if args.evasion:
        config.security.waf_evasion = True
        config.security.fingerprint_resistance = True
    if args.rate_limit:
        config.security.requests_per_second = int(1.0 / args.rate_limit)
    if args.format:
        config.output.format = args.format
    
    # Save config if requested
    if args.save_config:
        config_manager.save_config(config)
        print(f"{G}[INFO]{W} Configuration saved")
    
    return config

async def enhanced_scan(target: str, config: VulnXConfig, args) -> dict:
    """Perform enhanced scan on target"""
    print(f"\n{G}[SCANNING]{W} {target}")
    
    results = {
        'target': target,
        'timestamp': time.time(),
        'cms_detection': None,
        'vulnerabilities': [],
        'statistics': {}
    }
    
    try:
        # Initialize HTTP client
        http_manager = HTTPClientManager({
            'timeout': config.scan.timeout,
            'max_retries': config.scan.retries,
            'enable_evasion': config.security.waf_evasion,
            'rate_limit': 1.0 / config.security.requests_per_second if config.security.requests_per_second > 0 else None
        })
        
        # Get page content
        if args.async_mode:
            async with http_manager.get_async_client() as client:
                response = await client.get(target)
        else:
            client = http_manager.get_sync_client()
            response = client.get(target)
        
        if not response:
            print(f"{R}[ERROR]{W} Failed to connect to {target}")
            return results
        
        content = response.text if hasattr(response, 'text') else response.read().decode()
        headers = dict(response.headers)
        
        # Enhanced CMS detection
        if args.enhanced or args.ml_detection:
            detector = AdvancedCMSDetector(use_ml=args.ml_detection)
            detection_result = detector.detect_cms(content, headers, target)
            
            results['cms_detection'] = {
                'cms_type': detection_result.cms_type,
                'confidence': detection_result.confidence,
                'version': detection_result.version,
                'edition': detection_result.edition,
                'theme': detection_result.theme,
                'plugins': detection_result.plugins,
                'technologies': detection_result.technologies,
                'detection_methods': detection_result.detection_methods
            }
            
            print(f"{G}[DETECTED]{W} CMS: {detection_result.cms_type} (Confidence: {detection_result.confidence:.2f})")
            if detection_result.version:
                print(f"{G}[VERSION]{W} {detection_result.version}")
            if detection_result.theme:
                print(f"{G}[THEME]{W} {detection_result.theme}")
            if detection_result.plugins:
                print(f"{G}[PLUGINS]{W} {', '.join(detection_result.plugins[:5])}")
        
        # Traditional detection for comparison
        else:
            traditional_cms = CMS(
                url=target,
                headers={'User-Agent': random_UserAgent()},
                exploit=args.exploit,
                domain=False,
                webinfo=False,
                serveros=False,
                cmsinfo=True,
                dnsdump=False,
                port=False
            )
            
            cms_name = traditional_cms.detect()
            if cms_name:
                results['cms_detection'] = {
                    'cms_type': cms_name,
                    'confidence': 0.8,  # Default confidence for traditional detection
                    'detection_methods': ['traditional']
                }
                print(f"{G}[DETECTED]{W} CMS: {cms_name}")
        
        # Run exploits if requested
        if args.exploit and results['cms_detection']:
            cms_type = results['cms_detection']['cms_type']
            
            if cms_type != 'unknown':
                print(f"{Y}[EXPLOITING]{W} Running {cms_type} exploits...")
                
                # Run traditional exploit system
                exploit_cms = CMS(
                    url=target,
                    headers={'User-Agent': random_UserAgent()},
                    exploit=True,
                    domain=False,
                    webinfo=False,
                    serveros=False,
                    cmsinfo=False,
                    dnsdump=False,
                    port=False
                )
                
                try:
                    exploit_cms.instanciate()
                except Exception as e:
                    print(f"{R}[ERROR]{W} Exploit execution failed: {e}")
        
        # Get statistics if available
        if hasattr(client, 'get_stats'):
            stats = client.get_stats()
            results['statistics'] = {
                'total_requests': stats.total_requests,
                'successful_requests': stats.successful_requests,
                'failed_requests': stats.failed_requests,
                'average_response_time': stats.average_response_time,
                'total_bytes_downloaded': stats.total_bytes_downloaded
            }
        
    except Exception as e:
        print(f"{R}[ERROR]{W} Scan failed: {e}")
        results['error'] = str(e)
    
    return results

async def main():
    """Main function"""
    # Show banner
    banner()
    
    # Parse arguments
    parser = create_enhanced_parser()
    args = parser.parse_args()
    
    # Configuration wizard
    if args.config_wizard:
        config_manager = ConfigManager()
        config_manager.create_config_wizard()
        return
    
    # Load targets
    targets = load_targets(args)
    
    # Setup configuration
    config = setup_configuration(args)
    
    print(f"\n{G}[INFO]{W} VulnX-Snow Enhanced Scanner")
    print(f"{G}[INFO]{W} Targets: {len(targets)}")
    print(f"{G}[INFO]{W} Enhanced Mode: {'Enabled' if args.enhanced else 'Disabled'}")
    print(f"{G}[INFO]{W} ML Detection: {'Enabled' if args.ml_detection else 'Disabled'}")
    print(f"{G}[INFO]{W} Async Mode: {'Enabled' if args.async_mode else 'Disabled'}")
    
    # Scan targets
    all_results = []
    start_time = time.time()
    
    for target in targets:
        result = await enhanced_scan(target, config, args)
        all_results.append(result)
    
    total_time = time.time() - start_time
    
    # Show summary
    print(f"\n{G}[SUMMARY]{W}")
    print(f"Total targets scanned: {len(targets)}")
    print(f"Total time: {total_time:.2f} seconds")
    print(f"Average time per target: {total_time/len(targets):.2f} seconds")
    
    # CMS detection summary
    cms_counts = {}
    for result in all_results:
        if result.get('cms_detection'):
            cms_type = result['cms_detection']['cms_type']
            cms_counts[cms_type] = cms_counts.get(cms_type, 0) + 1
    
    if cms_counts:
        print(f"\n{G}[CMS DISTRIBUTION]{W}")
        for cms, count in cms_counts.items():
            print(f"  {cms}: {count}")
    
    # Export results if requested
    if args.export or args.output:
        import json
        output_file = args.output or f"vulnx_results_{int(time.time())}.{args.export or args.format}"
        
        export_data = {
            'scan_info': {
                'targets': len(targets),
                'total_time': total_time,
                'enhanced_mode': args.enhanced,
                'ml_detection': args.ml_detection,
                'timestamp': time.time()
            },
            'results': all_results,
            'summary': {
                'cms_distribution': cms_counts,
                'total_targets': len(targets),
                'successful_scans': len([r for r in all_results if 'error' not in r])
            }
        }
        
        try:
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2)
            print(f"{G}[EXPORT]{W} Results saved to {output_file}")
        except Exception as e:
            print(f"{R}[ERROR]{W} Failed to save results: {e}")
    
    # Show statistics if requested
    if args.stats:
        print(f"\n{G}[STATISTICS]{W}")
        total_requests = sum(r.get('statistics', {}).get('total_requests', 0) for r in all_results)
        total_bytes = sum(r.get('statistics', {}).get('total_bytes_downloaded', 0) for r in all_results)
        
        print(f"Total HTTP requests: {total_requests}")
        print(f"Total bytes downloaded: {total_bytes:,}")
        print(f"Average requests per target: {total_requests/len(targets):.1f}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Y}[INTERRUPTED]{W} Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n{R}[FATAL ERROR]{W} {e}")
        sys.exit(1)