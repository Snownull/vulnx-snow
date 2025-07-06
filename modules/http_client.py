#!/usr/bin/env python3

"""
Enhanced HTTP Client for VulnX
Advanced HTTP client with async support, connection pooling, and evasion techniques
Author: Enhanced by AI for VulnX-Snow 2025
"""

from __future__ import annotations
import asyncio
import aiohttp
import requests
import random
import time
import json
import hashlib
from typing import Dict, List, Optional, Any, Union, Tuple
from urllib.parse import urljoin, urlparse
import logging
from dataclasses import dataclass, field
import ssl
import certifi
from fake_useragent import UserAgent
import concurrent.futures
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import socket

logger = logging.getLogger(__name__)

@dataclass
class RequestStats:
    """Statistics for HTTP requests"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    average_response_time: float = 0.0
    total_bytes_downloaded: int = 0
    response_codes: Dict[int, int] = field(default_factory=dict)
    
    def add_request(self, success: bool, response_time: float, 
                   status_code: int = 0, content_length: int = 0):
        """Add request statistics"""
        self.total_requests += 1
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
        
        # Update average response time
        if self.total_requests == 1:
            self.average_response_time = response_time
        else:
            self.average_response_time = (
                (self.average_response_time * (self.total_requests - 1) + response_time) 
                / self.total_requests
            )
        
        self.total_bytes_downloaded += content_length
        
        if status_code in self.response_codes:
            self.response_codes[status_code] += 1
        else:
            self.response_codes[status_code] = 1

class EvasionTechniques:
    """Advanced evasion techniques for HTTP requests"""
    
    def __init__(self):
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.2210.121',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1'
        ]
        
        self.browser_headers = {
            'chrome': {
                'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'none',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1'
            },
            'firefox': {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'accept-language': 'en-US,en;q=0.5',
                'accept-encoding': 'gzip, deflate, br',
                'upgrade-insecure-requests': '1',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'none',
                'sec-fetch-user': '?1'
            },
            'safari': {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'accept-language': 'en-US,en;q=0.9',
                'accept-encoding': 'gzip, deflate, br',
                'connection': 'keep-alive',
                'upgrade-insecure-requests': '1'
            }
        }
        
        try:
            self.ua = UserAgent()
        except:
            self.ua = None
    
    def get_random_user_agent(self) -> str:
        """Get random user agent"""
        if self.ua:
            try:
                return self.ua.random
            except:
                pass
        return random.choice(self.user_agents)
    
    def get_browser_headers(self, user_agent: str) -> Dict[str, str]:
        """Get browser-specific headers"""
        if 'chrome' in user_agent.lower():
            return self.browser_headers['chrome'].copy()
        elif 'firefox' in user_agent.lower():
            return self.browser_headers['firefox'].copy()
        elif 'safari' in user_agent.lower():
            return self.browser_headers['safari'].copy()
        else:
            return self.browser_headers['chrome'].copy()
    
    def randomize_headers(self, base_headers: Dict[str, str]) -> Dict[str, str]:
        """Randomize HTTP headers"""
        headers = base_headers.copy()
        
        # Random user agent
        user_agent = self.get_random_user_agent()
        headers['User-Agent'] = user_agent
        
        # Add browser-specific headers
        browser_headers = self.get_browser_headers(user_agent)
        headers.update(browser_headers)
        
        # Random accept-language
        languages = [
            'en-US,en;q=0.9',
            'en-GB,en;q=0.9',
            'en-CA,en;q=0.9',
            'en-AU,en;q=0.9',
            'es-ES,es;q=0.9',
            'fr-FR,fr;q=0.9',
            'de-DE,de;q=0.9',
            'it-IT,it;q=0.9',
            'pt-BR,pt;q=0.9',
            'ru-RU,ru;q=0.9'
        ]
        headers['Accept-Language'] = random.choice(languages)
        
        # Random accept-encoding
        encodings = [
            'gzip, deflate, br',
            'gzip, deflate',
            'gzip',
            'deflate',
            'br'
        ]
        headers['Accept-Encoding'] = random.choice(encodings)
        
        # Random DNT header
        if random.choice([True, False]):
            headers['DNT'] = '1'
        
        # Random connection header
        if random.choice([True, False]):
            headers['Connection'] = random.choice(['keep-alive', 'close'])
        
        return headers
    
    def add_evasion_headers(self, headers: Dict[str, str], target_url: str) -> Dict[str, str]:
        """Add evasion headers"""
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc
        
        # Random X-Forwarded headers
        fake_ips = [
            '127.0.0.1',
            '192.168.1.1',
            '10.0.0.1',
            '172.16.0.1',
            f'{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}'
        ]
        
        evasion_headers = {
            'X-Forwarded-For': random.choice(fake_ips),
            'X-Real-IP': random.choice(fake_ips),
            'X-Originating-IP': random.choice(fake_ips),
            'X-Remote-IP': random.choice(fake_ips),
            'X-Remote-Addr': random.choice(fake_ips)
        }
        
        # Add random subset of evasion headers
        num_headers = random.randint(1, len(evasion_headers))
        selected_headers = dict(random.sample(list(evasion_headers.items()), num_headers))
        
        headers.update(selected_headers)
        
        # Random referer
        referers = [
            f'https://www.google.com/search?q={domain}',
            f'https://www.bing.com/search?q={domain}',
            f'https://duckduckgo.com/?q={domain}',
            f'https://{domain}/',
            f'https://www.{domain}/',
            'https://www.google.com/',
            'https://www.bing.com/',
            'https://duckduckgo.com/'
        ]
        
        if random.choice([True, False]):
            headers['Referer'] = random.choice(referers)
        
        return headers
    
    def get_random_delay(self, min_delay: float = 0.5, max_delay: float = 2.0) -> float:
        """Get random delay for rate limiting evasion"""
        return random.uniform(min_delay, max_delay)
    
    def generate_session_fingerprint(self) -> str:
        """Generate unique session fingerprint"""
        timestamp = str(time.time())
        random_data = str(random.random())
        return hashlib.md5((timestamp + random_data).encode()).hexdigest()[:16]

class EnhancedHTTPClient:
    """Enhanced HTTP client with advanced features"""
    
    def __init__(self, 
                 timeout: int = 10,
                 max_retries: int = 3,
                 backoff_factor: float = 0.3,
                 pool_connections: int = 10,
                 pool_maxsize: int = 10,
                 enable_evasion: bool = True,
                 rate_limit: Optional[float] = None):
        
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.enable_evasion = enable_evasion
        self.rate_limit = rate_limit
        self.last_request_time = 0
        
        self.stats = RequestStats()
        self.evasion = EvasionTechniques()
        
        # Configure session with retry strategy
        self.session = requests.Session()
        
        retry_strategy = Retry(
            total=max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS", "POST"],
            backoff_factor=backoff_factor
        )
        
        adapter = HTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=retry_strategy
        )
        
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # SSL configuration
        self.session.verify = certifi.where()
        
        # Default headers
        self.default_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
    
    def _apply_rate_limiting(self):
        """Apply rate limiting"""
        if self.rate_limit:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            if time_since_last < self.rate_limit:
                sleep_time = self.rate_limit - time_since_last
                time.sleep(sleep_time)
            self.last_request_time = time.time()
    
    def _prepare_headers(self, headers: Optional[Dict[str, str]], url: str) -> Dict[str, str]:
        """Prepare headers with evasion techniques"""
        final_headers = self.default_headers.copy()
        
        if headers:
            final_headers.update(headers)
        
        if self.enable_evasion:
            final_headers = self.evasion.randomize_headers(final_headers)
            final_headers = self.evasion.add_evasion_headers(final_headers, url)
        
        return final_headers
    
    def request(self, 
                method: str, 
                url: str, 
                headers: Optional[Dict[str, str]] = None,
                data: Optional[Union[Dict, str, bytes]] = None,
                json_data: Optional[Dict] = None,
                params: Optional[Dict[str, str]] = None,
                files: Optional[Dict] = None,
                allow_redirects: bool = True,
                verify_ssl: bool = False,
                stream: bool = False,
                **kwargs) -> Optional[requests.Response]:
        """Make HTTP request with enhanced features"""
        
        start_time = time.time()
        
        try:
            # Apply rate limiting
            self._apply_rate_limiting()
            
            # Add random delay for evasion
            if self.enable_evasion:
                delay = self.evasion.get_random_delay()
                time.sleep(delay)
            
            # Prepare headers
            final_headers = self._prepare_headers(headers, url)
            
            # Make request
            response = self.session.request(
                method=method,
                url=url,
                headers=final_headers,
                data=data,
                json=json_data,
                params=params,
                files=files,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                verify=verify_ssl,
                stream=stream,
                **kwargs
            )
            
            # Update statistics
            response_time = time.time() - start_time
            content_length = len(response.content) if response.content else 0
            
            self.stats.add_request(
                success=True,
                response_time=response_time,
                status_code=response.status_code,
                content_length=content_length
            )
            
            logger.debug(f"{method} {url} - {response.status_code} - {response_time:.2f}s")
            
            return response
            
        except Exception as e:
            response_time = time.time() - start_time
            self.stats.add_request(success=False, response_time=response_time)
            logger.error(f"Request failed: {method} {url} - {e}")
            return None
    
    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make GET request"""
        return self.request('GET', url, **kwargs)
    
    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make POST request"""
        return self.request('POST', url, **kwargs)
    
    def put(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make PUT request"""
        return self.request('PUT', url, **kwargs)
    
    def delete(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make DELETE request"""
        return self.request('DELETE', url, **kwargs)
    
    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make HEAD request"""
        return self.request('HEAD', url, **kwargs)
    
    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make OPTIONS request"""
        return self.request('OPTIONS', url, **kwargs)
    
    def get_stats(self) -> RequestStats:
        """Get request statistics"""
        return self.stats
    
    def reset_stats(self):
        """Reset request statistics"""
        self.stats = RequestStats()
    
    def close(self):
        """Close session"""
        self.session.close()

class AsyncHTTPClient:
    """Async HTTP client for concurrent requests"""
    
    def __init__(self,
                 timeout: int = 10,
                 max_connections: int = 100,
                 max_connections_per_host: int = 10,
                 enable_evasion: bool = True,
                 rate_limit: Optional[float] = None):
        
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_connections = max_connections
        self.max_connections_per_host = max_connections_per_host
        self.enable_evasion = enable_evasion
        self.rate_limit = rate_limit
        
        self.stats = RequestStats()
        self.evasion = EvasionTechniques()
        
        # SSL context
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Connector with connection pooling
        self.connector = aiohttp.TCPConnector(
            limit=max_connections,
            limit_per_host=max_connections_per_host,
            ssl=ssl_context,
            enable_cleanup_closed=True
        )
        
        self.session = None
        self._semaphore = asyncio.Semaphore(max_connections)
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            connector=self.connector,
            timeout=self.timeout
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
        await self.connector.close()
    
    async def _apply_rate_limiting(self):
        """Apply async rate limiting"""
        if self.rate_limit:
            await asyncio.sleep(self.rate_limit)
    
    def _prepare_headers(self, headers: Optional[Dict[str, str]], url: str) -> Dict[str, str]:
        """Prepare headers with evasion techniques"""
        default_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        
        final_headers = default_headers.copy()
        
        if headers:
            final_headers.update(headers)
        
        if self.enable_evasion:
            final_headers = self.evasion.randomize_headers(final_headers)
            final_headers = self.evasion.add_evasion_headers(final_headers, url)
        
        return final_headers
    
    async def request(self,
                     method: str,
                     url: str,
                     headers: Optional[Dict[str, str]] = None,
                     data: Optional[Union[Dict, str, bytes]] = None,
                     json_data: Optional[Dict] = None,
                     params: Optional[Dict[str, str]] = None,
                     **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make async HTTP request"""
        
        if not self.session:
            raise RuntimeError("AsyncHTTPClient must be used as async context manager")
        
        async with self._semaphore:
            start_time = time.time()
            
            try:
                # Apply rate limiting
                await self._apply_rate_limiting()
                
                # Add random delay for evasion
                if self.enable_evasion:
                    delay = self.evasion.get_random_delay()
                    await asyncio.sleep(delay)
                
                # Prepare headers
                final_headers = self._prepare_headers(headers, url)
                
                # Make request
                async with self.session.request(
                    method=method,
                    url=url,
                    headers=final_headers,
                    data=data,
                    json=json_data,
                    params=params,
                    **kwargs
                ) as response:
                    
                    # Read response content
                    content = await response.read()
                    
                    # Update statistics
                    response_time = time.time() - start_time
                    content_length = len(content) if content else 0
                    
                    self.stats.add_request(
                        success=True,
                        response_time=response_time,
                        status_code=response.status,
                        content_length=content_length
                    )
                    
                    logger.debug(f"ASYNC {method} {url} - {response.status} - {response_time:.2f}s")
                    
                    # Create response-like object
                    response._content = content
                    return response
                    
            except Exception as e:
                response_time = time.time() - start_time
                self.stats.add_request(success=False, response_time=response_time)
                logger.error(f"Async request failed: {method} {url} - {e}")
                return None
    
    async def get(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make async GET request"""
        return await self.request('GET', url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make async POST request"""
        return await self.request('POST', url, **kwargs)
    
    async def batch_requests(self, requests_data: List[Dict[str, Any]]) -> List[Optional[aiohttp.ClientResponse]]:
        """Make multiple async requests concurrently"""
        tasks = []
        
        for request_data in requests_data:
            method = request_data.get('method', 'GET')
            url = request_data.get('url')
            kwargs = {k: v for k, v in request_data.items() if k not in ['method', 'url']}
            
            task = asyncio.create_task(self.request(method, url, **kwargs))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        responses = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Batch request failed: {result}")
                responses.append(None)
            else:
                responses.append(result)
        
        return responses
    
    def get_stats(self) -> RequestStats:
        """Get request statistics"""
        return self.stats

class HTTPClientManager:
    """Manager for HTTP clients with smart selection"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._sync_client = None
        self._async_client = None
        
    def get_sync_client(self, **kwargs) -> EnhancedHTTPClient:
        """Get synchronous HTTP client"""
        if not self._sync_client:
            client_config = self.config.copy()
            client_config.update(kwargs)
            self._sync_client = EnhancedHTTPClient(**client_config)
        return self._sync_client
    
    def get_async_client(self, **kwargs) -> AsyncHTTPClient:
        """Get asynchronous HTTP client"""
        if not self._async_client:
            client_config = self.config.copy()
            client_config.update(kwargs)
            self._async_client = AsyncHTTPClient(**client_config)
        return self._async_client
    
    def close_all(self):
        """Close all clients"""
        if self._sync_client:
            self._sync_client.close()
        
        # Async client closes automatically with context manager
    
    async def smart_request(self, 
                           urls: Union[str, List[str]],
                           method: str = 'GET',
                           use_async: bool = None,
                           **kwargs) -> Union[requests.Response, List[requests.Response]]:
        """Smart request selection between sync and async"""
        
        if isinstance(urls, str):
            urls = [urls]
        
        # Auto-select async for multiple URLs
        if use_async is None:
            use_async = len(urls) > 5
        
        if use_async:
            async with self.get_async_client() as client:
                requests_data = [{'method': method, 'url': url, **kwargs} for url in urls]
                responses = await client.batch_requests(requests_data)
                return responses[0] if len(responses) == 1 else responses
        else:
            client = self.get_sync_client()
            responses = []
            for url in urls:
                response = client.request(method, url, **kwargs)
                responses.append(response)
            return responses[0] if len(responses) == 1 else responses

# Global HTTP client manager
http_manager = HTTPClientManager()

def get_http_client(async_client: bool = False, **kwargs) -> Union[EnhancedHTTPClient, AsyncHTTPClient]:
    """Get HTTP client instance"""
    if async_client:
        return http_manager.get_async_client(**kwargs)
    else:
        return http_manager.get_sync_client(**kwargs)

async def make_async_requests(requests_data: List[Dict[str, Any]]) -> List[Optional[aiohttp.ClientResponse]]:
    """Make multiple async requests"""
    async with http_manager.get_async_client() as client:
        return await client.batch_requests(requests_data)