#!/usr/bin/env python3
"""
安全請求處理工具
提供安全的 HTTP 請求處理功能
"""

import asyncio
import aiohttp
import logging
from typing import Optional, Dict, Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class SafeRequestHandler:
    """安全請求處理器"""

    def __init__(self):
        self.timeout = aiohttp.ClientTimeout(total=30, connect=10)

    async def safe_get(self, session: aiohttp.ClientSession, url: str,
                       timeout: int = 30, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """安全的 GET 請求"""
        try:
            # 驗證 URL
            if not self._validate_url(url):
                logger.warning(f"無效的 URL: {url}")
                return None

            # 設定安全頭部
            headers = kwargs.get('headers', {})
            headers.update(self._get_safe_headers())
            kwargs['headers'] = headers

            # 設定超時
            custom_timeout = aiohttp.ClientTimeout(total=timeout)

            response = await session.get(url, timeout=custom_timeout, **kwargs)
            return response

        except asyncio.TimeoutError:
            logger.warning(f"請求超時: {url}")
        except aiohttp.ClientError as e:
            logger.warning(f"客戶端錯誤 {url}: {str(e)}")
        except Exception as e:
            logger.error(f"請求錯誤 {url}: {str(e)}")

        return None

    async def safe_post(self, session: aiohttp.ClientSession, url: str,
                        data: Any = None, timeout: int = 30, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """安全的 POST 請求"""
        try:
            if not self._validate_url(url):
                logger.warning(f"無效的 URL: {url}")
                return None

            headers = kwargs.get('headers', {})
            headers.update(self._get_safe_headers())
            kwargs['headers'] = headers

            custom_timeout = aiohttp.ClientTimeout(total=timeout)

            async with session.post(url, data=data, timeout=custom_timeout, **kwargs) as response:
                return response

        except asyncio.TimeoutError:
            logger.warning(f"POST 請求超時: {url}")
        except aiohttp.ClientError as e:
            logger.warning(f"POST 客戶端錯誤 {url}: {str(e)}")
        except Exception as e:
            logger.error(f"POST 請求錯誤 {url}: {str(e)}")

        return None

    async def safe_head(self, session: aiohttp.ClientSession, url: str,
                        timeout: int = 10, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """安全的 HEAD 請求"""
        try:
            if not self._validate_url(url):
                logger.warning(f"無效的 URL: {url}")
                return None

            headers = kwargs.get('headers', {})
            headers.update(self._get_safe_headers())
            kwargs['headers'] = headers

            custom_timeout = aiohttp.ClientTimeout(total=timeout)

            response = await session.head(url, timeout=custom_timeout, **kwargs)
            return response

        except asyncio.TimeoutError:
            logger.warning(f"HEAD 請求超時: {url}")
        except aiohttp.ClientError as e:
            logger.warning(f"HEAD 客戶端錯誤 {url}: {str(e)}")
        except Exception as e:
            logger.error(f"HEAD 請求錯誤 {url}: {str(e)}")

        return None

    def _validate_url(self, url: str) -> bool:
        """驗證 URL 安全性"""
        try:
            parsed = urlparse(url)

            # 檢查協議
            if parsed.scheme not in ['http', 'https']:
                return False

            # 檢查主機名
            if not parsed.hostname:
                return False

            # 檢查是否為私有 IP（可選的安全檢查）
            hostname = parsed.hostname.lower()
            if hostname in ['localhost', '127.0.0.1']:
                logger.warning(f"檢測到本地地址: {hostname}")

            return True

        except Exception:
            return False

    def _get_safe_headers(self) -> Dict[str, str]:
        """獲取安全的 HTTP 頭部"""
        return {
            'User-Agent': 'WebSecScan/1.0 Security Scanner',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }