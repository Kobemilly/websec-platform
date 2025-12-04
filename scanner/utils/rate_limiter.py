#!/usr/bin/env python3
"""
速率限制器
控制 HTTP 請求頻率，避免對目標造成過大負擔
"""

import asyncio
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class RateLimiter:
    """速率限制器"""

    def __init__(self, requests_per_second: float = 5.0):
        """
        初始化速率限制器

        Args:
            requests_per_second: 每秒允許的請求數量
        """
        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second if requests_per_second > 0 else 0
        self.last_request_time = 0.0
        self._lock = asyncio.Lock()

    async def __aenter__(self):
        """異步上下文管理器入口"""
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """異步上下文管理器出口"""
        pass

    async def acquire(self):
        """獲取請求許可"""
        if self.min_interval <= 0:
            return

        async with self._lock:
            current_time = time.time()
            time_since_last_request = current_time - self.last_request_time

            if time_since_last_request < self.min_interval:
                sleep_time = self.min_interval - time_since_last_request
                logger.debug(f"速率限制: 等待 {sleep_time:.3f} 秒")
                await asyncio.sleep(sleep_time)

            self.last_request_time = time.time()

    def set_rate(self, requests_per_second: float):
        """動態調整速率限制"""
        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second if requests_per_second > 0 else 0
        logger.info(f"速率限制已調整為: {requests_per_second} 請求/秒")