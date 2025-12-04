#!/usr/bin/env python3
"""
WebSecScan 連接性測試
簡化版測試腳本，用於驗證目標連接性
"""

import asyncio
import aiohttp
import ssl
import logging
import os
import sys
from pathlib import Path

# 添加當前目錄到 Python 路徑
current_dir = Path(__file__).parent.absolute()
sys.path.insert(0, str(current_dir))

from utils.safe_request import SafeRequestHandler

# 設定日誌
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def test_connectivity(target_url: str):
    """測試目標連接性"""
    logger.info(f"🔍 測試連接到: {target_url}")

    # 建立 SSL 上下文
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    # 建立連接器
    connector = aiohttp.TCPConnector(
        ssl=ssl_context,
        limit=10,
        limit_per_host=5,
        ttl_dns_cache=300,
    )

    # 設定超時
    timeout = aiohttp.ClientTimeout(total=30, connect=10)

    try:
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'WebSecScan/1.0 Test'}
        ) as session:

            # 創建安全請求處理器
            request_handler = SafeRequestHandler()

            # 測試 GET 請求
            logger.info("發送 GET 請求...")
            response = await request_handler.safe_get(session, target_url, timeout=10)

            if response is None:
                logger.error("❌ 無法連接到目標")
                return False
            else:
                logger.info(f"✅ 連接成功! 狀態碼: {response.status}")
                logger.info(f"📊 回應標頭: {dict(response.headers)}")

                # 嘗試讀取內容
                try:
                    content = await response.text()
                    logger.info(f"📄 內容長度: {len(content)} 字符")
                    logger.info(f"📝 內容預覽: {content[:200]}...")
                    return True
                except Exception as e:
                    logger.warning(f"⚠️ 無法讀取回應內容: {str(e)}")
                    return True  # 連接成功，但讀取內容失敗

    except Exception as e:
        logger.error(f"❌ 連接錯誤: {str(e)}")
        return False

async def main():
    """主測試函數"""
    target_url = "http://192.168.250.35:8081/"

    logger.info("🛡️ WebSecScan 連接性測試開始")
    logger.info(f"🎯 目標: {target_url}")

    # 清除代理設置
    for proxy_var in ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY']:
        if proxy_var in os.environ:
            del os.environ[proxy_var]
            logger.info(f"🔧 清除代理設置: {proxy_var}")

    success = await test_connectivity(target_url)

    if success:
        logger.info("🎉 連接性測試通過!")
        return 0
    else:
        logger.error("💥 連接性測試失敗!")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)