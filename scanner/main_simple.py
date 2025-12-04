#!/usr/bin/env python3
"""
WebSecScan 掃描引擎主程式 - 簡化版本
用於測試基本掃描功能
"""

import asyncio
import logging
import os
import sys
import time
from pathlib import Path

# 添加當前目錄到 Python 路徑
current_dir = Path(__file__).parent.absolute()
sys.path.insert(0, str(current_dir))

from core.scanner_engine import ScannerEngine, ScanTarget

# 設定日誌
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def load_config():
    """載入配置"""
    return {
        'rate_limit': int(os.getenv('SCANNER_RATE_LIMIT', '2')),  # 降低速率限制
        'max_workers': int(os.getenv('SCANNER_MAX_WORKERS', '2')),  # 減少工作者
        'total_timeout': int(os.getenv('SCANNER_TIMEOUT', '300')),   # 減少超時時間
        'connect_timeout': 15  # 減少連接超時
    }

async def simple_scan():
    """簡化的掃描測試"""
    logger.info("🛡️ WebSecScan 簡化掃描引擎啟動")

    # 清除代理設置
    for proxy_var in ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY']:
        if proxy_var in os.environ:
            del os.environ[proxy_var]
            logger.info(f"🔧 清除代理設置: {proxy_var}")

    # 載入配置
    config = load_config()
    logger.info(f"配置載入完成: {config}")

    # 創建掃描引擎實例
    async with ScannerEngine(config) as scanner:
        logger.info("掃描引擎初始化完成")

        # 簡化的掃描目標 - 只測試基本功能
        test_target = ScanTarget(
            url="http://192.168.250.35:8081/",
            scan_type="basic",
            modules=[],  # 暫時不使用任何掃描模組
            max_concurrency=1,
            timeout=15
        )

        def progress_callback(percent, message):
            logger.info(f"掃描進度: {percent:.1f}% - {message}")

        try:
            # 手動測試目標可達性
            logger.info("🔍 手動測試目標可達性...")
            is_reachable = await scanner._check_target_reachability(test_target.url)

            if is_reachable:
                logger.info("✅ 目標可達性檢查通過!")

                # 測試應用結構發現
                logger.info("🔍 測試應用結構發現...")
                discovered_urls = await scanner._discover_application_structure(test_target.url)
                logger.info(f"📊 發現 {len(discovered_urls)} 個 URLs: {discovered_urls}")

                logger.info("🎉 簡化掃描測試完成 - 所有基本功能正常!")
                return True
            else:
                logger.error("❌ 目標不可達")
                return False

        except Exception as e:
            logger.error(f"掃描執行錯誤: {str(e)}")
            import traceback
            logger.error(f"詳細錯誤: {traceback.format_exc()}")
            return False

async def main():
    """主程式"""
    # 確保必要目錄存在
    for directory in ['logs', 'results']:
        Path(directory).mkdir(exist_ok=True)

    try:
        success = await simple_scan()
        if success:
            logger.info("🎊 簡化掃描引擎測試成功!")
            return 0
        else:
            logger.error("💥 簡化掃描引擎測試失敗!")
            return 1
    except KeyboardInterrupt:
        logger.info("掃描引擎測試停止")
        return 0
    except Exception as e:
        logger.error(f"掃描引擎測試失敗: {str(e)}")
        import traceback
        logger.error(f"詳細錯誤: {traceback.format_exc()}")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)