#!/usr/bin/env python3
"""
WebSecScan 掃描引擎主程式 - 完整版本
執行實際的漏洞掃描測試
"""

import asyncio
import logging
import os
import sys
import time
import json
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
        'rate_limit': int(os.getenv('SCANNER_RATE_LIMIT', '2')),
        'max_workers': int(os.getenv('SCANNER_MAX_WORKERS', '2')),
        'total_timeout': int(os.getenv('SCANNER_TIMEOUT', '600')),
        'connect_timeout': 20
    }

async def full_scan():
    """完整的掃描測試"""
    logger.info("🛡️ WebSecScan 完整掃描引擎啟動")

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

        # 完整的掃描目標 - 使用安全的掃描模組
        test_target = ScanTarget(
            url="http://192.168.250.35:8081/",
            scan_type="comprehensive",
            modules=['info_disclosure', 'ssl_tls'],  # 使用相對安全的掃描模組
            max_concurrency=2,
            timeout=20
        )

        def progress_callback(percent, message):
            logger.info(f"掃描進度: {percent:.1f}% - {message}")

        try:
            # 執行完整掃描
            logger.info("🚀 開始執行完整掃描...")
            result = await scanner.scan_target(test_target, progress_callback)

            logger.info("=== 掃描完成 ===")
            logger.info(f"掃描ID: {result.scan_id}")
            logger.info(f"目標: {result.target_url}")
            logger.info(f"狀態: {result.status}")
            logger.info(f"持續時間: {result.duration:.2f} 秒")
            logger.info(f"發現漏洞: {len(result.vulnerabilities)} 個")
            logger.info(f"風險評分: {result.risk_score:.1f}/10.0")

            # 顯示發現的漏洞
            if result.vulnerabilities:
                logger.info("🔍 發現的漏洞:")
                for i, vuln in enumerate(result.vulnerabilities[:5], 1):  # 只顯示前5個
                    logger.info(f"  {i}. {vuln.title} ({vuln.severity})")

            # 匯出結果
            results_dir = Path('results')
            results_dir.mkdir(exist_ok=True)

            result_file = results_dir / f"scan_result_{result.scan_id}.json"
            json_result = scanner.export_results(result, 'json')

            with open(result_file, 'w', encoding='utf-8') as f:
                f.write(json_result)

            logger.info(f"掃描結果已儲存到: {result_file}")

            if result.status == "completed":
                logger.info("🎉 完整掃描測試成功!")
                return True
            else:
                logger.warning(f"⚠️ 掃描完成但狀態為: {result.status}")
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
        success = await full_scan()
        if success:
            logger.info("🎊 完整掃描引擎測試成功!")
            return 0
        else:
            logger.error("💥 完整掃描引擎測試失敗!")
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