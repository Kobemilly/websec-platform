#!/usr/bin/env python3
"""
WebSecScan 掃描引擎主程式
專業網站安全掃描系統入口點
"""

import asyncio
import logging
import os
import sys
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
        logging.FileHandler('logs/scanner.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def load_config():
    """載入配置"""
    return {
        'rate_limit': int(os.getenv('SCANNER_RATE_LIMIT', '5')),
        'max_workers': int(os.getenv('SCANNER_MAX_WORKERS', '5')),
        'total_timeout': int(os.getenv('SCANNER_TIMEOUT', '3600')),
        'connect_timeout': 30
    }

async def main():
    """主程式"""
    logger.info("🛡️ WebSecScan 掃描引擎啟動")

    # 載入配置
    config = load_config()
    logger.info(f"配置載入完成: {config}")

    # 創建掃描引擎實例
    async with ScannerEngine(config) as scanner:
        logger.info("掃描引擎初始化完成")

        # 示例掃描目標（在實際應用中這會來自任務佇列）
        test_target = ScanTarget(
            url="http://192.168.250.35:8081/",
            scan_type="comprehensive",
            modules=['sql_injection', 'xss', 'ssl_tls'],
            max_concurrency=3,
            timeout=30
        )

        def progress_callback(percent, message):
            logger.info(f"掃描進度: {percent:.1f}% - {message}")

        try:
            # 執行掃描
            result = await scanner.scan_target(test_target, progress_callback)

            logger.info("=== 掃描完成 ===")
            logger.info(f"掃描ID: {result.scan_id}")
            logger.info(f"目標: {result.target_url}")
            logger.info(f"狀態: {result.status}")
            logger.info(f"持續時間: {result.duration:.2f} 秒")
            logger.info(f"發現漏洞: {len(result.vulnerabilities)} 個")
            logger.info(f"風險評分: {result.risk_score:.1f}/10.0")

            # 匯出結果
            json_result = scanner.export_results(result, 'json')

            # 確保結果目錄存在
            results_dir = Path('results')
            results_dir.mkdir(exist_ok=True)

            # 寫入結果檔案
            result_file = results_dir / f"scan_result_{result.scan_id}.json"
            with open(result_file, 'w', encoding='utf-8') as f:
                f.write(json_result)

            logger.info(f"掃描結果已儲存到: {result_file}")

        except Exception as e:
            logger.error(f"掃描執行錯誤: {str(e)}")
            sys.exit(1)

def run_health_check():
    """健康檢查"""
    try:
        logger.info("執行健康檢查...")

        # 檢查必要的目錄
        required_dirs = ['logs', 'results', 'core', 'modules', 'utils']
        for dir_name in required_dirs:
            dir_path = Path(dir_name)
            if not dir_path.exists():
                logger.warning(f"目錄不存在，正在創建: {dir_name}")
                dir_path.mkdir(parents=True, exist_ok=True)

        logger.info("健康檢查通過")
        return True

    except Exception as e:
        logger.error(f"健康檢查失敗: {str(e)}")
        return False

if __name__ == "__main__":
    # 創建必要目錄
    for directory in ['logs', 'results']:
        Path(directory).mkdir(exist_ok=True)

    # 檢查命令行參數
    if len(sys.argv) > 1:
        if sys.argv[1] == "--health":
            success = run_health_check()
            sys.exit(0 if success else 1)
        elif sys.argv[1] == "--version":
            print("WebSecScan Scanner v1.0.0")
            sys.exit(0)
        elif sys.argv[1] == "--help":
            print("""
WebSecScan 掃描引擎

使用方式:
    python main.py                 # 啟動掃描引擎
    python main.py --health        # 健康檢查
    python main.py --version       # 顯示版本
    python main.py --help          # 顯示幫助

環境變數:
    SCANNER_RATE_LIMIT     # 速率限制 (預設: 5)
    SCANNER_MAX_WORKERS    # 最大工作者數量 (預設: 5)
    SCANNER_TIMEOUT        # 掃描超時 (預設: 3600)
            """)
            sys.exit(0)

    try:
        # 運行主程式
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("掃描引擎停止")
        sys.exit(0)
    except Exception as e:
        logger.error(f"掃描引擎啟動失敗: {str(e)}")
        sys.exit(1)