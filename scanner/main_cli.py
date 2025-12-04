#!/usr/bin/env python3
"""
WebSecScan 掃描引擎 - 命令列介面
支援從後端 API 調用
"""

import asyncio
import logging
import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

# 添加當前目錄到 Python 路徑
current_dir = Path(__file__).parent.absolute()
sys.path.insert(0, str(current_dir))

from core.scanner_engine import ScannerEngine

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

def parse_arguments():
    """解析命令列參數"""
    parser = argparse.ArgumentParser(description='WebSecScan 安全掃描引擎')
    
    parser.add_argument('--target', required=True, help='掃描目標 URL')
    parser.add_argument('--scan-type', default='comprehensive', 
                       choices=['basic', 'comprehensive', 'owasp'],
                       help='掃描類型')
    parser.add_argument('--modules', default='', 
                       help='掃描模組列表,逗號分隔 (例如: sql_injection,xss)')
    parser.add_argument('--output-dir', default='results', help='輸出目錄')
    parser.add_argument('--output-format', default='json', 
                       choices=['json', 'html', 'pdf'],
                       help='輸出格式')
    parser.add_argument('--scan-id', default=None, help='自訂掃描 ID')
    parser.add_argument('--max-concurrency', type=int, default=3, 
                       help='最大並發數')
    parser.add_argument('--timeout', type=int, default=30, help='請求超時(秒)')
    
    return parser.parse_args()

async def run_scan(args):
    """執行掃描"""
    # 確保必要目錄存在
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 解析模組列表
    modules = [m.strip() for m in args.modules.split(',') if m.strip()]
    if not modules:
        # 預設模組 - 使用正確的模組名稱
        modules = ['sql_injection', 'xss', 'csrf', 
                   'ssl_tls', 'info_disclosure']
    
    # 配置
    config = {
        'rate_limit': int(os.getenv('SCANNER_RATE_LIMIT', '5')),
        'max_workers': int(os.getenv('SCANNER_MAX_WORKERS', '5')),
        'total_timeout': int(os.getenv('SCANNER_TIMEOUT', '3600')),
        'connect_timeout': 30
    }
    
    logger.info(f"🚀 開始掃描: {args.target}")
    logger.info(f"掃描類型: {args.scan_type}")
    logger.info(f"掃描模組: {modules}")
    
    # 創建掃描引擎
    engine = ScannerEngine(config)
    
    # 進度回調
    async def progress_callback(percent, message):
        # 輸出可被後端解析的進度格式
        print(f"Progress: {int(percent)}%", file=sys.stderr, flush=True)
        print(f"Status: {message}", file=sys.stderr, flush=True)
        logger.info(f"掃描進度: {percent:.1f}% - {message}")
    
    try:
        # 使用異步上下文管理器初始化 session
        async with engine:
            # 構建 ScanTarget 對象
            from core.scanner_engine import ScanTarget
            
            scan_target = ScanTarget(
                url=args.target,
                scan_type=args.scan_type,
                modules=modules,
                max_concurrency=args.max_concurrency,
                timeout=args.timeout
            )
            
            # 執行掃描
            scan_result = await engine.scan_target(scan_target, progress_callback)
        
        # 轉換為字典格式
        result = {
            'scan_id': args.scan_id or scan_result.scan_id,
            'target_url': scan_result.target_url,
            'scan_type': scan_result.scan_type,
            'start_time': scan_result.start_time,
            'end_time': scan_result.end_time,
            'duration': scan_result.duration,
            'status': scan_result.status,
            'vulnerabilities': [vars(v) for v in scan_result.vulnerabilities],
            'statistics': scan_result.statistics,
            'risk_score': scan_result.risk_score
        }
        
        logger.info(f"✅ 掃描完成: {result['scan_id']}")
        logger.info(f"發現漏洞: {len(result['vulnerabilities'])} 個")
        logger.info(f"風險評分: {result['risk_score']:.1f}/10.0")
        
        # 生成掃描 ID (如果沒有提供)
        scan_id = result['scan_id']
        
        # 儲存結果
        result_file = output_dir / f"scan_result_{scan_id}.json"
        
        # 確保結果包含所有必要欄位,包括模板字段
        output_result = {
            'scan_id': scan_id,
            'target_url': result['target_url'],
            'scan_type': result['scan_type'],
            'start_time': result['start_time'],
            'end_time': result['end_time'],
            'duration': result['duration'],
            'status': result['status'],
            'vulnerabilities': result['vulnerabilities'],
            'statistics': result['statistics'],
            'risk_score': result['risk_score']
        }
        
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(output_result, f, ensure_ascii=False, indent=2)
        
        logger.info(f"📄 結果已儲存: {result_file}")
        
        # 輸出 JSON 到標準輸出 (可選)
        print(json.dumps(output_result, ensure_ascii=False, indent=2))
        
        return 0
        
    except Exception as e:
        logger.error(f"❌ 掃描失敗: {str(e)}")
        
        # 輸出失敗結果
        scan_id = args.scan_id or f"scan_{int(datetime.now().timestamp())}"
        failed_result = {
            'scan_id': scan_id,
            'target_url': args.target,
            'scan_type': args.scan_type,
            'start_time': datetime.now().isoformat(),
            'end_time': datetime.now().isoformat(),
            'duration': 0,
            'status': 'failed',
            'error': str(e),
            'vulnerabilities': [],
            'statistics': {},
            'risk_score': 0.0
        }
        
        result_file = output_dir / f"scan_result_{scan_id}.json"
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(failed_result, f, ensure_ascii=False, indent=2)
        
        return 1

def main():
    """主程式"""
    try:
        # 創建必要目錄
        Path('logs').mkdir(exist_ok=True)
        Path('results').mkdir(exist_ok=True)
        
        # 解析參數
        args = parse_arguments()
        
        # 執行掃描
        exit_code = asyncio.run(run_scan(args))
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        logger.info("⚠️ 掃描被用戶中斷")
        sys.exit(130)
    except Exception as e:
        logger.error(f"❌ 程式錯誤: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
