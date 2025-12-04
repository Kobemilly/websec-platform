#!/usr/bin/env python3
"""
WebSecScan - 安全掃描引擎核心模組
專業的網站安全掃描系統，支援 OWASP Top 10 漏洞檢測
"""

import asyncio
import logging
import time
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from urllib.parse import urljoin, urlparse
import aiohttp
import ssl
from concurrent.futures import ThreadPoolExecutor
import hashlib

# 安全模組導入
from modules.sql_injection_scanner import SQLInjectionScanner
from modules.xss_scanner import XSSScanner
from modules.csrf_scanner import CSRFScanner
from modules.auth_bypass_scanner import AuthBypassScanner
from modules.ssl_tls_scanner import SSLTLSScanner
from modules.directory_traversal_scanner import DirectoryTraversalScanner
from modules.info_disclosure_scanner import InfoDisclosureScanner
from utils.safe_request import SafeRequestHandler
from utils.vulnerability_classifier import VulnerabilityClassifier
from utils.rate_limiter import RateLimiter

# 日誌設定
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ScanTarget:
    """掃描目標資料結構"""
    url: str
    scan_type: str
    modules: List[str]
    max_concurrency: int = 5
    timeout: int = 30
    user_agent: str = "WebSecScan/1.0 Security Scanner"

@dataclass
class VulnerabilityResult:
    """漏洞結果資料結構"""
    id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low
    cwe_id: str
    owasp_category: str
    affected_url: str
    request_method: str
    request_payload: str
    response_evidence: str
    remediation: str
    risk_score: float
    confidence: str  # confirmed, likely, possible
    timestamp: str

@dataclass
class ScanResult:
    """掃描結果資料結構"""
    scan_id: str
    target_url: str
    scan_type: str
    start_time: str
    end_time: str
    duration: float
    status: str  # completed, failed, cancelled
    vulnerabilities: List[VulnerabilityResult]
    statistics: Dict[str, Any]
    risk_score: float

class ScannerEngine:
    """安全掃描引擎主類別"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.session = None
        self.rate_limiter = RateLimiter(
            requests_per_second=self.config.get('rate_limit', 10)
        )
        self.request_handler = SafeRequestHandler()
        self.vulnerability_classifier = VulnerabilityClassifier()

        # 掃描模組註冊
        self.scanner_modules = {
            'sql_injection': SQLInjectionScanner(),
            'xss': XSSScanner(),
            'csrf': CSRFScanner(),
            'auth_bypass': AuthBypassScanner(),
            'ssl_tls': SSLTLSScanner(),
            'directory_traversal': DirectoryTraversalScanner(),
            'info_disclosure': InfoDisclosureScanner()
        }

        # 執行器
        self.executor = ThreadPoolExecutor(max_workers=10)

    async def __aenter__(self):
        """異步上下文管理器入口"""
        # 建立 SSL 上下文
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        # 建立連接器
        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            limit=100,
            limit_per_host=20,
            ttl_dns_cache=300,
            use_dns_cache=True,
        )

        # 設定超時
        timeout = aiohttp.ClientTimeout(
            total=self.config.get('total_timeout', 300),
            connect=self.config.get('connect_timeout', 30)
        )

        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'WebSecScan/1.0 Security Scanner'}
        )

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """異步上下文管理器出口"""
        if self.session:
            await self.session.close()
        self.executor.shutdown(wait=True)

    async def scan_target(self, target: ScanTarget, progress_callback=None) -> ScanResult:
        """
        執行目標掃描

        Args:
            target: 掃描目標配置
            progress_callback: 進度回調函數

        Returns:
            ScanResult: 掃描結果
        """
        scan_id = self._generate_scan_id(target.url)
        start_time = time.time()

        logger.info(f"開始掃描目標: {target.url} (ID: {scan_id})")

        # 重置請求統計計數器
        self.request_handler.reset_stats()

        try:
            # 初始化掃描結果
            scan_result = ScanResult(
                scan_id=scan_id,
                target_url=target.url,
                scan_type=target.scan_type,
                start_time=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time)),
                end_time="",
                duration=0.0,
                status="running",
                vulnerabilities=[],
                statistics={
                    'total_requests': 0,
                    'successful_requests': 0,
                    'failed_requests': 0,
                    'modules_executed': 0,
                    'pages_scanned': 0
                },
                risk_score=0.0
            )

            # 目標可達性檢查
            if progress_callback:
                await progress_callback(5, "檢查目標可達性...")

            is_reachable = await self._check_target_reachability(target.url)
            if not is_reachable:
                scan_result.status = "failed"
                scan_result.end_time = time.strftime('%Y-%m-%d %H:%M:%S')
                logger.error(f"目標不可達: {target.url}")
                return scan_result

            # 發現端點和頁面
            if progress_callback:
                await progress_callback(15, "發現應用程式結構...")

            discovered_urls = await self._discover_application_structure(target.url)
            scan_result.statistics['pages_scanned'] = len(discovered_urls)

            # 執行安全模組掃描
            total_modules = len(target.modules)
            vulnerabilities = []

            for i, module_name in enumerate(target.modules):
                if module_name in self.scanner_modules:
                    progress = 20 + (60 * (i + 1) / total_modules)
                    if progress_callback:
                        await progress_callback(progress, f"執行 {module_name} 掃描...")

                    module = self.scanner_modules[module_name]
                    module_results = await self._run_scanner_module(
                        module, target, discovered_urls
                    )
                    vulnerabilities.extend(module_results)
                    scan_result.statistics['modules_executed'] += 1

            # 漏洞去重和分類
            if progress_callback:
                await progress_callback(85, "分析和分類漏洞...")

            unique_vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)
            classified_vulnerabilities = await self._classify_vulnerabilities(
                unique_vulnerabilities
            )

            # 計算風險評分
            if progress_callback:
                await progress_callback(95, "計算風險評分...")

            risk_score = self._calculate_risk_score(classified_vulnerabilities)

            # 完成掃描
            end_time = time.time()
            
            # 更新請求統計
            request_stats = self.request_handler.get_stats()
            scan_result.statistics.update(request_stats)
            
            scan_result.end_time = time.strftime(
                '%Y-%m-%d %H:%M:%S',
                time.localtime(end_time)
            )
            scan_result.duration = end_time - start_time
            scan_result.status = "completed"
            scan_result.vulnerabilities = classified_vulnerabilities
            scan_result.risk_score = risk_score

            if progress_callback:
                await progress_callback(100, "掃描完成")

            logger.info(
                f"掃描完成: {scan_id}, 發現 {len(classified_vulnerabilities)} 個漏洞, "
                f"風險評分: {risk_score:.1f}"
            )

            return scan_result

        except Exception as e:
            logger.error(f"掃描過程中發生錯誤: {str(e)}")
            end_time = time.time()
            scan_result.end_time = time.strftime(
                '%Y-%m-%d %H:%M:%S',
                time.localtime(end_time)
            )
            scan_result.duration = end_time - start_time
            scan_result.status = "failed"
            return scan_result

    async def _check_target_reachability(self, url: str) -> bool:
        """檢查目標是否可達"""
        try:
            async with self.rate_limiter:
                response = await self.request_handler.safe_get(
                    self.session, url, timeout=10
                )
                if response is None:
                    logger.warning(f"無法連接到目標: {url}")
                    return False
                return response.status < 500
        except Exception as e:
            logger.error(f"目標可達性檢查失敗: {str(e)}")
            return False

    async def _discover_application_structure(self, base_url: str) -> List[str]:
        """發現應用程式結構和端點"""
        discovered_urls = [base_url]

        # 常見路徑發現
        common_paths = [
            '/admin', '/login', '/api', '/dashboard', '/user', '/profile',
            '/search', '/upload', '/download', '/contact', '/about',
            '/robots.txt', '/sitemap.xml', '/.env', '/config.php'
        ]

        tasks = []
        for path in common_paths:
            url = urljoin(base_url, path)
            tasks.append(self._check_url_exists(url))

        # 限制並發請求
        semaphore = asyncio.Semaphore(10)

        async def bounded_check(url):
            async with semaphore:
                return await self._check_url_exists(url)

        results = await asyncio.gather(*[
            bounded_check(urljoin(base_url, path)) for path in common_paths
        ], return_exceptions=True)

        for i, result in enumerate(results):
            if isinstance(result, str):  # 成功返回URL
                discovered_urls.append(result)

        return list(set(discovered_urls))  # 去重

    async def _check_url_exists(self, url: str) -> Optional[str]:
        """檢查URL是否存在"""
        try:
            async with self.rate_limiter:
                response = await self.request_handler.safe_head(
                    self.session, url, timeout=5
                )
                if response is not None and response.status < 400:
                    return url
        except Exception:
            pass
        return None

    async def _run_scanner_module(
        self,
        module,
        target: ScanTarget,
        urls: List[str]
    ) -> List[VulnerabilityResult]:
        """執行掃描模組"""
        try:
            return await module.scan(self.session, target, urls)
        except Exception as e:
            logger.error(f"掃描模組執行錯誤: {str(e)}")
            return []

    def _deduplicate_vulnerabilities(
        self,
        vulnerabilities: List[VulnerabilityResult]
    ) -> List[VulnerabilityResult]:
        """漏洞去重"""
        seen = set()
        unique_vulns = []

        for vuln in vulnerabilities:
            # 使用 URL + CWE ID + 負載 作為唯一標識
            key = f"{vuln.affected_url}:{vuln.cwe_id}:{vuln.request_payload}"
            hash_key = hashlib.md5(key.encode()).hexdigest()

            if hash_key not in seen:
                seen.add(hash_key)
                unique_vulns.append(vuln)

        return unique_vulns

    async def _classify_vulnerabilities(
        self,
        vulnerabilities: List[VulnerabilityResult]
    ) -> List[VulnerabilityResult]:
        """漏洞分類和評分"""
        classified = []

        for vuln in vulnerabilities:
            # 使用漏洞分類器進行評分
            enhanced_vuln = await self.vulnerability_classifier.classify(vuln)
            classified.append(enhanced_vuln)

        # 按嚴重程度和置信度排序
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        confidence_order = {'confirmed': 3, 'likely': 2, 'possible': 1}

        classified.sort(
            key=lambda v: (
                severity_order.get(v.severity, 0),
                confidence_order.get(v.confidence, 0),
                v.risk_score
            ),
            reverse=True
        )

        return classified

    def _calculate_risk_score(self, vulnerabilities: List[VulnerabilityResult]) -> float:
        """計算整體風險評分"""
        if not vulnerabilities:
            return 0.0

        # 權重計算
        severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
        confidence_weights = {'confirmed': 1.0, 'likely': 0.8, 'possible': 0.5}

        total_score = 0.0
        total_weight = 0.0

        for vuln in vulnerabilities:
            severity_weight = severity_weights.get(vuln.severity, 1)
            confidence_weight = confidence_weights.get(vuln.confidence, 0.5)

            score = severity_weight * confidence_weight * vuln.risk_score
            total_score += score
            total_weight += severity_weight * confidence_weight

        return min(total_score / total_weight if total_weight > 0 else 0.0, 10.0)

    def _generate_scan_id(self, url: str) -> str:
        """生成掃描ID"""
        timestamp = str(int(time.time()))
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        return f"scan_{timestamp}_{url_hash}"

    def export_results(self, scan_result: ScanResult, format: str = 'json') -> str:
        """匯出掃描結果"""
        if format == 'json':
            return json.dumps(asdict(scan_result), indent=2, ensure_ascii=False)
        elif format == 'csv':
            # CSV 格式匯出實作
            pass
        elif format == 'pdf':
            # PDF 報告生成實作
            pass
        else:
            raise ValueError(f"不支援的匯出格式: {format}")

# 使用範例
async def main():
    """主程式範例"""
    config = {
        'rate_limit': 5,  # 每秒請求數限制
        'total_timeout': 600,  # 總超時時間
        'connect_timeout': 30   # 連接超時時間
    }

    target = ScanTarget(
        url="https://example.com",
        scan_type="owasp",
        modules=['sql_injection', 'xss', 'csrf', 'ssl_tls'],
        max_concurrency=5,
        timeout=30
    )

    async with ScannerEngine(config) as scanner:
        def progress_callback(percent, message):
            print(f"進度: {percent:.1f}% - {message}")

        result = await scanner.scan_target(target, progress_callback)

        print("\n=== 掃描結果 ===")
        print(f"掃描ID: {result.scan_id}")
        print(f"目標: {result.target_url}")
        print(f"狀態: {result.status}")
        print(f"持續時間: {result.duration:.2f} 秒")
        print(f"發現漏洞: {len(result.vulnerabilities)} 個")
        print(f"風險評分: {result.risk_score:.1f}/10.0")

        # 匯出結果
        json_result = scanner.export_results(result, 'json')
        with open('scan_result.json', 'w', encoding='utf-8') as f:
            f.write(json_result)

if __name__ == "__main__":
    asyncio.run(main())