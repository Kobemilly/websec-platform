#!/usr/bin/env python3
"""
SQL 注入掃描模組
檢測各種 SQL 注入漏洞,包括基於錯誤、布林盲注和時間盲注
"""

import asyncio
import re
import time
import logging
import json
import os
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class SQLInjectionPayload:
    """SQL 注入測試負載"""
    payload: str
    description: str
    detection_method: str  # error, boolean, time
    expected_response: str = ""
    sleep_time: float = 0

class SQLInjectionScanner:
    """SQL 注入掃描器"""

    def __init__(self):
        self.rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'rules')
        self.rules_file = os.path.join(self.rules_dir, 'sql_injection.json')
        self.payloads = []
        self.error_patterns = []
        self.max_concurrent = 5
        self._load_rules_from_file()

    def _load_rules_from_file(self) -> None:
        """從 JSON 檔案載入規則"""
        try:
            if not os.path.exists(self.rules_file):
                logger.warning(f"Rules file not found: {self.rules_file}, using fallback initialization")
                self.payloads = self._initialize_payloads()
                self.error_patterns = self._initialize_error_patterns()
                return

            with open(self.rules_file, 'r', encoding='utf-8') as f:
                rules = json.load(f)
            
            # 載入 payloads
            for payload_data in rules.get('payloads', []):
                if payload_data.get('enabled', True):
                    self.payloads.append(SQLInjectionPayload(
                        payload=payload_data['payload'],
                        description=payload_data['description'],
                        detection_method=payload_data['detection_method'],
                        expected_response=payload_data.get('expected_response', ''),
                        sleep_time=payload_data.get('sleep_time', 0)
                    ))
            
            # 載入 error patterns
            self.error_patterns = [
                pattern['pattern']
                for pattern in rules.get('error_patterns', [])
                if pattern.get('enabled', True)
            ]
            
            logger.info(f"Loaded {len(self.payloads)} payloads and {len(self.error_patterns)} error patterns from {self.rules_file}")
            
        except Exception as e:
            logger.error(f"Failed to load rules from {self.rules_file}: {e}")
            logger.warning("Falling back to hardcoded rules")
            self.payloads = self._initialize_payloads()
            self.error_patterns = self._initialize_error_patterns()

    def reload_rules(self) -> None:
        """重新載入規則(熱重載)"""
        logger.info("Reloading SQL injection rules...")
        self.payloads = []
        self.error_patterns = []
        self._load_rules_from_file()

    def _initialize_payloads(self) -> List[SQLInjectionPayload]:
        """初始化 SQL 注入測試負載"""
        return [
            # 基於錯誤的注入
            SQLInjectionPayload(
                payload="'",
                description="單引號錯誤測試",
                detection_method="error"
            ),
            SQLInjectionPayload(
                payload='"',
                description="雙引號錯誤測試",
                detection_method="error"
            ),
            SQLInjectionPayload(
                payload="' OR '1'='1",
                description="經典 OR 注入",
                detection_method="boolean"
            ),
            SQLInjectionPayload(
                payload="' AND '1'='1",
                description="AND 條件注入",
                detection_method="boolean"
            ),
            SQLInjectionPayload(
                payload="1' UNION SELECT null--",
                description="UNION 查詢注入",
                detection_method="error"
            ),
            SQLInjectionPayload(
                payload="'; DROP TABLE users--",
                description="破壞性注入測試",
                detection_method="error"
            ),

            # 布林盲注
            SQLInjectionPayload(
                payload="1' AND 1=1--",
                description="布林盲注 - 真條件",
                detection_method="boolean"
            ),
            SQLInjectionPayload(
                payload="1' AND 1=2--",
                description="布林盲注 - 假條件",
                detection_method="boolean"
            ),

            # 時間盲注
            SQLInjectionPayload(
                payload="1'; WAITFOR DELAY '00:00:05'--",
                description="SQL Server 時間延遲注入",
                detection_method="time",
                sleep_time=5.0
            ),
            SQLInjectionPayload(
                payload="1' AND SLEEP(5)--",
                description="MySQL 時間延遲注入",
                detection_method="time",
                sleep_time=5.0
            ),
            SQLInjectionPayload(
                payload="1'; SELECT pg_sleep(5)--",
                description="PostgreSQL 時間延遲注入",
                detection_method="time",
                sleep_time=5.0
            ),

            # NoSQL 注入
            SQLInjectionPayload(
                payload="'||'1'=='1",
                description="NoSQL 注入測試",
                detection_method="boolean"
            ),

            # 二階注入
            SQLInjectionPayload(
                payload="admin'--",
                description="二階注入測試",
                detection_method="error"
            )
        ]

    def _initialize_error_patterns(self) -> List[Dict[str, str]]:
        """初始化 SQL 錯誤模式"""
        return [
            # MySQL 錯誤
            {
                "pattern": r"You have an error in your SQL syntax",
                "database": "MySQL"
            },
            {
                "pattern": r"mysql_fetch_array\(\)",
                "database": "MySQL"
            },
            {
                "pattern": r"MySQL server version",
                "database": "MySQL"
            },

            # PostgreSQL 錯誤
            {
                "pattern": r"PostgreSQL.*ERROR",
                "database": "PostgreSQL"
            },
            {
                "pattern": r"Warning.*\Wpg_",
                "database": "PostgreSQL"
            },
            {
                "pattern": r"PostgreSQL query failed",
                "database": "PostgreSQL"
            },

            # SQL Server 錯誤
            {
                "pattern": r"Microsoft OLE DB Provider for ODBC Drivers",
                "database": "SQL Server"
            },
            {
                "pattern": r"\[SQL Server\]",
                "database": "SQL Server"
            },
            {
                "pattern": r"Unclosed quotation mark after the character string",
                "database": "SQL Server"
            },

            # Oracle 錯誤
            {
                "pattern": r"ORA-[0-9][0-9][0-9][0-9]",
                "database": "Oracle"
            },
            {
                "pattern": r"Oracle error",
                "database": "Oracle"
            },
            {
                "pattern": r"Oracle.*Driver",
                "database": "Oracle"
            },

            # SQLite 錯誤
            {
                "pattern": r"SQLite/JDBCDriver",
                "database": "SQLite"
            },
            {
                "pattern": r"SQLite.Exception",
                "database": "SQLite"
            },

            # 一般 SQL 錯誤
            {
                "pattern": r"SQL syntax.*MySQL",
                "database": "Generic"
            },
            {
                "pattern": r"Warning.*mysql_.*",
                "database": "Generic"
            },
            {
                "pattern": r"MySQLSyntaxErrorException",
                "database": "Generic"
            }
        ]

    async def scan(self, session, target, urls: List[str]) -> List[Any]:
        """執行 SQL 注入掃描"""
        vulnerabilities = []

        logger.info(f"開始 SQL 注入掃描，目標 URL 數量: {len(urls)}")

        # 使用信號量限制並發
        semaphore = asyncio.Semaphore(self.max_concurrent)

        tasks = []
        for url in urls:
            task = self._scan_url_with_semaphore(semaphore, session, url)
            tasks.append(task)

        # 執行所有掃描任務
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 收集結果
        for result in results:
            if isinstance(result, list):
                vulnerabilities.extend(result)
            elif isinstance(result, Exception):
                logger.error(f"掃描過程中發生錯誤: {str(result)}")

        logger.info(f"SQL 注入掃描完成，發現 {len(vulnerabilities)} 個漏洞")
        return vulnerabilities

    async def _scan_url_with_semaphore(self, semaphore, session, url):
        """使用信號量控制並發的 URL 掃描"""
        async with semaphore:
            return await self._scan_single_url(session, url)

    async def _scan_single_url(self, session, url: str) -> List[Any]:
        """掃描單個 URL"""
        vulnerabilities = []

        try:
            # 獲取原始響應作為基準
            baseline_response = await self._get_baseline_response(session, url)
            if not baseline_response:
                return vulnerabilities

            # 測試 GET 參數
            get_vulns = await self._test_get_parameters(session, url, baseline_response)
            vulnerabilities.extend(get_vulns)

            # 測試 POST 參數（如果有表單）
            post_vulns = await self._test_post_parameters(session, url, baseline_response)
            vulnerabilities.extend(post_vulns)

            # 測試 Cookie 注入
            cookie_vulns = await self._test_cookie_injection(session, url, baseline_response)
            vulnerabilities.extend(cookie_vulns)

            # 測試 Header 注入
            header_vulns = await self._test_header_injection(session, url, baseline_response)
            vulnerabilities.extend(header_vulns)

        except Exception as e:
            logger.error(f"掃描 URL {url} 時發生錯誤: {str(e)}")

        return vulnerabilities

    async def _get_baseline_response(self, session, url: str) -> Dict[str, Any]:
        """獲取基準響應"""
        try:
            async with session.get(url, timeout=10) as response:
                text = await response.text()
                return {
                    'status': response.status,
                    'text': text,
                    'length': len(text),
                    'headers': dict(response.headers)
                }
        except Exception as e:
            logger.error(f"獲取基準響應失敗 {url}: {str(e)}")
            return None

    async def _test_get_parameters(self, session, url: str, baseline) -> List[Any]:
        """測試 GET 參數注入"""
        vulnerabilities = []

        parsed_url = urlparse(url)
        if not parsed_url.query:
            return vulnerabilities

        # 解析現有參數
        params = parse_qs(parsed_url.query)

        for param_name in params:
            for payload_obj in self.payloads:
                try:
                    # 修改參數值
                    test_params = params.copy()
                    test_params[param_name] = [payload_obj.payload]

                    # 構建測試 URL
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{test_query}"

                    # 發送請求
                    vulnerability = await self._test_payload(
                        session, test_url, payload_obj, baseline,
                        injection_point=f"GET parameter: {param_name}"
                    )

                    if vulnerability:
                        vulnerabilities.append(vulnerability)

                except Exception as e:
                    logger.error(f"測試 GET 參數 {param_name} 時發生錯誤: {str(e)}")

        return vulnerabilities

    async def _test_post_parameters(self, session, url: str, baseline) -> List[Any]:
        """測試 POST 參數注入"""
        vulnerabilities = []

        # 嘗試發現表單
        forms = await self._discover_forms(session, url)

        for form in forms:
            for field_name in form.get('fields', []):
                for payload_obj in self.payloads:
                    try:
                        # 構建 POST 數據
                        post_data = {field_name: payload_obj.payload}

                        vulnerability = await self._test_post_payload(
                            session, form['action'], post_data, payload_obj, baseline,
                            injection_point=f"POST parameter: {field_name}"
                        )

                        if vulnerability:
                            vulnerabilities.append(vulnerability)

                    except Exception as e:
                        logger.error(f"測試 POST 參數 {field_name} 時發生錯誤: {str(e)}")

        return vulnerabilities

    async def _test_cookie_injection(self, session, url: str, baseline) -> List[Any]:
        """測試 Cookie 注入"""
        vulnerabilities = []

        # 獲取現有 Cookie
        cookies = session.cookie_jar.filter_cookies(url)

        for cookie in cookies:
            for payload_obj in self.payloads:
                try:
                    # 修改 Cookie 值
                    test_cookies = {cookie.key: payload_obj.payload}

                    async with session.get(url, cookies=test_cookies, timeout=10) as response:
                        response_text = await response.text()

                        vulnerability = await self._analyze_response(
                            response, response_text, payload_obj, baseline,
                            injection_point=f"Cookie: {cookie.key}",
                            request_url=url
                        )

                        if vulnerability:
                            vulnerabilities.append(vulnerability)

                except Exception as e:
                    logger.error(f"測試 Cookie {cookie.key} 時發生錯誤: {str(e)}")

        return vulnerabilities

    async def _test_header_injection(self, session, url: str, baseline) -> List[Any]:
        """測試 HTTP Header 注入"""
        vulnerabilities = []

        # 測試常見的可能存在注入的 Header
        test_headers = ['User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP']

        for header_name in test_headers:
            for payload_obj in self.payloads:
                try:
                    test_headers_dict = {header_name: payload_obj.payload}

                    async with session.get(url, headers=test_headers_dict, timeout=10) as response:
                        response_text = await response.text()

                        vulnerability = await self._analyze_response(
                            response, response_text, payload_obj, baseline,
                            injection_point=f"HTTP Header: {header_name}",
                            request_url=url
                        )

                        if vulnerability:
                            vulnerabilities.append(vulnerability)

                except Exception as e:
                    logger.error(f"測試 Header {header_name} 時發生錯誤: {str(e)}")

        return vulnerabilities

    async def _test_payload(self, session, url: str, payload_obj: SQLInjectionPayload,
                           baseline, injection_point: str) -> Any:
        """測試單個負載"""
        try:
            start_time = time.time()

            async with session.get(url, timeout=15) as response:
                response_text = await response.text()
                response_time = time.time() - start_time

                return await self._analyze_response(
                    response, response_text, payload_obj, baseline,
                    injection_point, url, response_time
                )

        except Exception as e:
            logger.error(f"測試負載時發生錯誤: {str(e)}")
            return None

    async def _test_post_payload(self, session, url: str, data: Dict,
                                payload_obj: SQLInjectionPayload, baseline,
                                injection_point: str) -> Any:
        """測試 POST 負載"""
        try:
            start_time = time.time()

            async with session.post(url, data=data, timeout=15) as response:
                response_text = await response.text()
                response_time = time.time() - start_time

                return await self._analyze_response(
                    response, response_text, payload_obj, baseline,
                    injection_point, url, response_time
                )

        except Exception as e:
            logger.error(f"測試 POST 負載時發生錯誤: {str(e)}")
            return None

    async def _analyze_response(self, response, response_text: str,
                               payload_obj: SQLInjectionPayload, baseline,
                               injection_point: str, request_url: str,
                               response_time: float = 0) -> Any:
        """分析響應以檢測 SQL 注入"""

        # 基於錯誤的檢測
        if payload_obj.detection_method == "error":
            detected_db = self._detect_sql_errors(response_text)
            if detected_db:
                return self._create_vulnerability_result(
                    title="SQL 注入漏洞 (基於錯誤)",
                    description=f"在 {injection_point} 發現 SQL 注入漏洞，數據庫類型: {detected_db}",
                    severity="high",
                    cwe_id="CWE-89",
                    affected_url=request_url,
                    request_payload=payload_obj.payload,
                    response_evidence=response_text[:500],
                    confidence="confirmed"
                )

        # 基於布林的檢測
        elif payload_obj.detection_method == "boolean":
            if self._detect_boolean_injection(response_text, baseline):
                return self._create_vulnerability_result(
                    title="SQL 注入漏洞 (布林盲注)",
                    description=f"在 {injection_point} 發現布林盲注漏洞",
                    severity="medium",
                    cwe_id="CWE-89",
                    affected_url=request_url,
                    request_payload=payload_obj.payload,
                    response_evidence=f"響應內容變化檢測到注入",
                    confidence="likely"
                )

        # 基於時間的檢測
        elif payload_obj.detection_method == "time":
            if response_time >= payload_obj.sleep_time * 0.8:  # 允許20%誤差
                return self._create_vulnerability_result(
                    title="SQL 注入漏洞 (時間盲注)",
                    description=f"在 {injection_point} 發現時間盲注漏洞，響應時間: {response_time:.2f}秒",
                    severity="medium",
                    cwe_id="CWE-89",
                    affected_url=request_url,
                    request_payload=payload_obj.payload,
                    response_evidence=f"預期延遲: {payload_obj.sleep_time}秒, 實際延遲: {response_time:.2f}秒",
                    confidence="likely"
                )

        return None

    def _detect_sql_errors(self, response_text: str) -> str:
        """檢測 SQL 錯誤模式"""
        for error_pattern in self.error_patterns:
            if re.search(error_pattern["pattern"], response_text, re.IGNORECASE):
                return error_pattern["database"]
        return None

    def _detect_boolean_injection(self, response_text: str, baseline) -> bool:
        """檢測布林注入"""
        if not baseline:
            return False

        # 比較響應長度差異
        length_diff = abs(len(response_text) - baseline['length'])

        # 如果響應長度差異超過10%，可能存在注入
        if length_diff > baseline['length'] * 0.1:
            return True

        # 檢查狀態碼變化
        return False

    async def _discover_forms(self, session, url: str) -> List[Dict]:
        """發現頁面中的表單"""
        forms = []

        try:
            async with session.get(url, timeout=10) as response:
                html_content = await response.text()

                # 簡單的表單解析（實際應用中建議使用 BeautifulSoup）
                form_pattern = r'<form[^>]*action=["\']?([^"\'>\s]+)[^>]*>(.*?)</form>'
                input_pattern = r'<input[^>]*name=["\']?([^"\'>\s]+)[^>]*>'

                for form_match in re.finditer(form_pattern, html_content, re.DOTALL | re.IGNORECASE):
                    action = form_match.group(1)
                    form_content = form_match.group(2)

                    # 提取輸入欄位
                    fields = []
                    for input_match in re.finditer(input_pattern, form_content, re.IGNORECASE):
                        field_name = input_match.group(1)
                        fields.append(field_name)

                    if fields:
                        forms.append({
                            'action': urljoin(url, action),
                            'fields': fields
                        })

        except Exception as e:
            logger.error(f"發現表單時發生錯誤: {str(e)}")

        return forms

    def _create_vulnerability_result(self, title: str, description: str,
                                   severity: str, cwe_id: str, affected_url: str,
                                   request_payload: str, response_evidence: str,
                                   confidence: str) -> Any:
        """創建漏洞結果對象"""
        from core.scanner_engine import VulnerabilityResult
        import uuid

        return VulnerabilityResult(
            id=str(uuid.uuid4()),
            title=title,
            description=description,
            severity=severity,
            cwe_id=cwe_id,
            owasp_category="A03:2021 - Injection",
            affected_url=affected_url,
            request_method="GET/POST",
            request_payload=request_payload,
            response_evidence=response_evidence,
            remediation="使用參數化查詢、輸入驗證和最小權限原則",
            risk_score=self._calculate_risk_score(severity, confidence),
            confidence=confidence,
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
        )

    def _calculate_risk_score(self, severity: str, confidence: str) -> float:
        """計算風險評分"""
        severity_scores = {'critical': 9.0, 'high': 7.0, 'medium': 5.0, 'low': 2.0}
        confidence_multipliers = {'confirmed': 1.0, 'likely': 0.8, 'possible': 0.5}

        base_score = severity_scores.get(severity, 2.0)
        multiplier = confidence_multipliers.get(confidence, 0.5)

        return min(base_score * multiplier, 10.0)