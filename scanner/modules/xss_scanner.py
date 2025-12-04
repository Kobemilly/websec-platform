#!/usr/bin/env python3
"""
XSS 漏洞掃描模組
檢測反射型、儲存型和 DOM 型 XSS 漏洞
"""

import asyncio
import logging
import re
import time
import json
import os
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from dataclasses import dataclass
import aiohttp
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

@dataclass
class XSSPayload:
    """XSS 測試負載"""
    payload: str
    description: str
    type: str  # reflected, stored, dom
    severity: str

class XSSScanner:
    """XSS 漏洞掃描器"""

    def __init__(self):
        self.name = "XSS Scanner"
        self.description = "Cross-Site Scripting vulnerability scanner"
        
        self.rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'rules')
        self.rules_file = os.path.join(self.rules_dir, 'xss_payloads.json')
        self.payloads = []
        self.detection_patterns = []
        self.input_patterns = []
        self._load_rules_from_file()

    def _load_rules_from_file(self) -> None:
        """從 JSON 檔案載入規則"""
        try:
            if not os.path.exists(self.rules_file):
                logger.warning(f"Rules file not found: {self.rules_file}, using fallback initialization")
                self._initialize_fallback_rules()
                return

            with open(self.rules_file, 'r', encoding='utf-8') as f:
                rules = json.load(f)
            
            # 載入 payloads
            for payload_data in rules.get('payloads', []):
                if payload_data.get('enabled', True):
                    self.payloads.append(XSSPayload(
                        payload=payload_data['payload'],
                        description=payload_data['description'],
                        type=payload_data['type'],
                        severity=payload_data['severity']
                    ))
            
            # 載入 detection patterns
            self.detection_patterns = [
                pattern['pattern']
                for pattern in rules.get('detection_patterns', [])
            ]
            
            # 載入 input patterns
            self.input_patterns = rules.get('input_patterns', [])
            
            logger.info(f"Loaded {len(self.payloads)} XSS payloads, {len(self.detection_patterns)} detection patterns from {self.rules_file}")
            
        except Exception as e:
            logger.error(f"Failed to load rules from {self.rules_file}: {e}")
            logger.warning("Falling back to hardcoded rules")
            self._initialize_fallback_rules()

    def reload_rules(self) -> None:
        """重新載入規則(熱重載)"""
        logger.info("Reloading XSS rules...")
        self.payloads = []
        self.detection_patterns = []
        self.input_patterns = []
        self._load_rules_from_file()

    def _initialize_fallback_rules(self) -> None:
        """初始化備用規則(當 JSON 檔案不存在時)"""
    def _initialize_fallback_rules(self) -> None:
        """初始化備用規則(當 JSON 檔案不存在時)"""
        # XSS 測試負載庫
        self.payloads = [
            # 基礎反射型 XSS 負載
            XSSPayload('<script>alert("XSS")</script>', 'Basic script alert', 'reflected', 'high'),
            XSSPayload('<img src="x" onerror="alert(\'XSS\')">', 'Image tag with onerror', 'reflected', 'high'),
            XSSPayload('<svg onload="alert(1)">', 'SVG onload event', 'reflected', 'high'),
            XSSPayload('"><script>alert(String.fromCharCode(88,83,83))</script>', 'Breaking out of attributes', 'reflected', 'high'),
            XSSPayload("';alert('XSS');//", 'JavaScript context injection', 'reflected', 'high'),
            XSSPayload('<iframe src="javascript:alert(\'XSS\')"></iframe>', 'JavaScript URI in iframe', 'reflected', 'medium'),

            # 繞過過濾器的負載
            XSSPayload('<ScRiPt>alert("XSS")</ScRiPt>', 'Case variation bypass', 'reflected', 'high'),
            XSSPayload('<script>alert(/XSS/)</script>', 'Regular expression alert', 'reflected', 'high'),
            XSSPayload('<script>alert`XSS`</script>', 'Template literal alert', 'reflected', 'high'),
            XSSPayload('<script>\u0061lert("XSS")</script>', 'Unicode encoding bypass', 'reflected', 'high'),
            XSSPayload('<img/src="x"/onerror="alert(1)">', 'Whitespace bypass', 'reflected', 'high'),

            # DOM 型 XSS 負載
            XSSPayload('#<script>alert("DOM-XSS")</script>', 'Hash-based DOM XSS', 'dom', 'high'),
            XSSPayload('javascript:alert("DOM-XSS")', 'JavaScript protocol', 'dom', 'medium'),

            # 儲存型 XSS 負載 (需要更謹慎)
            XSSPayload('<script>/*stored*/alert("Stored-XSS")/**/</script>', 'Stored XSS with comments', 'stored', 'critical'),
        ]

        # XSS 檢測模式
        self.detection_patterns = [
            r'<script[^>]*>.*?alert.*?</script>',
            r'<img[^>]*onerror[^>]*=',
            r'<svg[^>]*onload[^>]*=',
            r'<iframe[^>]*src[^>]*=.*javascript:',
            r'javascript:.*alert',
            r'alert\s*\(',
            r'eval\s*\(',
            r'document\.write',
            r'innerHTML.*=',
        ]

        # 常見的輸入點
        self.input_patterns = [
            'input[type="text"]',
            'input[type="search"]',
            'input[type="email"]',
            'input[type="url"]',
            'textarea',
            'select',
            '[contenteditable]',
        ]

    async def scan(self, session: aiohttp.ClientSession, target, urls: List[str]) -> List[Any]:
        """
        執行 XSS 掃描

        Args:
            session: HTTP 客戶端會話
            target: 掃描目標配置
            urls: 要掃描的 URL 列表

        Returns:
            List[VulnerabilityResult]: 發現的漏洞列表
        """
        vulnerabilities = []

        logger.info(f"開始 XSS 掃描，目標 URLs: {len(urls)}")

        for url in urls:
            try:
                # 反射型 XSS 掃描
                reflected_vulns = await self._scan_reflected_xss(session, url)
                vulnerabilities.extend(reflected_vulns)

                # DOM 型 XSS 掃描
                dom_vulns = await self._scan_dom_xss(session, url)
                vulnerabilities.extend(dom_vulns)

                # 儲存型 XSS 掃描 (基礎檢測)
                stored_vulns = await self._scan_stored_xss(session, url)
                vulnerabilities.extend(stored_vulns)

                # 延遲避免過度負載
                await asyncio.sleep(0.1)

            except Exception as e:
                logger.error(f"XSS 掃描 URL {url} 時發生錯誤: {str(e)}")
                continue

        logger.info(f"XSS 掃描完成，發現 {len(vulnerabilities)} 個潛在漏洞")
        return vulnerabilities

    async def _scan_reflected_xss(self, session: aiohttp.ClientSession, url: str) -> List[Any]:
        """掃描反射型 XSS"""
        vulnerabilities = []

        # 獲取原始頁面
        try:
            async with session.get(url, timeout=10) as response:
                original_content = await response.text()
                soup = BeautifulSoup(original_content, 'html.parser')
        except Exception as e:
            logger.debug(f"無法獲取頁面 {url}: {str(e)}")
            return vulnerabilities

        # 查找表單輸入點
        forms = soup.find_all('form')
        for form in forms:
            form_vulns = await self._test_form_xss(session, url, form)
            vulnerabilities.extend(form_vulns)

        # 查找 GET 參數輸入點
        url_vulns = await self._test_url_parameters_xss(session, url)
        vulnerabilities.extend(url_vulns)

        return vulnerabilities

    async def _test_form_xss(self, session: aiohttp.ClientSession, url: str, form) -> List[Any]:
        """測試表單 XSS"""
        vulnerabilities = []

        form_action = form.get('action', '')
        form_method = form.get('method', 'get').lower()

        # 構建完整的表單提交 URL
        if form_action:
            if form_action.startswith('/'):
                form_url = urljoin(url, form_action)
            elif form_action.startswith('http'):
                form_url = form_action
            else:
                form_url = urljoin(url, form_action)
        else:
            form_url = url

        # 收集表單字段
        form_data = {}
        inputs = form.find_all(['input', 'textarea', 'select'])

        for input_elem in inputs:
            name = input_elem.get('name')
            if name:
                input_type = input_elem.get('type', 'text')
                if input_type not in ['submit', 'button', 'image', 'reset']:
                    form_data[name] = 'test_value'

        # 測試每個表單字段
        for field_name in form_data.keys():
            field_vulns = await self._test_form_field_xss(
                session, form_url, form_data, field_name, form_method
            )
            vulnerabilities.extend(field_vulns)

        return vulnerabilities

    async def _test_form_field_xss(
        self,
        session: aiohttp.ClientSession,
        form_url: str,
        form_data: Dict[str, str],
        field_name: str,
        method: str
    ) -> List[Any]:
        """測試特定表單字段的 XSS"""
        vulnerabilities = []

        for payload_obj in self.payloads[:5]:  # 限制測試負載數量
            if payload_obj.type != 'reflected':
                continue

            # 準備測試資料
            test_data = form_data.copy()
            test_data[field_name] = payload_obj.payload

            try:
                if method == 'post':
                    async with session.post(form_url, data=test_data, timeout=10) as response:
                        response_text = await response.text()
                else:
                    params = urlencode(test_data)
                    test_url = f"{form_url}?{params}"
                    async with session.get(test_url, timeout=10) as response:
                        response_text = await response.text()

                # 檢查是否成功注入
                if self._check_xss_injection(response_text, payload_obj.payload):
                    vulnerability = self._create_vulnerability_result(
                        title=f"反射型 XSS 漏洞在表單字段 '{field_name}'",
                        description=f"在表單字段 '{field_name}' 中檢測到反射型 XSS 漏洞。惡意腳本可以透過此欄位執行。",
                        severity=payload_obj.severity,
                        affected_url=form_url,
                        request_method=method.upper(),
                        request_payload=f"{field_name}={payload_obj.payload}",
                        response_evidence=self._extract_evidence(response_text, payload_obj.payload),
                        cwe_id="CWE-79",
                        owasp_category="A03:2021 – Injection"
                    )
                    vulnerabilities.append(vulnerability)
                    break  # 找到一個就足夠了

            except Exception as e:
                logger.debug(f"測試表單字段 XSS 時發生錯誤: {str(e)}")
                continue

        return vulnerabilities

    async def _test_url_parameters_xss(self, session: aiohttp.ClientSession, url: str) -> List[Any]:
        """測試 URL 參數 XSS"""
        vulnerabilities = []

        # 解析 URL 參數
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        if not params:
            return vulnerabilities

        # 測試每個參數
        for param_name in params.keys():
            for payload_obj in self.payloads[:3]:  # 限制測試負載
                if payload_obj.type != 'reflected':
                    continue

                # 構建測試 URL
                test_params = params.copy()
                test_params[param_name] = [payload_obj.payload]

                test_query = urlencode({k: v[0] if isinstance(v, list) else v
                                      for k, v in test_params.items()})
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{test_query}"

                try:
                    async with session.get(test_url, timeout=10) as response:
                        response_text = await response.text()

                    if self._check_xss_injection(response_text, payload_obj.payload):
                        vulnerability = self._create_vulnerability_result(
                            title=f"反射型 XSS 漏洞在 URL 參數 '{param_name}'",
                            description=f"在 URL 參數 '{param_name}' 中檢測到反射型 XSS 漏洞。",
                            severity=payload_obj.severity,
                            affected_url=test_url,
                            request_method="GET",
                            request_payload=f"{param_name}={payload_obj.payload}",
                            response_evidence=self._extract_evidence(response_text, payload_obj.payload),
                            cwe_id="CWE-79",
                            owasp_category="A03:2021 – Injection"
                        )
                        vulnerabilities.append(vulnerability)
                        break

                except Exception as e:
                    logger.debug(f"測試 URL 參數 XSS 時發生錯誤: {str(e)}")
                    continue

        return vulnerabilities

    async def _scan_dom_xss(self, session: aiohttp.ClientSession, url: str) -> List[Any]:
        """掃描 DOM 型 XSS (基礎檢測)"""
        vulnerabilities = []

        try:
            async with session.get(url, timeout=10) as response:
                content = await response.text()

            # 檢查危險的 JavaScript 模式
            dom_patterns = [
                r'document\.write\s*\(\s*[^)]*location',
                r'innerHTML\s*=\s*[^;]*location',
                r'document\.URL',
                r'window\.location',
                r'document\.location',
                r'eval\s*\(\s*[^)]*location',
            ]

            for pattern in dom_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    vulnerability = self._create_vulnerability_result(
                        title="潛在的 DOM 型 XSS 漏洞",
                        description="檢測到可能導致 DOM 型 XSS 的 JavaScript 代碼模式。",
                        severity="medium",
                        affected_url=url,
                        request_method="GET",
                        request_payload="",
                        response_evidence=pattern,
                        cwe_id="CWE-79",
                        owasp_category="A03:2021 – Injection"
                    )
                    vulnerabilities.append(vulnerability)
                    break  # 避免重複報告

        except Exception as e:
            logger.debug(f"DOM XSS 掃描錯誤: {str(e)}")

        return vulnerabilities

    async def _scan_stored_xss(self, session: aiohttp.ClientSession, url: str) -> List[Any]:
        """掃描儲存型 XSS (基礎檢測)"""
        vulnerabilities = []

        # 這裡只是基本的儲存型 XSS 檢測示例
        # 實際應用中需要更複雜的邏輯來測試資料持久性

        try:
            async with session.get(url, timeout=10) as response:
                content = await response.text()

            # 檢查頁面中是否存在可疑的儲存型內容
            soup = BeautifulSoup(content, 'html.parser')

            # 查找評論、留言板、用戶生成內容等區域
            potential_stored_areas = soup.find_all(['div', 'span', 'p'],
                                                 class_=re.compile(r'comment|message|post|content', re.I))

            for area in potential_stored_areas:
                area_text = area.get_text()
                for pattern in self.detection_patterns:
                    if re.search(pattern, area_text, re.IGNORECASE):
                        vulnerability = self._create_vulnerability_result(
                            title="潛在的儲存型 XSS 漏洞",
                            description="在用戶生成內容區域發現可疑的 JavaScript 代碼，可能為儲存型 XSS。",
                            severity="high",
                            affected_url=url,
                            request_method="GET",
                            request_payload="",
                            response_evidence=area_text[:200],
                            cwe_id="CWE-79",
                            owasp_category="A03:2021 – Injection"
                        )
                        vulnerabilities.append(vulnerability)
                        break

        except Exception as e:
            logger.debug(f"儲存型 XSS 掃描錯誤: {str(e)}")

        return vulnerabilities

    def _check_xss_injection(self, response_text: str, payload: str) -> bool:
        """檢查 XSS 注入是否成功"""
        # 檢查負載是否直接反射
        if payload in response_text:
            return True

        # 檢查是否觸發了 JavaScript 執行特徵
        for pattern in self.detection_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False

    def _extract_evidence(self, response_text: str, payload: str) -> str:
        """提取漏洞證據"""
        # 找到負載在回應中的位置
        index = response_text.find(payload)
        if index != -1:
            start = max(0, index - 50)
            end = min(len(response_text), index + len(payload) + 50)
            return response_text[start:end]

        return response_text[:200]  # 返回前200字符作為證據

    def _create_vulnerability_result(self, **kwargs):
        """創建漏洞結果對象"""
        from core.scanner_engine import VulnerabilityResult

        return VulnerabilityResult(
            id=f"xss_{int(time.time())}",
            title=kwargs.get('title', 'XSS Vulnerability'),
            description=kwargs.get('description', ''),
            severity=kwargs.get('severity', 'medium'),
            cwe_id=kwargs.get('cwe_id', 'CWE-79'),
            owasp_category=kwargs.get('owasp_category', 'A03:2021 – Injection'),
            affected_url=kwargs.get('affected_url', ''),
            request_method=kwargs.get('request_method', 'GET'),
            request_payload=kwargs.get('request_payload', ''),
            response_evidence=kwargs.get('response_evidence', ''),
            remediation=self._get_remediation_advice(),
            risk_score=self._calculate_risk_score(kwargs.get('severity', 'medium')),
            confidence="likely",
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
        )

    def _calculate_risk_score(self, severity: str) -> float:
        """計算風險評分"""
        risk_scores = {
            'critical': 9.5,
            'high': 8.0,
            'medium': 5.5,
            'low': 3.0
        }
        return risk_scores.get(severity, 5.0)

    def _get_remediation_advice(self) -> str:
        """獲取修復建議"""
        return """
修復建議:
1. 對所有用戶輸入進行適當的編碼和轉義
2. 使用內容安全策略 (CSP) 來限制腳本執行
3. 驗證和清理所有輸入資料
4. 使用安全的輸出編碼函數
5. 避免直接將用戶輸入插入 HTML 中
6. 定期進行安全代碼審查
"""