#!/usr/bin/env python3
"""
CSRF 漏洞掃描模組
檢測跨站請求偽造漏洞
"""

import asyncio
import logging
import time
import re
import json
import os
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
import aiohttp
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class CSRFScanner:
    """CSRF 漏洞掃描器"""

    def __init__(self):
        self.name = "CSRF Scanner"
        self.description = "Cross-Site Request Forgery vulnerability scanner"

        self.rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'rules')
        self.rules_file = os.path.join(self.rules_dir, 'csrf_patterns.json')
        self.csrf_token_names = []
        self.sensitive_actions = []
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
            
            # 載入 CSRF token names
            self.csrf_token_names = rules.get('csrf_token_names', [])
            
            # 載入 sensitive actions
            self.sensitive_actions = rules.get('sensitive_actions', [])
            
            logger.info(f"Loaded {len(self.csrf_token_names)} CSRF token names, {len(self.sensitive_actions)} sensitive actions from {self.rules_file}")
            
        except Exception as e:
            logger.error(f"Failed to load rules from {self.rules_file}: {e}")
            logger.warning("Falling back to hardcoded rules")
            self._initialize_fallback_rules()

    def reload_rules(self) -> None:
        """重新載入規則(熱重載)"""
        logger.info("Reloading CSRF rules...")
        self.csrf_token_names = []
        self.sensitive_actions = []
        self._load_rules_from_file()

    def _initialize_fallback_rules(self) -> None:
        """初始化備用規則(當 JSON 檔案不存在時)"""
        # 常見的 CSRF token 名稱
        self.csrf_token_names = [
            'csrf_token',
            'csrftoken',
            'csrf',
            '_token',
            'authenticity_token',
            'token',
            'security_token',
            'anti_csrf_token',
            'form_token',
            'session_token',
            '_csrf'
        ]

        # 需要檢查的表單動作
        self.sensitive_actions = [
            'login',
            'register',
            'delete',
            'update',
            'edit',
            'admin',
            'profile',
            'settings',
            'password',
            'email',
            'transfer',
            'payment',
            'purchase'
        ]

    async def scan(self, session: aiohttp.ClientSession, target, urls: List[str]) -> List[Any]:
        """
        執行 CSRF 掃描

        Args:
            session: HTTP 客戶端會話
            target: 掃描目標配置
            urls: 要掃描的 URL 列表

        Returns:
            List[VulnerabilityResult]: 發現的漏洞列表
        """
        vulnerabilities = []

        logger.info(f"開始 CSRF 掃描，目標 URLs: {len(urls)}")

        for url in urls:
            try:
                # 檢查表單的 CSRF 保護
                form_vulns = await self._scan_form_csrf(session, url)
                vulnerabilities.extend(form_vulns)

                # 檢查 AJAX 請求的 CSRF 保護
                ajax_vulns = await self._scan_ajax_csrf(session, url)
                vulnerabilities.extend(ajax_vulns)

                # 檢查 API 端點的 CSRF 保護
                api_vulns = await self._scan_api_csrf(session, url)
                vulnerabilities.extend(api_vulns)

                # 延遲避免過度負載
                await asyncio.sleep(0.1)

            except Exception as e:
                logger.error(f"CSRF 掃描 URL {url} 時發生錯誤: {str(e)}")
                continue

        logger.info(f"CSRF 掃描完成，發現 {len(vulnerabilities)} 個潛在漏洞")
        return vulnerabilities

    async def _scan_form_csrf(self, session: aiohttp.ClientSession, url: str) -> List[Any]:
        """掃描表單的 CSRF 保護"""
        vulnerabilities = []

        try:
            async with session.get(url, timeout=10) as response:
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')

            # 查找所有表單
            forms = soup.find_all('form')

            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()

                # 只檢查 POST 表單和敏感操作
                if form_method != 'post':
                    continue

                # 檢查是否為敏感表單
                is_sensitive = self._is_sensitive_form(form, form_action)

                if is_sensitive:
                    # 檢查 CSRF token
                    has_csrf_token = self._check_csrf_token_in_form(form)

                    if not has_csrf_token:
                        vulnerability = self._create_vulnerability_result(
                            title="CSRF 漏洞 - 缺少 CSRF Token",
                            description=f"表單缺少 CSRF token 保護。表單動作: {form_action}",
                            severity="high",
                            affected_url=url,
                            request_method="POST",
                            request_payload=f"Form action: {form_action}",
                            response_evidence=str(form)[:200],
                            cwe_id="CWE-352",
                            owasp_category="A01:2021 – Broken Access Control"
                        )
                        vulnerabilities.append(vulnerability)

                    # 檢查 SameSite cookie 設定
                    samesite_vuln = await self._check_samesite_cookies(session, url)
                    if samesite_vuln:
                        vulnerabilities.append(samesite_vuln)

        except Exception as e:
            logger.debug(f"表單 CSRF 掃描錯誤: {str(e)}")

        return vulnerabilities

    async def _scan_ajax_csrf(self, session: aiohttp.ClientSession, url: str) -> List[Any]:
        """掃描 AJAX 請求的 CSRF 保護"""
        vulnerabilities = []

        try:
            async with session.get(url, timeout=10) as response:
                content = await response.text()

            # 查找 AJAX 請求模式
            ajax_patterns = [
                r'\$\.ajax\s*\(',
                r'\$\.post\s*\(',
                r'fetch\s*\(',
                r'XMLHttpRequest',
                r'axios\.',
                r'$.get\s*\(',
            ]

            for pattern in ajax_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    # 檢查是否有 CSRF header 設定
                    csrf_header_patterns = [
                        r'X-CSRFToken',
                        r'X-CSRF-Token',
                        r'X-Requested-With',
                    ]

                    has_csrf_header = any(
                        re.search(header_pattern, content, re.IGNORECASE)
                        for header_pattern in csrf_header_patterns
                    )

                    if not has_csrf_header:
                        vulnerability = self._create_vulnerability_result(
                            title="CSRF 漏洞 - AJAX 請求缺少保護",
                            description="檢測到 AJAX 請求但缺少 CSRF 保護 header。",
                            severity="medium",
                            affected_url=url,
                            request_method="GET",
                            request_payload="",
                            response_evidence=pattern,
                            cwe_id="CWE-352",
                            owasp_category="A01:2021 – Broken Access Control"
                        )
                        vulnerabilities.append(vulnerability)
                        break  # 避免重複報告

        except Exception as e:
            logger.debug(f"AJAX CSRF 掃描錯誤: {str(e)}")

        return vulnerabilities

    async def _scan_api_csrf(self, session: aiohttp.ClientSession, url: str) -> List[Any]:
        """掃描 API 端點的 CSRF 保護"""
        vulnerabilities = []

        # 常見的 API 端點模式
        api_patterns = [
            '/api/',
            '/rest/',
            '/graphql',
            '/v1/',
            '/v2/',
            '.json',
        ]

        for pattern in api_patterns:
            if pattern in url.lower():
                try:
                    # 嘗試不同的 HTTP 方法
                    methods_to_test = ['POST', 'PUT', 'DELETE', 'PATCH']

                    for method in methods_to_test:
                        test_data = {'test': 'csrf_test'}

                        try:
                            if method == 'POST':
                                async with session.post(url, json=test_data, timeout=5) as response:
                                    status = response.status
                            elif method == 'PUT':
                                async with session.put(url, json=test_data, timeout=5) as response:
                                    status = response.status
                            elif method == 'DELETE':
                                async with session.delete(url, timeout=5) as response:
                                    status = response.status
                            elif method == 'PATCH':
                                async with session.patch(url, json=test_data, timeout=5) as response:
                                    status = response.status

                            # 如果請求成功且沒有 CSRF 保護
                            if 200 <= status < 300:
                                # 檢查回應 headers 是否有 CSRF 相關訊息
                                headers = response.headers
                                csrf_headers = [
                                    'X-CSRF-Token-Required',
                                    'X-CSRF-Protection',
                                ]

                                has_csrf_protection = any(
                                    header.lower() in [h.lower() for h in headers.keys()]
                                    for header in csrf_headers
                                )

                                if not has_csrf_protection:
                                    vulnerability = self._create_vulnerability_result(
                                        title=f"API CSRF 漏洞 - {method} 方法",
                                        description=f"API 端點 {method} 方法缺少 CSRF 保護。",
                                        severity="medium",
                                        affected_url=url,
                                        request_method=method,
                                        request_payload=str(test_data),
                                        response_evidence=f"Status: {status}",
                                        cwe_id="CWE-352",
                                        owasp_category="A01:2021 – Broken Access Control"
                                    )
                                    vulnerabilities.append(vulnerability)

                        except aiohttp.ClientError:
                            # 連接錯誤是正常的，繼續下一個測試
                            continue
                        except asyncio.TimeoutError:
                            # 超時也繼續
                            continue

                except Exception as e:
                    logger.debug(f"API CSRF 掃描錯誤: {str(e)}")

                break  # 只要匹配到一個 API 模式就足夠了

        return vulnerabilities

    def _is_sensitive_form(self, form, action: str) -> bool:
        """檢查是否為敏感表單"""
        # 檢查表單動作
        action_lower = action.lower()
        for sensitive_action in self.sensitive_actions:
            if sensitive_action in action_lower:
                return True

        # 檢查表單中的輸入字段名稱
        inputs = form.find_all(['input', 'textarea', 'select'])
        for input_elem in inputs:
            name = input_elem.get('name', '').lower()
            input_type = input_elem.get('type', '').lower()

            # 檢查敏感字段名稱
            sensitive_fields = [
                'password', 'email', 'username', 'admin', 'delete',
                'transfer', 'amount', 'payment', 'credit'
            ]

            for sensitive_field in sensitive_fields:
                if sensitive_field in name:
                    return True

            # 檢查敏感輸入類型
            if input_type in ['password', 'email']:
                return True

        return False

    def _check_csrf_token_in_form(self, form) -> bool:
        """檢查表單中是否有 CSRF token"""
        inputs = form.find_all('input', type='hidden')

        for input_elem in inputs:
            name = input_elem.get('name', '').lower()
            for token_name in self.csrf_token_names:
                if token_name in name:
                    return True

        return False

    async def _check_samesite_cookies(self, session: aiohttp.ClientSession, url: str) -> Optional[Any]:
        """檢查 SameSite cookie 設定"""
        try:
            async with session.get(url, timeout=10) as response:
                cookies = response.cookies

                for cookie in cookies.values():
                    # 檢查會話 cookie 是否設定了 SameSite
                    if 'session' in cookie.key.lower() or 'auth' in cookie.key.lower():
                        if not hasattr(cookie, 'samesite') or not cookie.samesite:
                            return self._create_vulnerability_result(
                                title="CSRF 漏洞 - SameSite Cookie 未設定",
                                description=f"會話 cookie '{cookie.key}' 未設定 SameSite 屬性，可能導致 CSRF 攻擊。",
                                severity="medium",
                                affected_url=url,
                                request_method="GET",
                                request_payload="",
                                response_evidence=f"Cookie: {cookie.key}",
                                cwe_id="CWE-352",
                                owasp_category="A01:2021 – Broken Access Control"
                            )

        except Exception as e:
            logger.debug(f"SameSite cookie 檢查錯誤: {str(e)}")

        return None

    def _create_vulnerability_result(self, **kwargs):
        """創建漏洞結果對象"""
        from core.scanner_engine import VulnerabilityResult

        return VulnerabilityResult(
            id=f"csrf_{int(time.time())}",
            title=kwargs.get('title', 'CSRF Vulnerability'),
            description=kwargs.get('description', ''),
            severity=kwargs.get('severity', 'medium'),
            cwe_id=kwargs.get('cwe_id', 'CWE-352'),
            owasp_category=kwargs.get('owasp_category', 'A01:2021 – Broken Access Control'),
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
            'critical': 9.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5
        }
        return risk_scores.get(severity, 5.0)

    def _get_remediation_advice(self) -> str:
        """獲取修復建議"""
        return """
修復建議:
1. 在所有敏感表單中使用 CSRF token
2. 驗證 HTTP Referer header
3. 使用 SameSite cookie 屬性
4. 對於 AJAX 請求使用自定義 header (如 X-Requested-With)
5. 實施雙重提交 cookie 模式
6. 使用 CORS 政策限制跨域請求
7. 對重要操作實施二次確認
"""