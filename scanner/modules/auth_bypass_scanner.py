#!/usr/bin/env python3
"""
認證繞過漏洞掃描模組
檢測身份驗證繞過和授權缺陷
"""

import asyncio
import logging
import time
import re
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse, quote
import aiohttp
from bs4 import BeautifulSoup
import base64

logger = logging.getLogger(__name__)

class AuthBypassScanner:
    """認證繞過漏洞掃描器"""

    def __init__(self):
        self.name = "Auth Bypass Scanner"
        self.description = "Authentication bypass vulnerability scanner"

        # 常見的管理員和敏感路徑
        self.admin_paths = [
            '/admin',
            '/administrator',
            '/admin.php',
            '/admin/',
            '/panel',
            '/control',
            '/dashboard',
            '/manage',
            '/manager',
            '/cp',
            '/controlpanel',
            '/admin/login',
            '/admin/index',
            '/admin/dashboard',
            '/wp-admin',
            '/phpmyadmin',
        ]

        # 常見的認證繞過負載
        self.bypass_payloads = [
            # SQL注入繞過
            ("admin'--", "password"),
            ("admin'/*", "password"),
            ("' or '1'='1'--", "password"),
            ("' or 1=1#", "password"),
            ("admin", "' or '1'='1"),
            ("admin", "' or 1=1#"),

            # 空值繞過
            ("admin", ""),
            ("", ""),
            ("admin", " "),

            # 預設認證
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("test", "test"),
            ("guest", "guest"),
            ("user", "user"),

            # 特殊字符繞過
            ("admin\x00", "password"),
            ("admin\n", "password"),
            ("admin\r", "password"),
            ("admin\t", "password"),
        ]

        # HTTP方法繞過
        self.http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']

        # 常見的認證相關參數
        self.auth_params = [
            'username', 'user', 'login', 'email', 'userid', 'user_id',
            'password', 'pass', 'pwd', 'passwd', 'secret'
        ]

    async def scan(self, session: aiohttp.ClientSession, target, urls: List[str]) -> List[Any]:
        """
        執行認證繞過掃描

        Args:
            session: HTTP 客戶端會話
            target: 掃描目標配置
            urls: 要掃描的 URL 列表

        Returns:
            List[VulnerabilityResult]: 發現的漏洞列表
        """
        vulnerabilities = []

        logger.info(f"開始認證繞過掃描，目標 URLs: {len(urls)}")

        # 掃描管理員路徑
        admin_vulns = await self._scan_admin_paths(session, target.url)
        vulnerabilities.extend(admin_vulns)

        # 掃描現有 URLs 的認證繞過
        for url in urls[:10]:  # 限制掃描數量
            try:
                # 登錄表單繞過
                login_vulns = await self._scan_login_bypass(session, url)
                vulnerabilities.extend(login_vulns)

                # HTTP方法繞過
                method_vulns = await self._scan_http_method_bypass(session, url)
                vulnerabilities.extend(method_vulns)

                # 路徑繞過
                path_vulns = await self._scan_path_bypass(session, url)
                vulnerabilities.extend(path_vulns)

                # 參數污染
                param_vulns = await self._scan_parameter_pollution(session, url)
                vulnerabilities.extend(param_vulns)

                await asyncio.sleep(0.2)

            except Exception as e:
                logger.error(f"認證繞過掃描 URL {url} 時發生錯誤: {str(e)}")
                continue

        logger.info(f"認證繞過掃描完成，發現 {len(vulnerabilities)} 個潛在漏洞")
        return vulnerabilities

    async def _scan_admin_paths(self, session: aiohttp.ClientSession, base_url: str) -> List[Any]:
        """掃描管理員路徑"""
        vulnerabilities = []

        for admin_path in self.admin_paths:
            try:
                admin_url = urljoin(base_url, admin_path)

                async with session.get(admin_url, timeout=10, allow_redirects=False) as response:
                    status = response.status
                    content = await response.text()

                    # 檢查是否可以直接訪問管理面板
                    if self._is_admin_panel_accessible(status, content):
                        vulnerability = self._create_vulnerability_result(
                            title=f"管理面板未受保護 - {admin_path}",
                            description=f"管理面板路徑 '{admin_path}' 可以直接訪問，未要求身份驗證。",
                            severity="high",
                            affected_url=admin_url,
                            request_method="GET",
                            request_payload="",
                            response_evidence=f"Status: {status}",
                            cwe_id="CWE-306",
                            owasp_category="A07:2021 – Identification and Authentication Failures"
                        )
                        vulnerabilities.append(vulnerability)

                    # 如果需要認證，嘗試認證繞過
                    elif status == 401 or 'login' in content.lower():
                        bypass_vulns = await self._test_admin_login_bypass(session, admin_url)
                        vulnerabilities.extend(bypass_vulns)

            except Exception as e:
                logger.debug(f"管理員路徑掃描錯誤 {admin_path}: {str(e)}")
                continue

        return vulnerabilities

    async def _scan_login_bypass(self, session: aiohttp.ClientSession, url: str) -> List[Any]:
        """掃描登錄表單繞過"""
        vulnerabilities = []

        try:
            async with session.get(url, timeout=10) as response:
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')

            # 查找登錄表單
            login_forms = self._find_login_forms(soup)

            for form in login_forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'post').lower()

                # 構建表單提交 URL
                if form_action:
                    form_url = urljoin(url, form_action)
                else:
                    form_url = url

                # 測試認證繞過負載
                bypass_vulns = await self._test_login_form_bypass(
                    session, form_url, form, form_method
                )
                vulnerabilities.extend(bypass_vulns)

        except Exception as e:
            logger.debug(f"登錄表單掃描錯誤: {str(e)}")

        return vulnerabilities

    async def _test_admin_login_bypass(self, session: aiohttp.ClientSession, admin_url: str) -> List[Any]:
        """測試管理員登錄繞過"""
        vulnerabilities = []

        # 嘗試預設認證
        for username, password in self.bypass_payloads:
            try:
                # 嘗試基本認證
                auth = aiohttp.BasicAuth(username, password)
                async with session.get(admin_url, auth=auth, timeout=5) as response:
                    if response.status == 200:
                        content = await response.text()
                        if self._is_admin_panel_accessible(response.status, content):
                            vulnerability = self._create_vulnerability_result(
                                title=f"管理員認證繞過 - 預設認證",
                                description=f"使用預設認證 {username}:{password} 成功訪問管理面板。",
                                severity="critical",
                                affected_url=admin_url,
                                request_method="GET",
                                request_payload=f"Basic Auth: {username}:{password}",
                                response_evidence="成功訪問管理面板",
                                cwe_id="CWE-521",
                                owasp_category="A07:2021 – Identification and Authentication Failures"
                            )
                            vulnerabilities.append(vulnerability)
                            break

            except Exception as e:
                logger.debug(f"基本認證測試錯誤: {str(e)}")
                continue

        return vulnerabilities

    async def _test_login_form_bypass(
        self,
        session: aiohttp.ClientSession,
        form_url: str,
        form,
        method: str
    ) -> List[Any]:
        """測試登錄表單繞過"""
        vulnerabilities = []

        # 收集表單字段
        form_fields = self._extract_form_fields(form)
        if not form_fields:
            return vulnerabilities

        # 識別用戶名和密碼字段
        username_field, password_field = self._identify_auth_fields(form_fields)
        if not username_field or not password_field:
            return vulnerabilities

        # 測試每個繞過負載
        for username, password in self.bypass_payloads[:5]:  # 限制測試數量
            try:
                test_data = form_fields.copy()
                test_data[username_field] = username
                test_data[password_field] = password

                if method == 'post':
                    async with session.post(form_url, data=test_data, timeout=10) as response:
                        success = await self._check_login_success(response)
                else:
                    params = '&'.join([f"{k}={quote(str(v))}" for k, v in test_data.items()])
                    test_url = f"{form_url}?{params}"
                    async with session.get(test_url, timeout=10) as response:
                        success = await self._check_login_success(response)

                if success:
                    vulnerability = self._create_vulnerability_result(
                        title="認證繞過漏洞 - 登錄表單",
                        description=f"使用負載 {username}:{password} 成功繞過登錄驗證。",
                        severity="critical",
                        affected_url=form_url,
                        request_method=method.upper(),
                        request_payload=f"{username_field}={username}&{password_field}={password}",
                        response_evidence="成功登錄",
                        cwe_id="CWE-287",
                        owasp_category="A07:2021 – Identification and Authentication Failures"
                    )
                    vulnerabilities.append(vulnerability)
                    break  # 找到一個成功的就足夠了

            except Exception as e:
                logger.debug(f"登錄表單繞過測試錯誤: {str(e)}")
                continue

        return vulnerabilities

    async def _scan_http_method_bypass(self, session: aiohttp.ClientSession, url: str) -> List[Any]:
        """掃描 HTTP 方法繞過"""
        vulnerabilities = []

        # 首先檢查正常 GET 請求的回應
        try:
            async with session.get(url, timeout=10) as response:
                original_status = response.status
                original_content = await response.text()
        except Exception:
            return vulnerabilities

        # 如果原始請求被拒絕 (401, 403)，嘗試其他方法
        if original_status in [401, 403]:
            for method in self.http_methods:
                if method == 'GET':  # 已經測試過了
                    continue

                try:
                    async with session.request(method, url, timeout=5) as response:
                        if response.status == 200:
                            content = await response.text()
                            if len(content) > 100 and content != original_content:
                                vulnerability = self._create_vulnerability_result(
                                    title=f"HTTP 方法繞過 - {method}",
                                    description=f"使用 {method} 方法可以繞過認證限制訪問受保護的資源。",
                                    severity="medium",
                                    affected_url=url,
                                    request_method=method,
                                    request_payload="",
                                    response_evidence=f"Status: {response.status}",
                                    cwe_id="CWE-425",
                                    owasp_category="A05:2021 – Security Misconfiguration"
                                )
                                vulnerabilities.append(vulnerability)
                                break

                except Exception as e:
                    logger.debug(f"HTTP方法測試錯誤 {method}: {str(e)}")
                    continue

        return vulnerabilities

    async def _scan_path_bypass(self, session: aiohttp.ClientSession, url: str) -> List[Any]:
        """掃描路徑繞過"""
        vulnerabilities = []

        # 路徑繞過技術
        bypass_paths = [
            url + '/',
            url + '/.',
            url + '/./',
            url + '//',
            url + '\\',
            url + '%2e',
            url + '%2f',
            url + '%5c',
            url + ';',
            url + '?',
            url + '#',
            url.replace('/', '/./'),
            url.replace('/', '//'),
            url + '%00',
            url + '%0a',
            url + '%0d',
            url + '%09',
        ]

        # 首先檢查原始 URL 的狀態
        try:
            async with session.get(url, timeout=10) as response:
                original_status = response.status
        except Exception:
            return vulnerabilities

        # 如果原始 URL 被拒絕，嘗試繞過技術
        if original_status in [401, 403, 404]:
            for bypass_url in bypass_paths:
                try:
                    async with session.get(bypass_url, timeout=5) as response:
                        if response.status == 200:
                            content = await response.text()
                            if len(content) > 100:  # 確保有實質內容
                                vulnerability = self._create_vulnerability_result(
                                    title="路徑繞過漏洞",
                                    description=f"使用路徑操作技術可以繞過存取限制。繞過 URL: {bypass_url}",
                                    severity="medium",
                                    affected_url=bypass_url,
                                    request_method="GET",
                                    request_payload="",
                                    response_evidence=f"Original: {original_status}, Bypass: 200",
                                    cwe_id="CWE-22",
                                    owasp_category="A01:2021 – Broken Access Control"
                                )
                                vulnerabilities.append(vulnerability)
                                break

                except Exception as e:
                    logger.debug(f"路徑繞過測試錯誤: {str(e)}")
                    continue

        return vulnerabilities

    async def _scan_parameter_pollution(self, session: aiohttp.ClientSession, url: str) -> List[Any]:
        """掃描參數污染攻擊"""
        vulnerabilities = []

        # 如果 URL 包含參數，測試參數污染
        if '?' in url:
            base_url, query_string = url.split('?', 1)

            # 測試重複參數
            pollution_tests = [
                query_string + '&admin=true',
                query_string + '&user=admin',
                query_string + '&role=admin',
                query_string + '&auth=bypass',
                query_string + '&login=1',
                query_string + '&authenticated=1',
            ]

            for test_query in pollution_tests:
                test_url = f"{base_url}?{test_query}"

                try:
                    async with session.get(test_url, timeout=10) as response:
                        content = await response.text()

                        # 檢查是否有認證繞過的跡象
                        if self._check_auth_bypass_indicators(content):
                            vulnerability = self._create_vulnerability_result(
                                title="參數污染認證繞過",
                                description="通過參數污染技術可能繞過認證限制。",
                                severity="medium",
                                affected_url=test_url,
                                request_method="GET",
                                request_payload=test_query,
                                response_evidence="檢測到認證繞過指標",
                                cwe_id="CWE-235",
                                owasp_category="A03:2021 – Injection"
                            )
                            vulnerabilities.append(vulnerability)
                            break

                except Exception as e:
                    logger.debug(f"參數污染測試錯誤: {str(e)}")
                    continue

        return vulnerabilities

    def _find_login_forms(self, soup: BeautifulSoup) -> List:
        """查找登錄表單"""
        login_forms = []

        # 查找所有表單
        forms = soup.find_all('form')
        for form in forms:
            # 檢查表單是否為登錄表單
            if self._is_login_form(form):
                login_forms.append(form)

        return login_forms

    def _is_login_form(self, form) -> bool:
        """判斷是否為登錄表單"""
        # 檢查表單屬性
        form_action = form.get('action', '').lower()
        form_id = form.get('id', '').lower()
        form_class = ' '.join(form.get('class', [])).lower()

        login_indicators = ['login', 'signin', 'auth', 'session']

        for indicator in login_indicators:
            if indicator in form_action or indicator in form_id or indicator in form_class:
                return True

        # 檢查表單字段
        inputs = form.find_all(['input', 'textarea'])
        has_username = False
        has_password = False

        for input_elem in inputs:
            input_type = input_elem.get('type', '').lower()
            input_name = input_elem.get('name', '').lower()

            if input_type == 'password':
                has_password = True
            elif input_type in ['text', 'email'] or 'user' in input_name or 'email' in input_name:
                has_username = True

        return has_username and has_password

    def _extract_form_fields(self, form) -> Dict[str, str]:
        """提取表單字段"""
        fields = {}
        inputs = form.find_all(['input', 'textarea', 'select'])

        for input_elem in inputs:
            name = input_elem.get('name')
            input_type = input_elem.get('type', 'text')
            value = input_elem.get('value', '')

            if name and input_type not in ['submit', 'button', 'image', 'reset']:
                fields[name] = value

        return fields

    def _identify_auth_fields(self, form_fields: Dict[str, str]) -> Tuple[Optional[str], Optional[str]]:
        """識別用戶名和密碼字段"""
        username_field = None
        password_field = None

        for field_name in form_fields.keys():
            field_name_lower = field_name.lower()

            # 識別用戶名字段
            if any(param in field_name_lower for param in ['username', 'user', 'login', 'email']):
                username_field = field_name

            # 識別密碼字段
            elif any(param in field_name_lower for param in ['password', 'pass', 'pwd', 'passwd']):
                password_field = field_name

        return username_field, password_field

    async def _check_login_success(self, response: aiohttp.ClientResponse) -> bool:
        """檢查登錄是否成功"""
        # 檢查重定向
        if 300 <= response.status < 400:
            location = response.headers.get('Location', '')
            success_indicators = ['dashboard', 'admin', 'welcome', 'profile', 'home']
            if any(indicator in location.lower() for indicator in success_indicators):
                return True

        # 檢查回應內容
        try:
            content = await response.text()
            success_patterns = [
                r'welcome',
                r'dashboard',
                r'logout',
                r'profile',
                r'admin panel',
                r'successfully logged in',
                r'login successful',
            ]

            for pattern in success_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True

            # 檢查是否沒有錯誤訊息
            error_patterns = [
                r'invalid',
                r'incorrect',
                r'failed',
                r'error',
                r'wrong',
                r'denied',
            ]

            has_error = any(re.search(pattern, content, re.IGNORECASE) for pattern in error_patterns)

            # 如果沒有錯誤且頁面內容豐富，可能是成功的
            if not has_error and len(content) > 1000:
                return True

        except Exception:
            pass

        return False

    def _is_admin_panel_accessible(self, status: int, content: str) -> bool:
        """檢查管理面板是否可訪問"""
        if status != 200:
            return False

        admin_indicators = [
            'admin panel',
            'administration',
            'control panel',
            'dashboard',
            'manage',
            'settings',
            'users',
            'configuration',
        ]

        content_lower = content.lower()
        return any(indicator in content_lower for indicator in admin_indicators)

    def _check_auth_bypass_indicators(self, content: str) -> bool:
        """檢查認證繞過指標"""
        bypass_indicators = [
            'admin',
            'authenticated',
            'welcome',
            'dashboard',
            'control panel',
            'settings',
            'logout',
        ]

        content_lower = content.lower()
        return any(indicator in content_lower for indicator in bypass_indicators)

    def _create_vulnerability_result(self, **kwargs):
        """創建漏洞結果對象"""
        from core.scanner_engine import VulnerabilityResult

        return VulnerabilityResult(
            id=f"auth_bypass_{int(time.time())}",
            title=kwargs.get('title', 'Authentication Bypass Vulnerability'),
            description=kwargs.get('description', ''),
            severity=kwargs.get('severity', 'high'),
            cwe_id=kwargs.get('cwe_id', 'CWE-287'),
            owasp_category=kwargs.get('owasp_category', 'A07:2021 – Identification and Authentication Failures'),
            affected_url=kwargs.get('affected_url', ''),
            request_method=kwargs.get('request_method', 'GET'),
            request_payload=kwargs.get('request_payload', ''),
            response_evidence=kwargs.get('response_evidence', ''),
            remediation=self._get_remediation_advice(),
            risk_score=self._calculate_risk_score(kwargs.get('severity', 'high')),
            confidence="likely",
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
        )

    def _calculate_risk_score(self, severity: str) -> float:
        """計算風險評分"""
        risk_scores = {
            'critical': 9.8,
            'high': 8.5,
            'medium': 6.0,
            'low': 3.5
        }
        return risk_scores.get(severity, 6.0)

    def _get_remediation_advice(self) -> str:
        """獲取修復建議"""
        return """
修復建議:
1. 實施強密碼政策，禁用預設認證
2. 使用多因素認證 (MFA)
3. 實施帳戶鎖定機制防止暴力破解
4. 使用安全的會話管理
5. 實施適當的輸入驗證和清理
6. 限制管理面板的網路存取
7. 定期審核使用者權限和存取控制
8. 使用 HTTPS 加密認證資料傳輸
"""