#!/usr/bin/env python3
"""
資訊洩露漏洞掃描模組
檢測敏感資訊洩露和不當資訊公開
"""

import asyncio
import logging
import time
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
import aiohttp
from utils.vulnerability_templates import get_template_manager

logger = logging.getLogger(__name__)

class InfoDisclosureScanner:
    """資訊洩露漏洞掃描器"""

    def __init__(self):
        self.name = "Information Disclosure Scanner"
        self.description = "Information disclosure and sensitive data exposure scanner"

        # 敏感檔案清單
        self.sensitive_files = [
            # 配置檔案
            '.env',
            'config.php',
            'database.php',
            'wp-config.php',
            'settings.py',
            'application.properties',
            'web.config',
            'app.config',
            '.htaccess',
            '.htpasswd',
            'phpinfo.php',

            # 備份檔案
            'backup.sql',
            'dump.sql',
            'database.sql',
            'config.bak',
            'index.php.bak',
            'web.config.bak',
            'backup.tar.gz',
            'backup.zip',

            # 日誌檔案
            'access.log',
            'error.log',
            'debug.log',
            'application.log',
            'server.log',

            # 版本控制檔案
            '.git/config',
            '.git/HEAD',
            '.git/index',
            '.svn/entries',
            '.hg/hgrc',

            # 暫存檔案
            'temp.php',
            'test.php',
            'debug.php',
            'info.php',
            'phpinfo.php',
            'config.inc',

            # README 和文檔
            'README.md',
            'INSTALL.txt',
            'CHANGELOG.md',
            'TODO.txt',

            # 其他敏感檔案
            'robots.txt',
            'sitemap.xml',
            'crossdomain.xml',
            'clientaccesspolicy.xml',
        ]

        # 敏感目錄
        self.sensitive_directories = [
            '/.git/',
            '/.svn/',
            '/backup/',
            '/backups/',
            '/temp/',
            '/tmp/',
            '/logs/',
            '/log/',
            '/admin/',
            '/test/',
            '/debug/',
            '/config/',
            '/inc/',
            '/includes/',
            '/uploads/',
            '/files/',
        ]

        # 錯誤頁面觸發負載
        self.error_triggers = [
            "'",
            '"',
            '<>',
            '[]',
            '{}',
            'non_existent_page_12345',
            '/../',
            '%00',
            '\x00',
            '?id=',
            '?test=invalid',
        ]

        # 敏感資訊模式
        self.sensitive_patterns = {
            'email': [
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            ],
            'credit_card': [
                r'\b4[0-9]{12}(?:[0-9]{3})?\b',  # Visa
                r'\b5[1-5][0-9]{14}\b',          # MasterCard
                r'\b3[47][0-9]{13}\b',           # American Express
            ],
            'social_security': [
                r'\b\d{3}-\d{2}-\d{4}\b',
                r'\b\d{9}\b',
            ],
            'phone': [
                r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
                r'\(\d{3}\)\s*\d{3}[-.]?\d{4}',
            ],
            'api_key': [
                r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'secret[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'access[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            ],
            'database': [
                r'mysql://[^/]+/\w+',
                r'postgresql://[^/]+/\w+',
                r'mongodb://[^/]+/\w+',
                r'Server\s*=\s*[^;]+;Database\s*=\s*[^;]+',
            ],
            'path': [
                r'[A-Za-z]:\\\\[^\\]+\\\\',
                r'/home/[^/\s]+/',
                r'/var/www/[^/\s]+/',
                r'/usr/local/[^/\s]+/',
            ],
            'internal_ip': [
                r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
                r'\b172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b',
                r'\b192\.168\.\d{1,3}\.\d{1,3}\b',
            ],
            'version': [
                r'Server:\s*([^\r\n]+)',
                r'X-Powered-By:\s*([^\r\n]+)',
                r'Version\s*[:=]\s*([^\r\n\s]+)',
            ],
        }

    async def scan(self, session: aiohttp.ClientSession, target, urls: List[str]) -> List[Any]:
        """
        執行資訊洩露掃描

        Args:
            session: HTTP 客戶端會話
            target: 掃描目標配置
            urls: 要掃描的 URL 列表

        Returns:
            List[VulnerabilityResult]: 發現的漏洞列表
        """
        vulnerabilities = []

        logger.info(f"開始資訊洩露掃描，目標 URLs: {len(urls)}")

        # 掃描敏感檔案
        file_vulns = await self._scan_sensitive_files(session, target.url)
        vulnerabilities.extend(file_vulns)

        # 掃描敏感目錄
        dir_vulns = await self._scan_sensitive_directories(session, target.url)
        vulnerabilities.extend(dir_vulns)

        # 掃描錯誤頁面洩露
        error_vulns = await self._scan_error_disclosure(session, urls[0] if urls else target.url)
        vulnerabilities.extend(error_vulns)

        # 掃描 HTTP headers 洩露
        header_vulns = await self._scan_header_disclosure(session, urls[0] if urls else target.url)
        vulnerabilities.extend(header_vulns)

        # 掃描頁面內容中的敏感資訊
        for url in urls[:5]:  # 限制掃描數量
            try:
                content_vulns = await self._scan_content_disclosure(session, url)
                vulnerabilities.extend(content_vulns)

                await asyncio.sleep(0.1)

            except Exception as e:
                logger.error(f"內容掃描 URL {url} 時發生錯誤: {str(e)}")
                continue

        logger.info(f"資訊洩露掃描完成，發現 {len(vulnerabilities)} 個潛在漏洞")
        return vulnerabilities

    async def _scan_sensitive_files(self, session: aiohttp.ClientSession, base_url: str) -> List[Any]:
        """掃描敏感檔案"""
        vulnerabilities = []

        for sensitive_file in self.sensitive_files:
            try:
                file_url = urljoin(base_url, sensitive_file)

                async with session.get(file_url, timeout=10) as response:
                    if response.status == 200:
                        content = await response.text()

                        # 檢查是否為有效內容 (不是 404 頁面)
                        if self._is_valid_sensitive_content(content, sensitive_file):
                            # 分析內容中的敏感資訊
                            sensitive_info = self._analyze_sensitive_content(content)

                            severity = self._determine_file_severity(sensitive_file, sensitive_info)

                            vulnerability = self._create_vulnerability_result(
                                title=f"敏感檔案洩露 - {sensitive_file}",
                                description=f"發現可公開訪問的敏感檔案: {sensitive_file}",
                                severity=severity,
                                affected_url=file_url,
                                request_method="GET",
                                request_payload="",
                                response_evidence=self._sanitize_evidence(content[:300], sensitive_info),
                                cwe_id="CWE-200",
                                owasp_category="A01:2021 – Broken Access Control"
                            )
                            vulnerabilities.append(vulnerability)

            except Exception as e:
                logger.debug(f"敏感檔案掃描錯誤 {sensitive_file}: {str(e)}")
                continue

        return vulnerabilities

    async def _scan_sensitive_directories(self, session: aiohttp.ClientSession, base_url: str) -> List[Any]:
        """掃描敏感目錄"""
        vulnerabilities = []

        for sensitive_dir in self.sensitive_directories:
            try:
                dir_url = urljoin(base_url, sensitive_dir)

                async with session.get(dir_url, timeout=10) as response:
                    if response.status == 200:
                        content = await response.text()

                        # 檢查是否為目錄清單
                        if self._is_directory_listing(content):
                            vulnerability = self._create_vulnerability_result(
                                title=f"目錄清單洩露 - {sensitive_dir}",
                                description=f"發現可公開訪問的目錄清單: {sensitive_dir}",
                                severity="medium",
                                affected_url=dir_url,
                                request_method="GET",
                                request_payload="",
                                response_evidence=content[:300],
                                cwe_id="CWE-548",
                                owasp_category="A05:2021 – Security Misconfiguration"
                            )
                            vulnerabilities.append(vulnerability)

            except Exception as e:
                logger.debug(f"敏感目錄掃描錯誤 {sensitive_dir}: {str(e)}")
                continue

        return vulnerabilities

    async def _scan_error_disclosure(self, session: aiohttp.ClientSession, url: str) -> List[Any]:
        """掃描錯誤頁面資訊洩露"""
        vulnerabilities = []

        for trigger in self.error_triggers:
            try:
                # 在 URL 後添加觸發器
                if '?' in url:
                    test_url = f"{url}&error_test={trigger}"
                else:
                    test_url = f"{url}?error_test={trigger}"

                async with session.get(test_url, timeout=10) as response:
                    content = await response.text()

                    # 檢查錯誤訊息洩露
                    error_info = self._detect_error_disclosure(content)
                    if error_info:
                        vulnerability = self._create_vulnerability_result(
                            title="錯誤訊息洩露",
                            description=f"錯誤頁面洩露敏感資訊: {error_info['type']}",
                            severity="low",
                            affected_url=test_url,
                            request_method="GET",
                            request_payload=f"error_test={trigger}",
                            response_evidence=error_info['evidence'],
                            cwe_id="CWE-209",
                            owasp_category="A09:2021 – Security Logging and Monitoring Failures"
                        )
                        vulnerabilities.append(vulnerability)
                        break  # 找到一個就足夠了

            except Exception as e:
                logger.debug(f"錯誤頁面掃描錯誤: {str(e)}")
                continue

        return vulnerabilities

    async def _scan_header_disclosure(self, session: aiohttp.ClientSession, url: str) -> List[Any]:
        """掃描 HTTP headers 資訊洩露"""
        vulnerabilities = []
        template_mgr = get_template_manager()

        try:
            async with session.get(url, timeout=10) as response:
                headers = response.headers

                # 檢查洩露版本資訊的 headers
                version_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
                disclosed_headers = []
                
                for header_name in version_headers:
                    if header_name in headers:
                        header_value = headers[header_name]
                        if self._is_version_disclosure(header_value):
                            disclosed_headers.append(f"{header_name}: {header_value}")
                
                # 如果有資訊洩露,使用專業模板
                if disclosed_headers:
                    parsed_url = urlparse(url)
                    info_url = f"{parsed_url.scheme}://{parsed_url.netloc}/info"
                    
                    vuln_data = template_mgr.create_vulnerability_from_template(
                        'info_disclosure_server',
                        affected_url=info_url,
                        host=parsed_url.netloc,
                        url=url
                    )
                    
                    if vuln_data:
                        evidence = "\\n".join(disclosed_headers)
                        vulnerability = self._create_vulnerability_result(
                            title=vuln_data['title'],
                            description=vuln_data['description'],
                            severity=vuln_data['severity'],
                            affected_url=info_url,
                            request_method="GET",
                            request_payload="",
                            response_evidence=evidence,
                            cwe_id=vuln_data['cwe_id'],
                            owasp_category=vuln_data['owasp_category'],
                            remediation=vuln_data['remediation'],
                            cvss_score=vuln_data['cvss_score']
                        )
                        vulnerabilities.append(vulnerability)

                # 檢查調試 headers
                debug_headers = ['X-Debug', 'X-Debug-Info', 'X-Error-Details']
                for header_name in debug_headers:
                    if header_name in headers:
                        vulnerability = self._create_vulnerability_result(
                            title=f"調試資訊洩露 - {header_name}",
                            description=f"HTTP header '{header_name}' 洩露調試資訊。",
                            severity="medium",
                            affected_url=url,
                            request_method="GET",
                            request_payload="",
                            response_evidence=f"{header_name}: {headers[header_name]}",
                            cwe_id="CWE-489",
                            owasp_category="A09:2021 – Security Logging and Monitoring Failures"
                        )
                        vulnerabilities.append(vulnerability)

        except Exception as e:
            logger.debug(f"Header 掃描錯誤: {str(e)}")

        return vulnerabilities

    async def _scan_content_disclosure(self, session: aiohttp.ClientSession, url: str) -> List[Any]:
        """掃描頁面內容中的敏感資訊洩露"""
        vulnerabilities = []

        try:
            async with session.get(url, timeout=10) as response:
                content = await response.text()

                # 檢查各種敏感資訊模式
                for info_type, patterns in self.sensitive_patterns.items():
                    for pattern in patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            # 過濾明顯的假陽性
                            valid_matches = self._filter_false_positives(matches, info_type)
                            if valid_matches:
                                vulnerability = self._create_vulnerability_result(
                                    title=f"敏感資訊洩露 - {info_type.title()}",
                                    description=f"頁面內容中發現 {info_type} 資訊洩露。",
                                    severity=self._get_info_severity(info_type),
                                    affected_url=url,
                                    request_method="GET",
                                    request_payload="",
                                    response_evidence=f"找到 {len(valid_matches)} 個匹配項",
                                    cwe_id="CWE-200",
                                    owasp_category="A02:2021 – Cryptographic Failures"
                                )
                                vulnerabilities.append(vulnerability)
                                break  # 每種類型只報告一次

        except Exception as e:
            logger.debug(f"內容掃描錯誤: {str(e)}")

        return vulnerabilities

    def _is_valid_sensitive_content(self, content: str, filename: str) -> bool:
        """檢查是否為有效的敏感內容"""
        # 檢查是否為 404 頁面
        not_found_indicators = ['404', 'not found', 'page not found', 'file not found']
        content_lower = content.lower()

        if any(indicator in content_lower for indicator in not_found_indicators):
            return False

        # 檢查內容長度
        if len(content.strip()) < 10:
            return False

        # 根據檔案類型檢查特定內容
        if filename.endswith('.php') and '<?php' not in content:
            # PHP 檔案應該包含 PHP 標籤
            return len(content) > 100  # 但也可能是純 HTML

        if filename.endswith(('.sql', '.bak', '.backup')) and len(content) < 50:
            return False

        return True

    def _analyze_sensitive_content(self, content: str) -> Dict[str, List[str]]:
        """分析內容中的敏感資訊"""
        sensitive_info = {}

        for info_type, patterns in self.sensitive_patterns.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, content, re.IGNORECASE)
                matches.extend(found)

            if matches:
                sensitive_info[info_type] = self._filter_false_positives(matches, info_type)

        return sensitive_info

    def _determine_file_severity(self, filename: str, sensitive_info: Dict[str, List[str]]) -> str:
        """根據檔案類型和內容決定嚴重程度"""
        # 高風險檔案
        high_risk_files = ['.env', 'config.php', 'database.php', 'wp-config.php', '.htpasswd']
        if any(risk_file in filename for risk_file in high_risk_files):
            return "high"

        # 包含敏感資訊
        if any(info for info in sensitive_info.values()):
            high_risk_info = ['credit_card', 'social_security', 'api_key', 'database']
            if any(info_type in sensitive_info for info_type in high_risk_info):
                return "critical"
            return "high"

        # 備份和暫存檔案
        if any(ext in filename for ext in ['.bak', '.backup', '.tmp', 'temp']):
            return "medium"

        return "low"

    def _is_directory_listing(self, content: str) -> bool:
        """檢查是否為目錄清單"""
        listing_indicators = [
            'Index of /',
            'Directory listing for',
            'Parent Directory',
            '<pre><a href="../">../</a>',
            'folder.gif',
            'dir_icon',
        ]

        content_lower = content.lower()
        return any(indicator.lower() in content_lower for indicator in listing_indicators)

    def _detect_error_disclosure(self, content: str) -> Optional[Dict[str, str]]:
        """檢測錯誤訊息洩露"""
        error_patterns = {
            'database_error': [
                r'mysql_connect\(\)',
                r'ORA-\d+',
                r'Microsoft.*ODBC.*SQL Server',
                r'PostgreSQL.*ERROR',
                r'Warning.*mysql_.*',
            ],
            'path_disclosure': [
                r'[A-Za-z]:\\\\[^<>\s]+',
                r'/home/[^<>\s]+',
                r'/var/www/[^<>\s]+',
                r'/usr/local/[^<>\s]+',
            ],
            'stack_trace': [
                r'at\s+[\w.]+\([^)]+\)',
                r'Traceback \(most recent call last\)',
                r'Fatal error:.*in /[^<>\s]+',
                r'Warning:.*in /[^<>\s]+',
            ]
        }

        for error_type, patterns in error_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    return {
                        'type': error_type,
                        'evidence': match.group(0)[:100]
                    }

        return None

    def _is_version_disclosure(self, header_value: str) -> bool:
        """檢查是否為版本洩露"""
        # 檢查是否包含版本號
        version_patterns = [
            r'\d+\.\d+',
            r'v\d+',
            r'version\s*\d+',
        ]

        for pattern in version_patterns:
            if re.search(pattern, header_value, re.IGNORECASE):
                return True

        return False

    def _filter_false_positives(self, matches: List[str], info_type: str) -> List[str]:
        """過濾假陽性"""
        valid_matches = []

        for match in matches:
            if info_type == 'email':
                # 過濾明顯的假 email
                if not any(domain in match.lower() for domain in ['example.com', 'test.com', 'domain.com']):
                    valid_matches.append(match)

            elif info_type == 'credit_card':
                # 簡單的信用卡號碼驗證
                digits_only = ''.join(filter(str.isdigit, match))
                if len(digits_only) >= 13:
                    valid_matches.append(match)

            elif info_type == 'internal_ip':
                # 確保是有效的內部 IP
                if not match.endswith(('.0', '.255')):  # 排除網路和廣播地址
                    valid_matches.append(match)

            else:
                valid_matches.append(match)

        return valid_matches[:5]  # 限制數量

    def _get_info_severity(self, info_type: str) -> str:
        """根據資訊類型獲取嚴重程度"""
        severity_map = {
            'credit_card': 'critical',
            'social_security': 'critical',
            'api_key': 'high',
            'database': 'high',
            'email': 'medium',
            'phone': 'medium',
            'path': 'low',
            'internal_ip': 'low',
            'version': 'low',
        }
        return severity_map.get(info_type, 'medium')

    def _sanitize_evidence(self, evidence: str, sensitive_info: Dict[str, List[str]]) -> str:
        """清理證據中的敏感資訊"""
        sanitized = evidence

        # 遮蔽信用卡號碼
        if 'credit_card' in sensitive_info:
            sanitized = re.sub(r'\d{4}-\d{4}-\d{4}-\d{4}', 'XXXX-XXXX-XXXX-XXXX', sanitized)

        # 遮蔽 API 金鑰
        if 'api_key' in sensitive_info:
            sanitized = re.sub(r'[A-Za-z0-9]{20,}', '[REDACTED]', sanitized)

        return sanitized

    def _create_vulnerability_result(self, **kwargs):
        """創建漏洞結果對象"""
        from core.scanner_engine import VulnerabilityResult
        import uuid

        return VulnerabilityResult(
            id=str(uuid.uuid4()),
            title=kwargs.get('title', 'Information Disclosure'),
            description=kwargs.get('description', ''),
            severity=kwargs.get('severity', 'medium'),
            cwe_id=kwargs.get('cwe_id', 'CWE-200'),
            owasp_category=kwargs.get('owasp_category', 'A01:2021 – Broken Access Control'),
            affected_url=kwargs.get('affected_url', ''),
            request_method=kwargs.get('request_method', 'GET'),
            request_payload=kwargs.get('request_payload', ''),
            response_evidence=kwargs.get('response_evidence', ''),
            remediation=kwargs.get('remediation') or self._get_remediation_advice(),
            risk_score=kwargs.get('cvss_score') or self._calculate_risk_score(kwargs.get('severity', 'medium')),
            confidence="likely",
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
        )

    def _calculate_risk_score(self, severity: str) -> float:
        """計算風險評分"""
        risk_scores = {
            'critical': 9.0,
            'high': 7.0,
            'medium': 5.0,
            'low': 3.0
        }
        return risk_scores.get(severity, 5.0)

    def _get_remediation_advice(self) -> str:
        """獲取修復建議"""
        return """
修復建議:
1. 移除或保護敏感檔案和目錄
2. 配置 Web 伺服器隱藏版本資訊
3. 實施適當的錯誤處理，避免洩露系統資訊
4. 定期檢查和清理暫存檔案和備份檔案
5. 使用 .htaccess 或伺服器配置限制檔案存取
6. 實施內容過濾，移除敏感資訊
7. 配置安全的 HTTP headers
8. 定期進行安全審查和滲透測試
"""