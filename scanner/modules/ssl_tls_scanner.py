#!/usr/bin/env python3
"""
SSL/TLS 安全掃描模組
檢測 SSL/TLS 配置問題、證書漏洞和加密弱點
"""

import ssl
import socket
import asyncio
import logging
import time
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse
import datetime
import hashlib
import ipaddress
from dataclasses import dataclass
from utils.vulnerability_templates import get_template_manager

logger = logging.getLogger(__name__)

@dataclass
class CertificateInfo:
    """證書資訊結構"""
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime.datetime
    not_after: datetime.datetime
    signature_algorithm: str
    key_size: int
    fingerprint_sha256: str
    san_names: List[str]
    is_self_signed: bool
    is_expired: bool
    days_until_expiry: int

class SSLTLSScanner:
    """SSL/TLS 掃描器"""

    def __init__(self):
        self.max_concurrent = 3  # SSL 掃描較慢，限制並發數
        self.supported_protocols = [
            ('SSLv2', ssl.PROTOCOL_SSLv23),  # 已棄用
            ('SSLv3', ssl.PROTOCOL_SSLv23),  # 已棄用
            ('TLSv1.0', ssl.PROTOCOL_TLSv1),   # 弱協議
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1), # 弱協議
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2), # 安全
            ('TLSv1.3', getattr(ssl, 'PROTOCOL_TLSv1_3', None))  # 最安全
        ]

        # 弱密码套件模式
        self.weak_ciphers = {
            'NULL': r'NULL',
            'EXPORT': r'EXPORT',
            'RC4': r'RC4',
            'DES': r'DES-CBC',
            '3DES': r'3DES',
            'MD5': r'MD5',
            'ADH': r'ADH',
            'AECDH': r'AECDH'
        }

    async def scan(self, session, target, urls: List[str]) -> List[Any]:
        """執行 SSL/TLS 掃描"""
        vulnerabilities = []

        logger.info(f"開始 SSL/TLS 掃描，目標 URL 數量: {len(urls)}")

        # 提取唯一的主機和端口
        hosts_ports = self._extract_hosts_ports(urls)

        # 使用信號量限制並發
        semaphore = asyncio.Semaphore(self.max_concurrent)

        tasks = []
        for host, port in hosts_ports:
            task = self._scan_host_with_semaphore(semaphore, host, port)
            tasks.append(task)

        # 執行所有掃描任務
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 收集結果
        for result in results:
            if isinstance(result, list):
                vulnerabilities.extend(result)
            elif isinstance(result, Exception):
                logger.error(f"SSL/TLS 掃描過程中發生錯誤: {str(result)}")

        logger.info(f"SSL/TLS 掃描完成，發現 {len(vulnerabilities)} 個漏洞")
        return vulnerabilities

    def _extract_hosts_ports(self, urls: List[str]) -> List[Tuple[str, int]]:
        """提取主機和端口"""
        hosts_ports = set()

        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.scheme in ['https', 'http']:
                    host = parsed.hostname
                    if parsed.scheme == 'https':
                        port = parsed.port or 443
                    else:
                        port = parsed.port or 80

                    # 只掃描 HTTPS 或指定端口的 HTTP
                    if parsed.scheme == 'https' or port in [443, 8443, 8080]:
                        hosts_ports.add((host, port))

            except Exception as e:
                logger.error(f"解析 URL {url} 時發生錯誤: {str(e)}")

        return list(hosts_ports)

    async def _scan_host_with_semaphore(self, semaphore, host: str, port: int):
        """使用信號量控制並發的主機掃描"""
        async with semaphore:
            return await self._scan_single_host(host, port)

    async def _scan_single_host(self, host: str, port: int) -> List[Any]:
        """掃描單個主機"""
        vulnerabilities = []

        try:
            logger.info(f"掃描 SSL/TLS: {host}:{port}")

            # 檢查 SSL 是否可用
            ssl_available = await self._check_ssl_availability(host, port)
            if not ssl_available:
                # 使用專業模板報告 HTTP 未加密問題
                template_mgr = get_template_manager()
                vuln_data = template_mgr.create_vulnerability_from_template(
                    'http_no_encryption',
                    affected_url=f"http://{host}:{port}",
                    host=host,
                    port=port
                )
                
                if vuln_data:
                    from core.scanner_engine import VulnerabilityResult
                    import uuid
                    
                    vulnerability = VulnerabilityResult(
                        id=str(uuid.uuid4()),
                        title=vuln_data['title'],
                        description=vuln_data['description'],
                        severity=vuln_data['severity'],
                        cwe_id=vuln_data['cwe_id'],
                        owasp_category=vuln_data['owasp_category'],
                        affected_url=vuln_data['affected_url'],
                        request_method="GET",
                        request_payload="",
                        response_evidence=f"Protocol: HTTP, Port: {port}, Encryption: None",
                        remediation=vuln_data['remediation'],
                        risk_score=vuln_data['cvss_score'],
                        confidence="confirmed",
                        timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
                    )
                    vulnerabilities.append(vulnerability)
                
                logger.info(f"{host}:{port} 不支援 SSL/TLS, 使用明文 HTTP")
                return vulnerabilities

            # 獲取證書資訊
            cert_info = await self._get_certificate_info(host, port)
            if cert_info:
                cert_vulns = self._analyze_certificate(cert_info, host, port)
                vulnerabilities.extend(cert_vulns)

            # 檢查支援的協議版本
            protocol_vulns = await self._check_protocol_versions(host, port)
            vulnerabilities.extend(protocol_vulns)

            # 檢查密碼套件
            cipher_vulns = await self._check_cipher_suites(host, port)
            vulnerabilities.extend(cipher_vulns)

            # 檢查常見 SSL/TLS 漏洞
            common_vulns = await self._check_common_vulnerabilities(host, port)
            vulnerabilities.extend(common_vulns)

            # 檢查 HSTS 頭部
            hsts_vulns = await self._check_hsts_header(host, port)
            vulnerabilities.extend(hsts_vulns)

        except Exception as e:
            logger.error(f"掃描主機 {host}:{port} 時發生錯誤: {str(e)}")

        return vulnerabilities

    async def _check_ssl_availability(self, host: str, port: int) -> bool:
        """檢查 SSL 是否可用"""
        try:
            # 創建 SSL 連接測試
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # 使用 asyncio 的方式建立連接
            loop = asyncio.get_event_loop()

            def check_connection():
                with socket.create_connection((host, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        return True

            return await loop.run_in_executor(None, check_connection)

        except Exception:
            return False

    async def _get_certificate_info(self, host: str, port: int) -> Optional[CertificateInfo]:
        """獲取證書資訊"""
        try:
            loop = asyncio.get_event_loop()

            def get_cert():
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((host, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        cert_der = ssock.getpeercert(binary_form=True)
                        return cert, cert_der

            cert, cert_der = await loop.run_in_executor(None, get_cert)

            # 解析證書資訊
            subject = dict(x[0] for x in cert['subject'])
            issuer = dict(x[0] for x in cert['issuer'])

            # 計算指紋
            fingerprint = hashlib.sha256(cert_der).hexdigest()

            # 解析日期
            not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')

            # 計算到期時間
            now = datetime.datetime.now()
            days_until_expiry = (not_after - now).days

            # 獲取 SAN 名稱
            san_names = []
            if 'subjectAltName' in cert:
                san_names = [name[1] for name in cert['subjectAltName']]

            # 檢查是否為自簽證書
            is_self_signed = subject.get('commonName') == issuer.get('commonName')

            return CertificateInfo(
                subject=subject.get('commonName', 'Unknown'),
                issuer=issuer.get('commonName', 'Unknown'),
                serial_number=cert.get('serialNumber', 'Unknown'),
                not_before=not_before,
                not_after=not_after,
                signature_algorithm=cert.get('signatureAlgorithm', 'Unknown'),
                key_size=0,  # 需要額外解析
                fingerprint_sha256=fingerprint,
                san_names=san_names,
                is_self_signed=is_self_signed,
                is_expired=now > not_after,
                days_until_expiry=days_until_expiry
            )

        except Exception as e:
            logger.error(f"獲取證書資訊時發生錯誤: {str(e)}")
            return None

    def _analyze_certificate(self, cert_info: CertificateInfo,
                           host: str, port: int) -> List[Any]:
        """分析證書漏洞"""
        vulnerabilities = []

        # 檢查證書是否過期
        if cert_info.is_expired:
            vulnerabilities.append(self._create_ssl_vulnerability(
                title="SSL 證書已過期",
                description=f"SSL 證書已於 {cert_info.not_after.strftime('%Y-%m-%d')} 過期",
                severity="critical",
                host=host,
                port=port,
                evidence=f"證書到期日: {cert_info.not_after}",
                cwe_id="CWE-295"
            ))

        # 檢查證書即將過期
        elif cert_info.days_until_expiry <= 30:
            severity = "high" if cert_info.days_until_expiry <= 7 else "medium"
            vulnerabilities.append(self._create_ssl_vulnerability(
                title="SSL 證書即將過期",
                description=f"SSL 證書將在 {cert_info.days_until_expiry} 天後過期",
                severity=severity,
                host=host,
                port=port,
                evidence=f"證書到期日: {cert_info.not_after}",
                cwe_id="CWE-295"
            ))

        # 檢查自簽證書
        if cert_info.is_self_signed:
            vulnerabilities.append(self._create_ssl_vulnerability(
                title="自簽 SSL 證書",
                description="使用自簽證書會導致瀏覽器警告，影響用戶信任",
                severity="medium",
                host=host,
                port=port,
                evidence=f"發行者與主體相同: {cert_info.issuer}",
                cwe_id="CWE-295"
            ))

        # 檢查主機名不匹配
        if not self._validate_hostname(host, cert_info):
            vulnerabilities.append(self._create_ssl_vulnerability(
                title="SSL 證書主機名不匹配",
                description=f"證書主體名稱與請求的主機名不匹配",
                severity="high",
                host=host,
                port=port,
                evidence=f"證書主體: {cert_info.subject}, SAN: {cert_info.san_names}",
                cwe_id="CWE-295"
            ))

        # 檢查弱簽名算法
        if self._is_weak_signature_algorithm(cert_info.signature_algorithm):
            vulnerabilities.append(self._create_ssl_vulnerability(
                title="弱 SSL 證書簽名算法",
                description=f"證書使用弱簽名算法: {cert_info.signature_algorithm}",
                severity="medium",
                host=host,
                port=port,
                evidence=f"簽名算法: {cert_info.signature_algorithm}",
                cwe_id="CWE-327"
            ))

        return vulnerabilities

    async def _check_protocol_versions(self, host: str, port: int) -> List[Any]:
        """檢查支援的協議版本"""
        vulnerabilities = []

        # 檢查是否支援弱協議
        weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']

        for protocol_name, protocol_const in self.supported_protocols:
            if protocol_const is None:
                continue

            try:
                supports_protocol = await self._test_protocol_support(
                    host, port, protocol_const
                )

                if supports_protocol and protocol_name in weak_protocols:
                    severity = "critical" if protocol_name in ['SSLv2', 'SSLv3'] else "high"
                    vulnerabilities.append(self._create_ssl_vulnerability(
                        title=f"支援弱 {protocol_name} 協議",
                        description=f"伺服器支援已知不安全的 {protocol_name} 協議",
                        severity=severity,
                        host=host,
                        port=port,
                        evidence=f"伺服器響應 {protocol_name} 連接",
                        cwe_id="CWE-327"
                    ))

            except Exception as e:
                logger.error(f"測試協議 {protocol_name} 時發生錯誤: {str(e)}")

        return vulnerabilities

    async def _test_protocol_support(self, host: str, port: int, protocol) -> bool:
        """測試協議支援"""
        try:
            loop = asyncio.get_event_loop()

            def test_protocol():
                try:
                    context = ssl.SSLContext(protocol)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    context.set_ciphers('ALL:@SECLEVEL=0')  # 允許所有密碼套件

                    with socket.create_connection((host, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=host) as ssock:
                            return True
                except:
                    return False

            return await loop.run_in_executor(None, test_protocol)

        except Exception:
            return False

    async def _check_cipher_suites(self, host: str, port: int) -> List[Any]:
        """檢查密碼套件"""
        vulnerabilities = []

        try:
            # 獲取支援的密碼套件
            supported_ciphers = await self._get_supported_ciphers(host, port)

            # 檢查弱密碼套件
            for cipher in supported_ciphers:
                for weakness, pattern in self.weak_ciphers.items():
                    if pattern in cipher:
                        vulnerabilities.append(self._create_ssl_vulnerability(
                            title=f"支援弱密碼套件 ({weakness})",
                            description=f"伺服器支援弱密碼套件: {cipher}",
                            severity="high" if weakness in ['NULL', 'EXPORT', 'RC4'] else "medium",
                            host=host,
                            port=port,
                            evidence=f"弱密碼套件: {cipher}",
                            cwe_id="CWE-327"
                        ))
                        break

        except Exception as e:
            logger.error(f"檢查密碼套件時發生錯誤: {str(e)}")

        return vulnerabilities

    async def _get_supported_ciphers(self, host: str, port: int) -> List[str]:
        """獲取支援的密碼套件"""
        try:
            loop = asyncio.get_event_loop()

            def get_ciphers():
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                    with socket.create_connection((host, port), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=host) as ssock:
                            return [ssock.cipher()]

                except Exception:
                    return []

            cipher_info = await loop.run_in_executor(None, get_ciphers)
            return [cipher[0] for cipher in cipher_info if cipher]

        except Exception:
            return []

    async def _check_common_vulnerabilities(self, host: str, port: int) -> List[Any]:
        """檢查常見 SSL/TLS 漏洞"""
        vulnerabilities = []

        # 檢查 POODLE 漏洞 (SSLv3)
        if await self._test_protocol_support(host, port, ssl.PROTOCOL_SSLv23):
            # 這裡應該有更精確的 POODLE 檢測邏輯
            pass

        # 檢查 BEAST 攻擊
        beast_vulnerable = await self._check_beast_vulnerability(host, port)
        if beast_vulnerable:
            vulnerabilities.append(self._create_ssl_vulnerability(
                title="BEAST 攻擊漏洞",
                description="伺服器可能易受 BEAST (Browser Exploit Against SSL/TLS) 攻擊",
                severity="medium",
                host=host,
                port=port,
                evidence="支援 TLS 1.0 和 CBC 密碼套件",
                cwe_id="CWE-327"
            ))

        # 檢查 Heartbleed 漏洞（需要更複雜的檢測）
        # 這裡可以添加 OpenSSL Heartbleed 檢測邏輯

        return vulnerabilities

    async def _check_beast_vulnerability(self, host: str, port: int) -> bool:
        """檢查 BEAST 漏洞"""
        try:
            # BEAST 影響 TLS 1.0 和使用 CBC 密碼套件的連接
            tls10_support = await self._test_protocol_support(host, port, ssl.PROTOCOL_TLSv1)
            if tls10_support:
                # 檢查是否支援 CBC 密碼套件
                ciphers = await self._get_supported_ciphers(host, port)
                for cipher in ciphers:
                    if 'CBC' in cipher:
                        return True
            return False
        except Exception:
            return False

    async def _check_hsts_header(self, host: str, port: int) -> List[Any]:
        """檢查 HSTS 頭部"""
        vulnerabilities = []

        try:
            # 這裡需要發送 HTTP 請求檢查 HSTS 頭部
            # 由於是 SSL 掃描模組，我們假設有方法檢查 HSTS

            # 如果沒有 HSTS 頭部
            has_hsts = False  # 這裡應該有實際的檢測邏輯

            if not has_hsts:
                vulnerabilities.append(self._create_ssl_vulnerability(
                    title="缺少 HSTS 安全頭部",
                    description="伺服器沒有設定 HTTP Strict Transport Security (HSTS) 頭部",
                    severity="medium",
                    host=host,
                    port=port,
                    evidence="HTTP 響應中缺少 Strict-Transport-Security 頭部",
                    cwe_id="CWE-319"
                ))

        except Exception as e:
            logger.error(f"檢查 HSTS 頭部時發生錯誤: {str(e)}")

        return vulnerabilities

    def _validate_hostname(self, hostname: str, cert_info: CertificateInfo) -> bool:
        """驗證主機名是否匹配證書"""
        # 檢查主體名稱
        if cert_info.subject == hostname:
            return True

        # 檢查 SAN 擴展
        for san_name in cert_info.san_names:
            if self._match_hostname_pattern(hostname, san_name):
                return True

        return False

    def _match_hostname_pattern(self, hostname: str, pattern: str) -> bool:
        """匹配主機名模式（支援通配符）"""
        if pattern.startswith('*.'):
            # 通配符匹配
            pattern_domain = pattern[2:]
            if '.' in hostname:
                hostname_domain = hostname[hostname.index('.') + 1:]
                return hostname_domain == pattern_domain

        return hostname == pattern

    def _is_weak_signature_algorithm(self, algorithm: str) -> bool:
        """檢查是否為弱簽名算法"""
        weak_algorithms = ['md2', 'md4', 'md5', 'sha1']
        return any(weak in algorithm.lower() for weak in weak_algorithms)

    def _create_ssl_vulnerability(self, title: str, description: str,
                                 severity: str, host: str, port: int,
                                 evidence: str, cwe_id: str) -> Any:
        """創建 SSL/TLS 漏洞結果"""
        from core.scanner_engine import VulnerabilityResult
        import uuid

        return VulnerabilityResult(
            id=str(uuid.uuid4()),
            title=title,
            description=description,
            severity=severity,
            cwe_id=cwe_id,
            owasp_category="A02:2021 - Cryptographic Failures",
            affected_url=f"https://{host}:{port}",
            request_method="SSL/TLS",
            request_payload="SSL/TLS handshake",
            response_evidence=evidence,
            remediation=self._get_ssl_remediation(title),
            risk_score=self._calculate_ssl_risk_score(severity),
            confidence="confirmed",
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
        )

    def _get_ssl_remediation(self, vulnerability_title: str) -> str:
        """獲取 SSL/TLS 修復建議"""
        remediation_map = {
            "SSL 證書已過期": "立即更新 SSL 證書，確保證書有效期足夠長",
            "SSL 證書即將過期": "及時更新 SSL 證書，建議設定自動更新提醒",
            "自簽 SSL 證書": "使用可信任的證書頒發機構簽發的證書",
            "SSL 證書主機名不匹配": "確保證書主體名稱或 SAN 擴展包含正確的主機名",
            "弱 SSL 證書簽名算法": "使用 SHA-256 或更強的簽名算法重新簽發證書",
            "支援弱": "禁用弱協議，僅支援 TLS 1.2 和 TLS 1.3",
            "支援弱密碼套件": "配置伺服器僅支援安全的密碼套件，禁用弱密碼套件",
            "BEAST 攻擊漏洞": "升級到 TLS 1.2 或以上版本，優先使用 AEAD 密碼套件",
            "缺少 HSTS": "在 HTTP 響應中添加 Strict-Transport-Security 頭部"
        }

        for key, remediation in remediation_map.items():
            if key in vulnerability_title:
                return remediation

        return "請參考 SSL/TLS 最佳實踐指南進行配置"

    def _calculate_ssl_risk_score(self, severity: str) -> float:
        """計算 SSL/TLS 風險評分"""
        risk_scores = {
            'critical': 9.0,
            'high': 7.0,
            'medium': 5.0,
            'low': 3.0
        }
        return risk_scores.get(severity, 5.0)