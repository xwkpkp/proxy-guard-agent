"""core/mitm.py — MITM CA 与动态证书签发。

启动时生成自签根 CA（若 cert_store/ 下不存在）。
运行时为每个 HTTPS 域名动态签发叶子证书，带内存缓存。
客户端需将 proxy-guard-ca.crt 导入信任区才能正常访问 HTTPS。
"""
from __future__ import annotations

import datetime
import ipaddress
import logging
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

log = logging.getLogger("proxy_guard.mitm")

_ONE_DAY = datetime.timedelta(days=1)
_CA_VALIDITY = datetime.timedelta(days=3650)   # 根 CA 10年
_LEAF_VALIDITY = datetime.timedelta(days=365)  # 叶子证书1年


class CertStore:
    """管理 CA 证书 + 动态签发叶子证书。"""

    def __init__(self, store_dir: str) -> None:
        self.store_dir = Path(store_dir)
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self.ca_cert_path = self.store_dir / "proxy-guard-ca.crt"
        self.ca_key_path = self.store_dir / "proxy-guard-ca.key"
        self._leaf_cache: dict[str, tuple[bytes, bytes]] = {}  # host -> (cert_pem, key_pem)
        self._ca_cert: x509.Certificate | None = None
        self._ca_key = None
        self._load_or_create_ca()

    # ---- CA ----

    def _load_or_create_ca(self) -> None:
        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            self._ca_cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
            self._ca_key = serialization.load_pem_private_key(self.ca_key_path.read_bytes(), password=None)
            log.info("已加载根 CA: %s", self.ca_cert_path)
            return
        log.info("生成自签根 CA ...")
        self._ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Proxy Guard"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Proxy Guard Root CA"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _ONE_DAY)
            .not_valid_after(now + _CA_VALIDITY)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_encipherment=False, content_commitment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=True,
                    crl_sign=True, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(self._ca_key, hashes.SHA256())
        )
        self.ca_cert_path.write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        self.ca_key_path.write_bytes(
            self._ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        self._ca_cert = cert
        # 设置可读权限提示
        try:
            os.system(f'attrib +R "{self.ca_cert_path}"')
        except Exception:  # noqa: BLE001
            pass
        log.warning("⚠ 根 CA 已生成: %s", self.ca_cert_path)
        log.warning("  请把 proxy-guard-ca.crt 导入系统/浏览器信任区，否则 HTTPS 会报证书错误")

    # ---- 叶子证书 ----

    def get_leaf(self, host: str) -> tuple[bytes, bytes]:
        """返回 (cert_pem, key_pem)。命中缓存则直接返回。"""
        h = host.lower().strip(".")
        if h in self._leaf_cache:
            return self._leaf_cache[h]
        cert_pem, key_pem = self._sign_leaf(h)
        self._leaf_cache[h] = (cert_pem, key_pem)
        return cert_pem, key_pem

    def _sign_leaf(self, host: str) -> tuple[bytes, bytes]:
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        try:
            ip = ipaddress.ip_address(host)
            san = x509.IPAddress(ip)
        except ValueError:
            san = x509.DNSName(host)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Proxy Guard"),
            x509.NameAttribute(NameOID.COMMON_NAME, host),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)  # type: ignore[union-attr]
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _ONE_DAY)
            .not_valid_after(now + _LEAF_VALIDITY)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName([san]), critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())  # type: ignore[arg-type]
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        return cert_pem, key_pem

    @property
    def ca_cert_pem_path(self) -> Path:
        return self.ca_cert_path