"""core/shield.py — 防护层。

本地 HTTP 代理：按域名路由分流后转发，经检测引擎过滤。
  - 域名路由：国内直连，海外走代理池出口
  - 明文 HTTP：完整检测请求侧 + 响应体
  - HTTPS：MITM TLS 终止解密后做完整检测，再转发上游
  - SQLi：正则 + 语义 token 分析双重检测
命中即阻断 + 告警 + 强制出口切换。
"""
from __future__ import annotations

import asyncio
import logging
import ssl
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import aiohttp
from aiohttp import web

from . import detectors, sqli_detect, safeguards
from .mitm import CertStore
from .router import DIRECT, PROXY, DomainRouter
from .rotator import Rotator
from .safeguards import CircuitBreaker, RateLimiter, DEFAULT_CSP

log = logging.getLogger("proxy_guard.shield")


@dataclass
class ShieldStats:
    requests_total: int = 0
    blocked_total: int = 0
    rotated_on_detect: int = 0
    direct_count: int = 0
    proxy_count: int = 0
    tls_intercepted: int = 0
    redline_blocked: int = 0
    ssrf_blocked: int = 0
    injection_detected: int = 0
    by_rule: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)


class Shield:
    def __init__(
        self,
        rotator: Rotator,
        router: DomainRouter,
        judgment_queue=None,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8888,
        scan_request: bool = True,
        scan_response: bool = True,
        block_on_detect: bool = True,
        max_body_scan: int = 2 * 1024 * 1024,
        switch_on_detect: bool = True,
        rules_dir: str = "rules",
        mitm_enabled: bool = True,
        cert_store_dir: str = "cert_store",
    ) -> None:
        self.rotator = rotator
        self.router = router
        self.judgment_queue = judgment_queue
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.scan_request = scan_request
        self.scan_response = scan_response
        self.block_on_detect = block_on_detect
        self.max_body_scan = max_body_scan
        self.switch_on_detect = switch_on_detect
        self.mitm_enabled = mitm_enabled

        self.script_rules, self.traffic_rules = detectors.load_rules(rules_dir)
        self.cert_store: CertStore | None = None
        if mitm_enabled:
            self.cert_store = CertStore(cert_store_dir)
        self.stats = ShieldStats()
        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None
        self._site: web.BaseSite | None = None
        self._mitm_app: web.Application | None = None
        self.breaker = CircuitBreaker(threshold=5, cooldown=60.0)
        self.rate_limiter = RateLimiter(max_concurrent=20)

    # ---- 命中处置 ----

    def _record_hits(self, hits: list[detectors.Hit]) -> None:
        for h in hits:
            self.stats.by_rule[h.rule_id] = self.stats.by_rule.get(h.rule_id, 0) + 1
            self.stats.by_severity[h.severity] = self.stats.by_severity.get(h.severity, 0) + 1

    async def _enforce(self, hits: list[detectors.Hit], ctx: str,
                       sample: str = "", target: str = "") -> bool:
        if not hits:
            return False
        self._record_hits(hits)
        max_sev = max(hits.severity for h in hits) if hits else "low"
        rule_hits = ", ".join(f"{h.rule_id}({h.severity})" for h in hits)
        for h in sorted(hits, key=lambda x: detectors.severity_rank(x.severity), reverse=True):
            log.warning(
                "⚠ 检测命中 [%s] severity=%s | %s | %s | %s",
                ctx, h.severity, h.rule_id, h.rule_name, h.desc,
            )
        # ---- 异步入 LLM 研判队列 ----
        if self.judgment_queue is not None and sample:
            await self.judgment_queue.put(sample, rule_hits, ctx, target or ctx)
        if self.switch_on_detect:
            await self.rotator.force_rotate("shield-detect")
            self.stats.rotated_on_detect += 1
        if self.block_on_detect:
            self.stats.blocked_total += 1
            log.warning("⛔ 已阻断 (%s, 最高严重度=%s)", ctx, max_sev)
            return True
        return False

    def _scan_request_full(self, method: str, path: str, headers: dict[str, str], body: bytes) -> list[detectors.Hit]:
        """完整请求检测：规则匹配 + SQLi 语义分析。"""
        hits = detectors.scan_request(method, path, headers, body, self.traffic_rules)
        # SQLi 语义加强：对 path 和 body 都做
        sqli_hits = sqli_detect.detect_sqli_semantic(path)
        body_text = body.decode("utf-8", "ignore") if isinstance(body, (bytes, bytearray)) else (body or "")
        sqli_hits.extend(sqli_detect.detect_sqli_semantic(body_text))
        # 去重（同 rule_id 只算一次）
        seen = {h.rule_id for h in hits}
        for h in sqli_hits:
            if h.rule_id not in seen:
                hits.append(h)
                seen.add(h.rule_id)
        return hits

    # ---- 请求转发 ----

    async def _forward(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[int, dict[str, str], bytes]:
        """按域名路由转发请求：DIRECT 直连，PROXY 走当前出口代理。"""
        host = urlparse(url).hostname or ""
        route = self.router.decide(host)
        if route == DIRECT:
            self.stats.direct_count += 1
            exit_url = None
        else:
            self.stats.proxy_count += 1
            exit_url = await self.rotator.current_proxy_url()
        timeout = aiohttp.ClientTimeout(total=30)
        fwd_headers = {k: v for k, v in headers.items() if k.lower() not in (
            "host", "proxy-connection", "proxy-authorization", "te", "trailers",
        )}
        connector_kwargs: dict[str, Any] = {}
        if exit_url:
            connector_kwargs["proxy"] = exit_url
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.request(
                    method, url, headers=fwd_headers, data=body or None,
                    allow_redirects=False, **connector_kwargs,
                ) as resp:
                    data = await resp.read()
                    resp_headers = {k: v for k, v in resp.headers.items()
                                    if k.lower() not in ("transfer-encoding", "content-encoding", "content-length")}
                    if exit_url:
                        await self.rotator.report_success()
                        self.breaker.record_success()
                    return resp.status, resp_headers, data
        except Exception as exc:  # noqa: BLE001
            tag = "直连" if exit_url is None else f"代理({exit_url})"
            log.warning("转发失败(url=%s %s): %s", url, tag, exc)
            if exit_url:
                await self.rotator.report_failure()
            self.breaker.record_failure()
            return 502, {"Content-Type": "text/plain"}, f"proxy-guard: upstream failed ({exc})".encode()

    # ---- 明文 HTTP 代理 handler ----

    async def handle_http(self, request: web.Request) -> web.StreamResponse:
        self.stats.requests_total += 1
        method = request.method
        target = str(request.url)
        host = request.url.hostname or ""
        req_headers = {k: v for k, v in request.headers.items()}
        body = await request.read()

        # ---- 防护 3: SSRF 拦截 ----
        if safeguards.is_ssrf_target(host):
            self.stats.ssrf_blocked += 1
            log.warning("⛔ SSRF 拦截: %s (内网/元数据目标)", host)
            return web.Response(status=403, text="proxy-guard: SSRF target blocked")

        # ---- 防护 1: 数据红线 ----
        redline = safeguards.check_data_redline(method, target, req_headers, body)
        if redline.blocked:
            self.stats.redline_blocked += 1
            log.warning("⛔ 数据红线拦截: %s | %s", host, ", ".join(redline.reasons))
            return web.Response(status=403, text="proxy-guard: sensitive data redline blocked")

        # ---- 防护 5: 熔断检查 ----
        if self.breaker.is_open:
            log.warning("⛔ 熔断中，拒绝转发: %s", host)
            return web.Response(status=503, text="proxy-guard: circuit breaker open")

        if self.scan_request:
            path = request.url.path or "/"
            hits = self._scan_request_full(
                method, path + ("?" + request.url.query if request.url.query else ""),
                req_headers, body,
            )
            req_sample = (path + ("?" + request.url.query if request.url.query else "") + " | " + body.decode("utf-8","ignore")[:2048])[:4096]
            if await self._enforce(hits, f"request {method} {target}", sample=req_sample, target=target):
                return web.Response(status=403, text="proxy-guard: request blocked (malicious traffic)")

        status, resp_headers, resp_body = await self._forward(method, target, req_headers, body)

        # ---- 防护 6: 响应注入检测 ----
        if resp_body:
            inj = safeguards.detect_response_injection(status, resp_headers, resp_body)
            if inj:
                self.stats.injection_detected += 1
                log.warning("⚠ 响应被篡改注入: %s | %s", target, ", ".join(inj))
                if self.switch_on_detect:
                    await self.rotator.force_rotate("injection-detected")
                if self.block_on_detect:
                    self.stats.blocked_total += 1
                    return web.Response(status=502, text="proxy-guard: response tampering detected")

        # ---- 防护 8: CSP 注入（HTML 响应）----
        if safeguards.should_inject_csp(status, resp_headers):
            resp_headers["Content-Security-Policy"] = DEFAULT_CSP

        if self.scan_response and resp_body:
            ctype = resp_headers.get("Content-Type", "")
            if _is_scannable(ctype):
                scan_body = resp_body[: self.max_body_scan].decode("utf-8", "ignore")
                hits = detectors.scan_response(scan_body, self.script_rules)
                if await self._enforce(hits, f"response {target}", sample=scan_body[:4096], target=target):
                    return web.Response(status=403, text="proxy-guard: response blocked (malicious script)")

        out = web.Response(status=status, body=resp_body)
        for k, v in resp_headers.items():
            out.headers[k] = v
        return out

    # ---- HTTPS CONNECT：MITM 解密 或 隧道透传 ----

    async def handle_connect(self, request: web.Request) -> web.StreamResponse:
        """HTTPS 连接。MITM 开启时做 TLS 终止解密检测；否则透传隧道。"""
        self.stats.requests_total += 1
        host_port = request.host
        host = host_port.split(":")[0]
        port = int(host_port.split(":")[1]) if ":" in host_port else 443

        # ---- 防护 3: SSRF 拦截 ----
        if safeguards.is_ssrf_target(host):
            self.stats.ssrf_blocked += 1
            log.warning("⛔ CONNECT SSRF 拦截: %s (内网/元数据目标)", host)
            return web.Response(status=403, text="proxy-guard: SSRF target blocked")

        # ---- 防护 5: 熔断检查 ----
        if self.breaker.is_open:
            return web.Response(status=503, text="proxy-guard: circuit breaker open")

        if self.scan_request:
            hits = detectors.scan_request("CONNECT", "/" + host, {}, b"", self.traffic_rules)
            if await self._enforce(hits, f"CONNECT {host_port}", sample=host, target=host):
                return web.Response(status=403, text="proxy-guard: CONNECT blocked")

        if self.mitm_enabled and self.cert_store is not None:
            return await self._handle_connect_mitm(request, host, port)
        return await self._handle_connect_tunnel(request, host, port)

    async def _handle_connect_mitm(
        self, request: web.Request, host: str, port: int,
    ) -> web.StreamResponse:
        """MITM：对客户端用动态签发证书做 TLS 终止，解密后过检测再转发上游。"""
        self.stats.tls_intercepted += 1
        # 回 200 给客户端
        resp = web.Response(status=200)
        await resp.prepare(request)

        transport = request.transport
        if transport is None:
            return resp

        # 给客户端套 TLS（用我们签的叶子证书）
        cert_pem, key_pem = self.cert_store.get_leaf(host)  # type: ignore[union-attr]
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # 写临时文件给 ssl load
        import tempfile, os
        cert_file = os.path.join(self.cert_store.store_dir, f".tmp_{host}.crt")  # type: ignore[union-attr]
        key_file = os.path.join(self.cert_store.store_dir, f".tmp_{host}.key")  # type: ignore[union-attr]
        with open(cert_file, "wb") as f:
            f.write(cert_pem)
        with open(key_file, "wb") as f:
            f.write(key_pem)
        ssl_ctx.load_cert_chain(cert_file, key_file)

        loop = asyncio.get_event_loop()
        # 用 transport 建一个对客户端的 TLS server
        client_transport = transport
        try:
            tls_reader = asyncio.StreamReader()
            tls_protocol = asyncio.StreamReaderProtocol(tls_reader)
            transport.set_write_buffer_limits(0)
            new_transport = await loop.start_tls(
                transport, tls_protocol, ssl_ctx, server_side=True,
            )
            tls_writer = asyncio.StreamWriter(new_transport, tls_protocol, tls_reader, loop)
        except Exception as exc:  # noqa: BLE001
            log.warning("MITM TLS 握手失败 %s: %s", host, exc)
            try:
                transport.close()
            except Exception:  # noqa: BLE001
                pass
            return resp

        # 把后续 HTTPS 流量交给一个内部 aiohttp app 解析
        log.debug("MITM 已解密 %s:%d", host, port)
        await self._serve_decrypted(tls_reader, tls_writer, host, port)

        # 清理临时证书文件
        for f in (cert_file, key_file):
            try:
                os.remove(f)
            except Exception:  # noqa: BLE001
                pass
        return resp

    async def _serve_decrypted(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> None:
        """从已解密的 TLS 流读取 HTTP 请求，检测后转发，把响应写回客户端。"""
        try:
            while True:
                req_bytes = await _read_http_request(reader)
                if not req_bytes:
                    break
                method, path, req_headers, body = _parse_http(req_bytes, reader)
                # 请求检测
                if self.scan_request:
                    hits = self._scan_request_full(method, path, req_headers, body)
                    if hits:
                        await self._enforce_async(hits, f"MITM-req {method} https://{host}{path}")
                        if self.block_on_detect:
                            writer.write(
                                b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n"
                                b"Content-Length: 47\r\n\r\n"
                                b"proxy-guard: MITM blocked (malicious traffic)"
                            )
                            await writer.drain()
                            continue
                # 转发
                scheme_url = f"https://{host}" + path
                status, resp_headers, resp_body = await self._forward(method, scheme_url, req_headers, body)
                # 响应检测
                if self.scan_response and resp_body:
                    ctype = resp_headers.get("Content-Type", "")
                    if _is_scannable(ctype):
                        scan_body = resp_body[: self.max_body_scan].decode("utf-8", "ignore")
                        hits = detectors.scan_response(scan_body, self.script_rules)
                        if hits:
                            await self._enforce_async(hits, f"MITM-resp https://{host}{path}")
                            if self.block_on_detect:
                                writer.write(
                                    b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n"
                                    b"Content-Length: 46\r\n\r\n"
                                    b"proxy-guard: MITM blocked (malicious script)"
                                )
                                await writer.drain()
                                continue
                # 写响应回客户端
                resp_raw = _serialize_response(status, resp_headers, resp_body)
                writer.write(resp_raw)
                await writer.drain()
        except Exception as exc:  # noqa: BLE001
            log.debug("MITM 解密流结束 %s:%d: %s", host, port, exc)
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def _enforce_async(self, hits: list[detectors.Hit], ctx: str) -> bool:
        """异步版 enforce，供 MITM 路径用。"""
        if not hits:
            return False
        self._record_hits(hits)
        for h in sorted(hits, key=lambda x: detectors.severity_rank(x.severity), reverse=True):
            log.warning(
                "⚠ MITM 检测命中 [%s] severity=%s | %s | %s",
                h.severity, h.rule_id, h.rule_name, h.desc,
            )
        if self.switch_on_detect:
            await self.rotator.force_rotate("mitm-detect")
            self.stats.rotated_on_detect += 1
        if self.block_on_detect:
            self.stats.blocked_total += 1
            log.warning("⛔ MITM 已阻断 (%s)", ctx)
            return True
        return False

    # ---- 透传隧道（MITM 关闭时）----

    async def _handle_connect_tunnel(
        self, request: web.Request, host: str, port: int,
    ) -> web.StreamResponse:
        """不解密的透传隧道。按域名路由直连或经代理。"""
        route = self.router.decide(host)
        exit_url = None
        try:
            if route == DIRECT:
                self.stats.direct_count += 1
                reader, writer = await asyncio.open_connection(host, port)
                log.debug("CONNECT 透传直连 %s:%d", host, port)
            else:
                self.stats.proxy_count += 1
                exit_url = await self.rotator.current_proxy_url()
                reader, writer = await self._open_tunnel_via_proxy(host, port, exit_url)
                log.debug("CONNECT 透传经代理 %s -> %s:%d", exit_url, host, port)
        except Exception as exc:  # noqa: BLE001
            tag = "直连" if route == DIRECT else f"代理({exit_url})"
            log.warning("CONNECT 建隧道失败 %s %s: %s", tag, host, exc)
            return web.Response(status=502, text=f"proxy-guard: connect failed ({exc})")

        peer = request.transport
        if peer is None:
            writer.close()
            return web.Response(status=502, text="proxy-guard: no transport")
        resp = web.Response(status=200)
        resp.force_close = False
        await resp.prepare(request)

        async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except Exception:  # noqa: BLE001
                pass
            finally:
                try:
                    dst.close()
                except Exception:  # noqa: BLE001
                    pass

        client_reader = request.content
        asyncio.create_task(_pipe(client_reader, writer))
        asyncio.create_task(_pipe(reader, peer))
        return resp

    async def _open_tunnel_via_proxy(
        self, host: str, port: int, proxy_url: str,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        p = urlparse(proxy_url)
        proxy_host = p.hostname or ""
        proxy_port = p.port or (443 if p.scheme == "https" else 80)
        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
        req_line = (
            f"CONNECT {host}:{port} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Proxy-Connection: keep-alive\r\n\r\n"
        )
        writer.write(req_line.encode())
        await writer.drain()
        status_line = await reader.readline()
        if not status_line:
            raise ConnectionError("代理未响应 CONNECT")
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
        if b" 200" not in status_line:
            raise ConnectionError(f"代理拒绝 CONNECT: {status_line.decode(errors='ignore').strip()}")
        return reader, writer

    # ---- 启动 ----

    def _build_app(self) -> web.Application:
        app = web.Application()
        async def _any(request: web.Request) -> web.StreamResponse:
            if request.method == "CONNECT":
                return await self.handle_connect(request)
            return await self.handle_http(request)
        app.router.add_route("*", "/{tail:.*}", _any)
        async def _root(request: web.Request) -> web.StreamResponse:
            return await self.handle_http(request)
        app.router.add_route("*", "/", _root)
        return app

    async def start(self) -> None:
        self._app = self._build_app()
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self.listen_host, self.listen_port)
        await self._site.start()
        log.info("🛡 防护层已启动: %s:%d (把浏览器/程序 HTTP 代理指到这里)", self.listen_host, self.port)
        if self.mitm_enabled:
            log.info("   MITM: HTTPS 已解密检测 (需信任根 CA: %s)", self.cert_store.ca_cert_path if self.cert_store else "?")
        else:
            log.info("   MITM: 关闭，HTTPS 透传")

    async def stop(self) -> None:
        if self._site:
            await self._site.stop()
        if self._runner:
            await self._runner.cleanup()


def _is_scannable(content_type: str) -> bool:
    ct = content_type.lower()
    return any(t in ct for t in (
        "text/html", "text/plain", "text/javascript", "application/javascript",
        "application/x-javascript", "application/json", "application/xml",
        "text/xml", "text/css",
    ))


# ---- MITM HTTP 解析辅助 ----

async def _read_http_request(reader: asyncio.StreamReader) -> bytes:
    """从 TLS 流读一个完整 HTTP 请求（含 body）。"""
    header_data = await reader.readuntil(b"\r\n\r\n")
    # 解析 Content-Length
    head_text = header_data.decode("iso-8859-1")
    lines = head_text.split("\r\n")
    cl = 0
    for line in lines[1:]:
        if line.lower().startswith("content-length:"):
            try:
                cl = int(line.split(":", 1)[1].strip())
            except ValueError:
                cl = 0
            break
    body = b""
    if cl > 0:
        body = await reader.readexactly(cl)
    return header_data + body


def _parse_http(raw: bytes, reader: asyncio.StreamReader) -> tuple[str, str, dict[str, str], bytes]:
    """解析 HTTP 请求字节，返回 (method, path, headers, body)。"""
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    parts = lines[0].split(" ", 2)
    method = parts[0] if len(parts) > 0 else "GET"
    path = parts[1] if len(parts) > 1 else "/"
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return method, path, headers, body


def _serialize_response(status: int, headers: dict[str, str], body: bytes) -> bytes:
    """把 (status, headers, body) 序列化成 HTTP 响应字节。"""
    reason = {200: "OK", 403: "Forbidden", 404: "Not Found", 500: "Internal Server Error"}.get(status, "OK")
    out = f"HTTP/1.1 {status} {reason}\r\n".encode()
    hdrs = dict(headers)
    hdrs["Content-Length"] = str(len(body))
    hdrs.setdefault("Connection", "close")
    for k, v in hdrs.items():
        out += f"{k}: {v}\r\n".encode()
    out += b"\r\n"
    out += body
    return out