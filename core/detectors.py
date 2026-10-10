"""core/detectors.py — 恶意脚本与恶意流量检测引擎。

加载 rules/ 下的 YAML 规则，对请求和响应做规则匹配 + 启发式检测。
负责两类：
  1. 恶意脚本（响应体）：签名 + 启发式（高熵混淆 / 超长编码串）
  2. 恶意流量（请求侧）：扫描器 UA / 敏感路径探测 / SQLi / XXE / 命令注入 / C2 beacon
"""
from __future__ import annotations

import logging
import math
import os
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

log = logging.getLogger("proxy_guard.detectors")


@dataclass
class Hit:
    rule_id: str
    rule_name: str
    severity: str
    desc: str
    snippet: str = ""


@dataclass
class Rule:
    id: str
    name: str
    severity: str
    scope: str               # response_body / request_header / request_path / request_body
    field: str = ""          # 仅 request_header 用
    type: str = "substring"  # regex / substring / contains_any
    pattern: str = ""
    compiled: Any = None
    desc: str = ""


def _compile(rule_raw: dict, default_scope: str) -> Rule:
    rtype = rule_raw.get("type", "substring")
    pat = rule_raw.get("pattern", "")
    compiled = None
    if rtype == "regex":
        try:
            compiled = re.compile(pat)
        except re.error as exc:
            log.warning("规则 %s 正则编译失败: %s", rule_raw.get("id"), exc)
    return Rule(
        id=rule_raw.get("id", ""),
        name=rule_raw.get("name", ""),
        severity=rule_raw.get("severity", "low"),
        scope=rule_raw.get("scope", default_scope),
        field=rule_raw.get("field", ""),
        type=rtype,
        pattern=pat,
        compiled=compiled,
        desc=rule_raw.get("desc", ""),
    )


def load_rules(rules_dir: str) -> tuple[list[Rule], list[Rule]]:
    """返回 (script_rules, traffic_rules)。"""
    script_rules: list[Rule] = []
    traffic_rules: list[Rule] = []
    if not os.path.isdir(rules_dir):
        log.warning("规则目录不存在: %s", rules_dir)
        return script_rules, traffic_rules
    sig_path = os.path.join(rules_dir, "malicious_signatures.yaml")
    traf_path = os.path.join(rules_dir, "traffic_rules.yaml")
    if os.path.isfile(sig_path):
        with open(sig_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        for raw in data.get("rules", []):
            script_rules.append(_compile(raw, "response_body"))
        log.info("加载脚本签名规则 %d 条", len(script_rules))
    if os.path.isfile(traf_path):
        with open(traf_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        for raw in data.get("rules", []):
            traffic_rules.append(_compile(raw, "request_path"))
        log.info("加载流量检测规则 %d 条", len(traffic_rules))
    return script_rules, traffic_rules


# ---------- 启发式 ----------

def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(data)
    ent = 0.0
    for cnt in freq.values():
        p = cnt / n
        ent -= p * math.log2(p)
    return ent


def _heuristic_response(body: str) -> list[Hit]:
    """对响应体做启发式检测（不依赖固定签名）。"""
    hits: list[Hit] = []
    # 超长 base64 串（>2000字符高熵），常见于混淆载荷
    for m in re.finditer(r"[A-Za-z0-9+/=]{2000,}", body):
        seg = m.group(0)
        if _shannon_entropy(seg) > 4.5:
            hits.append(Hit(
                rule_id="heuristic_long_b64",
                rule_name="超长高熵 Base64 块",
                severity="medium",
                desc="响应中出现超长高熵字符串，疑似混淆载荷",
                snippet=seg[:60] + "...",
            ))
            break
    # 超长 hex 串
    for m in re.finditer(r"[0-9a-fA-F]{400,}", body):
        seg = m.group(0)
        if _shannon_entropy(seg) > 3.5:
            hits.append(Hit(
                rule_id="heuristic_long_hex",
                rule_name="超长 Hex 块",
                severity="medium",
                desc="响应中出现超长十六进制串，疑似 shellcode/编码载荷",
                snippet=seg[:60] + "...",
            ))
            break
    # 大量 String.fromCharCode 拼接（计数 > 8）
    if len(re.findall(r"String\.fromCharCode", body)) > 8:
        hits.append(Hit(
            rule_id="heuristic_charcode_spam",
            rule_name="String.fromCharCode 密集拼接",
            severity="medium",
            desc="响应中密集出现 String.fromCharCode，疑似混淆",
        ))
    return hits


def _match(rule: Rule, text: str) -> Hit | None:
    if not text:
        return None
    if rule.type == "regex" and rule.compiled:
        m = rule.compiled.search(text)
        if m:
            return Hit(rule.id, rule.name, rule.severity, rule.desc, snippet=m.group(0)[:120])
    elif rule.type == "substring":
        if rule.pattern in text:
            return Hit(rule.id, rule.name, rule.severity, rule.desc, snippet=rule.pattern[:120])
    elif rule.type == "contains_any":
        for p in rule.pattern.split("|"):
            if p and p in text:
                return Hit(rule.id, rule.name, rule.severity, rule.desc, snippet=p[:120])
    return None


# ---------- 公共 API ----------

def scan_response(body: str, script_rules: list[Rule]) -> list[Hit]:
    hits: list[Hit] = []
    for rule in script_rules:
        h = _match(rule, body)
        if h:
            hits.append(h)
    hits.extend(_heuristic_response(body))
    return hits


def scan_request(
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes | str,
    traffic_rules: list[Rule],
) -> list[Hit]:
    hits: list[Hit] = []
    body_text = body.decode("utf-8", "ignore") if isinstance(body, (bytes, bytearray)) else (body or "")
    for rule in traffic_rules:
        if rule.scope == "request_header":
            hdr_val = headers.get(rule.field, "") or headers.get(rule.field.lower(), "")
            h = _match(rule, hdr_val)
        elif rule.scope == "request_path":
            h = _match(rule, path)
        elif rule.scope == "request_body":
            h = _match(rule, body_text)
        else:
            h = None
        if h:
            hits.append(h)
    return hits


def severity_rank(s: str) -> int:
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(s, 0)