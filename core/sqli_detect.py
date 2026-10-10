"""core/sqli_detect.py — SQLi 语义检测加强。

正则能抓 `UNION SELECT`，但抓不到 `UnIoN/**/SeLeCt` 这类绕过。
这里做一个轻量 token 分析器：先规范化（去注释/小写/合并空白），
再用语义模式匹配，弥补正则的漏报。
"""
from __future__ import annotations

import re

from .detectors import Hit

# ---- 规范化 ----

_SQL_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_SQL_LINE_COMMENT = re.compile(r"--[^\n]*")
_SQL_WS = re.compile(r"\s+")


def _normalize(text: str) -> str:
    """去掉注释、合并空白、转小写。"""
    t = _SQL_COMMENT.sub(" ", text)
    t = _SQL_LINE_COMMENT.sub(" ", t)
    t = _SQL_WS.sub(" ", t)
    return t.lower().strip()


# ---- 语义模式（对规范化后的文本做子串匹配）----

_SEMANTIC_PATTERNS = [
    ("sqli_union_semantic", "UNION SELECT 语义注入", "union select", "UNION SELECT 注入（绕过大小写/注释分割后仍命中）"),
    ("sqli_union_all_semantic", "UNION ALL SELECT", "union all select", "UNION ALL SELECT 注入"),
    ("sqli_or_bool_true", "OR 1=1 布尔注入", "or 1=1", "布尔型注入 OR 1=1"),
    ("sqli_and_bool_true", "AND 1=1 布尔注入", "and 1=1", "布尔型注入 AND 1=1"),
    ("sqli_or_bool_str", "OR 'a'='a' 布尔注入", "or 'a'='a'", "布尔型注入 OR 'a'='a'"),
    ("sqli_sleep_semantic", "SLEEP() 时间盲注", "sleep(", "时间盲注 sleep()"),
    ("sqli_benchmark_semantic", "BENCHMARK() 时间盲注", "benchmark(", "时间盲注 benchmark()"),
    ("sqli_pg_sleep_semantic", "PG_SLEEP() 时间盲注", "pg_sleep(", "PostgreSQL 时间盲注"),
    ("sqli_waitfor_delay", "WAITFOR DELAY 时间盲注", "waitfor delay", "SQL Server 时间盲注"),
    ("sqli_into_outfile", "INTO OUTFILE 写文件", "into outfile", "写文件注入 INTO OUTFILE"),
    ("sqli_load_file", "LOAD_FILE() 读文件", "load_file(", "读文件注入 LOAD_FILE()"),
    ("sqli_info_schema", "INFORMATION_SCHEMA 探测", "information_schema", "信息架构探测"),
    ("sqli_concat_group", "CONCAT/GROUP_CONCAT", "group_concat(", "GROUP_CONCAT 数据提取"),
    ("sqli_hex_fn", "HEX() 函数", "hex(", "HEX 编码绕过"),
    ("sqli_unhex_fn", "UNHEX() 函数", "unhex(", "UNHEX 解码载荷"),
    ("sqli_char_fn", "CHAR() 函数", "char(", "CHAR 字符码绕过"),
    ("sqli_extractvalue", "EXTRACTVALUE 报错注入", "extractvalue(", "EXTRACTVALUE 报错注入"),
    ("sqli_updatexml", "UPDATEXML 报错注入", "updatexml(", "UPDATEXML 报错注入"),
]


def detect_sqli_semantic(text: str, scope: str = "request_body") -> list[Hit]:
    """对文本做 SQLi 语义检测。返回命中列表。"""
    if not text:
        return []
    norm = _normalize(text)
    hits: list[Hit] = []
    for rule_id, name, pat, desc in _SEMANTIC_PATTERNS:
        if pat in norm:
            hits.append(Hit(
                rule_id=rule_id,
                rule_name=name,
                severity="high",
                desc=desc,
                snippet=pat,
            ))
    return hits