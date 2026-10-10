"""tests/test_sqli_mitm.py — SQLi 语义检测 + MITM 证书测试。"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.sqli_detect import detect_sqli_semantic
from core.mitm import CertStore

def test_sqli():
    cases = [
        ("1 UNION SELECT password FROM users", 1),
        ("1 UnIoN/**/SeLeCt password", 1),
        ("1 UNION/**/ALL/**/SELECT 1,2,3", 1),
        ("' OR 1=1 --", 1),
        ("' AND 1=1 --", 1),
        ("' OR 'a'='a'", 1),
        ("1; WAITFOR DELAY '0:0:5'", 1),
        ("1 AND SLEEP(5)", 1),
        ("1 AND BENCHMARK(5000000,MD5(1))", 1),
        ("1 AND PG_SLEEP(5)", 1),
        ("1 INTO OUTFILE '/tmp/shell.php'", 1),
        ("LOAD_FILE('/etc/passwd')", 1),
        ("information_schema.tables", 1),
        ("GROUP_CONCAT(username,0x3a,password)", 1),
        ("EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))", 1),
        # 干净输入不应命中
        ("hello world normal search query", 0),
        ("product_id=42", 0),
    ]
    ok = 0
    for text, expect_min in cases:
        hits = detect_sqli_semantic(text)
        got = len(hits)
        flag = "OK" if got >= expect_min else "FAIL"
        if got >= expect_min:
            ok += 1
        detail = ", ".join(h.rule_id for h in hits) if hits else "-"
        short = text[:45]
        print(f"  [{flag}] {short:45s} hits={got:>2} ({detail})")
    print(f"SQLi 语义检测: {ok}/{len(cases)} 通过\n")

def test_mitm():
    cs = CertStore("cert_store")
    cert_pem, key_pem = cs.get_leaf("www.google.com")
    print(f"叶子证书签发 OK, host=www.google.com")
    print(f"cert_pem: {len(cert_pem)} bytes | key_pem: {len(key_pem)} bytes")
    cert2, key2 = cs.get_leaf("www.google.com")
    print(f"缓存命中: {cert2 == cert_pem}\n")

if __name__ == "__main__":
    test_sqli()
    test_mitm()