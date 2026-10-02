import json

N = {
    "P-256": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    "P-384": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
}

def der_rs(sig_bytes):
    """(r, s) as integers from DER SEQUENCE{INTEGER r, INTEGER s}."""
    b = sig_bytes
    assert b[0] == 0x30
    i = 2
    assert b[i] == 0x02, f"r tag {b[i]:02x}"
    rl = b[i + 1]
    r = int.from_bytes(b[i + 2:i + 2 + rl], "big")
    j = i + 2 + rl
    assert b[j] == 0x02, f"s tag {b[j]:02x}"
    sl = b[j + 1]
    s = int.from_bytes(b[j + 2:j + 2 + sl], "big")
    return r, s

def der_s_high(sig_bytes, n):
    """True iff s > n/2 (exact comparison — top-byte heuristics break on
    `0x00…`/`0x7f…` edge encodings, which this corpus deliberately has)."""
    _, s = der_rs(sig_bytes)
    return s > n // 2

out = []
for fn, curve in [
    ("ecdsa_secp256r1_sha256_test.json", "P-256"),
    ("ecdsa_secp384r1_sha384_test.json", "P-384"),
    ("ed25519_test.json", "ED25519"),
]:
    d = json.load(open(fn))
    n = 0
    for g in d["testGroups"]:
        pk = (g["publicKey"].get("uncompressed") or g["publicKey"]["pk"]).lower()
        sha = g.get("sha", "")
        for t in g["tests"]:
            sig = t["sig"].lower()
            out.append("[sv]")
            out.append(f"curve = {curve}")
            out.append(f"sha = {sha}")
            out.append(f"count = {t['tcId']}")
            out.append(f"pk = {pk}")
            out.append(f"msg = {t['msg'].lower()}")
            out.append(f"sig = {sig}")
            out.append(f"result = {t['result']}")
            if curve != "ED25519":
                try:
                    high = int(der_s_high(bytes.fromhex(sig), N[curve]))
                except Exception:
                    high = 0  # malformed sig — verdict is reject regardless
                out.append(f"high_s = {high}")
            flags = ",".join(t.get("flags", []))
            if flags:
                out.append(f"flags = {flags}")
            n += 1
    print(curve, n)
open("wycheproof.txt", "w").write(
    "# Wycheproof distilled verify vectors (ECDSA P-256/SHA-256, P-384/SHA-384, Ed25519).\n"
    "# `high_s` marks DER sigs whose s > n/2: this crate canonicalises to low-s\n"
    "# and rejects those even where Wycheproof (testvectors_v1) marks them valid.\n"
    "# See PROVENANCE.md for source, license, and provenance.\n\n"
    + "\n".join(out) + "\n"
)
