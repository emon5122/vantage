"""
classify_lib.py — Python mirror of src/vantage/agent/il2cpp/classify.js.

Same category keyword model + trusted-namespace boosts, so the offline static
inventory classifier and the on-device recovery agree. Used by
build_static_inventory.py (real static data) and analyze_metadata.py (runtime).
"""

CAT = {
    "Network":     {"strong": ["network", "tcpclient", "tcpconnection", "socket", "connection", "clientengine", "receiver"], "weak": ["net", "transport", "channel"]},
    "HTTP":        {"strong": ["http", "besthttp", "webrequest", "httprequestwork", "httpgetwork"], "weak": ["web", "url", "download"]},
    "Request":     {"strong": ["request", "quest"], "weak": ["req"]},
    "Response":    {"strong": ["response", "answer"], "weak": ["resp", "reply"]},
    "Gateway":     {"strong": ["gateway", "gate"], "weak": []},
    "Login":       {"strong": ["login", "auth", "signin", "logon", "cgsession"], "weak": ["account", "token", "session"]},
    "Session":     {"strong": ["session"], "weak": ["token", "credential"]},
    "Player":      {"strong": ["player", "profile"], "weak": ["user", "role", "avatar"]},
    "Battle":      {"strong": ["battle", "combat", "fight"], "weak": ["skill", "buff"]},
    "March":       {"strong": ["march", "rally", "troop"], "weak": ["army", "squad"]},
    "Alliance":    {"strong": ["alliance", "guild", "clan"], "weak": ["union"]},
    "Chat":        {"strong": ["chat", "rtm", "conversation", "message"], "weak": ["talk"]},
    "Config":      {"strong": ["config", "setting", "configreader", "configdata"], "weak": ["cfg", "define", "const"]},
    "Version":     {"strong": ["version", "manifest", "hotfix", "patch", "checkappversion", "versionmanifest"], "weak": ["update", "upgrade"]},
    "Asset":       {"strong": ["asset", "assetloader", "assetmodule", "resloader", "resource"], "weak": ["res", "texture"]},
    "Bundle":      {"strong": ["assetbundle", "bundle", "assetbundlemgr"], "weak": []},
    "Lua":         {"strong": ["lua", "tolua", "luastate", "luaclient"], "weak": []},
    "Message":     {"strong": ["message", "msg", "notify", "notification"], "weak": []},
    "Packet":      {"strong": ["packet", "pkt"], "weak": []},
    "Serialize":   {"strong": ["serialize", "serializer", "formatter", "msgpacker"], "weak": ["encode", "pack", "writer"]},
    "Deserialize": {"strong": ["deserialize", "unpacker", "msgunpacker", "reader", "parser"], "weak": ["decode", "unpack"]},
}

TRUST = [
    (r"^com\.fpnn", ["Network", "Message", "Packet", "Serialize", "Deserialize", "Chat"], 0.35),
    (r"Best\.HTTP", ["HTTP", "Request", "Response", "Network"], 0.30),
    (r"CenturyGame\.GameFramework", ["Asset", "Bundle", "Version", "HTTP", "Network", "Config"], 0.20),
    (r"OdinSerializer", ["Serialize", "Deserialize"], 0.30),
    (r"^Lua|tolua", ["Lua"], 0.30),
]

import re
_TRUST = [(re.compile(rx, re.I), cats, b) for rx, cats, b in TRUST]

# Third-party TLS/crypto/ASN.1 plumbing bundled inside BestHTTP (BouncyCastle).
# These are NOT the game's networking design — bucket them separately so they
# don't flood HTTP/Packet/Session. Detected by namespace.
_LIB_INTERNAL = re.compile(
    r"BouncyCastle|SecureProtocol|(^|\.)Asn1(\.|$)|Bcpg|(^|\.)Pkcs|(^|\.)Tls(\.|$)|"
    r"Ocsp|(^|\.)Cms(\.|$)|Crmf|(^|\.)Ess(\.|$)|(^|\.)X509|(^|\.)Pkix", re.I)


def score_one(assembly, ns, name):
    if ns and _LIB_INTERNAL.search(ns):
        return {"role": "TlsCryptoInternal", "confidence": 0.15, "tier": "low",
                "categories": {"TlsCryptoInternal": 0.15}, "reasons": ["third-party TLS/crypto (BestHTTP/BouncyCastle) — excluded from game networking"],
                "library_internal": True}
    hay_name = (name or "").lower()
    hay_ns = (ns or "").lower()
    ctx = f"{assembly or ''}.{ns or ''}"
    all_cats = {}
    best = {"role": None, "score": 0.0, "reasons": []}
    for cat, kw in CAT.items():
        s = 0.0
        why = []
        for k in kw["strong"]:
            if k in hay_name:
                s += 0.6; why.append(f"name~{k}")
            elif k in hay_ns:
                s += 0.3; why.append(f"ns~{k}")
        for k in kw["weak"]:
            if k in hay_name:
                s += 0.2; why.append(f"name~{k}")
        for rx, cats, boost in _TRUST:
            if rx.search(ctx) and cat in cats:
                s += boost; why.append(f"trust:{rx.pattern}")
        if s > 0:
            all_cats[cat] = min(round(s, 2), 1.0)
            if s > best["score"]:
                best = {"role": cat, "score": min(s, 1.0), "reasons": why}
    conf = round(best["score"], 2)
    tier = "high" if conf >= 0.75 else ("medium" if conf >= 0.5 else ("low" if conf > 0 else "none"))
    return {"role": best["role"], "confidence": conf, "tier": tier, "categories": all_cats, "reasons": best["reasons"]}
