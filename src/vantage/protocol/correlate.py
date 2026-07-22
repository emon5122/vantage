"""
correlate.py — request/response correlation + timing over parsed FPNN frames.

Reads frames.jsonl (from capture.py). Pairs two-way quests with answers by seq,
measures RTT, detects heartbeats (regular same-method quests), server pushes
(one-way quests arriving on rx), retries (repeat before answer) and timeouts.
Observation/analysis only — computed from captured frames, nothing is sent.
"""
import json
import os
import statistics
from collections import defaultdict


def load_frames(path):
    if os.path.isdir(path):
        path = os.path.join(path, "frames.jsonl")
    frames = []
    if not os.path.exists(path):
        return frames
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "header" in r:
                frames.append(r)
    return frames


def correlate(frames, timeout_s=15.0):
    quests = [f for f in frames if f["header"]["mtype"] in (0, 1)]
    answers = [f for f in frames if f["header"]["mtype"] == 2]
    ans_by_seq = defaultdict(list)
    for a in answers:
        ans_by_seq[a.get("seq")].append(a)

    pairs, pushes, unanswered = [], [], []
    for q in quests:
        direction = q.get("_dir")
        mtype = q["header"]["mtype"]
        if mtype == 0 and direction == "rx":
            pushes.append({"method": q.get("method"), "ts": q.get("_ts"), "payload_len": q.get("payload_len"),
                           "kind": "server_push", "confidence": "observed"})
            continue
        seq = q.get("seq")
        cand = [a for a in ans_by_seq.get(seq, []) if a.get("_ts", 0) >= q.get("_ts", 0)]
        if cand:
            a = min(cand, key=lambda x: x.get("_ts", 0))
            rtt = (a.get("_ts", 0) - q.get("_ts", 0)) * 1000.0
            pairs.append({"seq": seq, "method": q.get("method"), "rtt_ms": round(rtt, 2),
                          "req_len": q.get("payload_len"), "resp_len": a.get("payload_len"),
                          "status": a.get("status"), "ts": q.get("_ts")})
        else:
            unanswered.append({"seq": seq, "method": q.get("method"), "ts": q.get("_ts"),
                               "note": "no answer captured (timeout/one-way/uncaptured)"})

    # heartbeat detection: methods with >=3 regular quests
    by_method = defaultdict(list)
    for q in quests:
        if q.get("method") is not None:
            by_method[q["method"]].append(q.get("_ts"))
    heartbeats = []
    for method, tss in by_method.items():
        tss = sorted(t for t in tss if t)
        if len(tss) >= 3:
            gaps = [round(tss[i + 1] - tss[i], 2) for i in range(len(tss) - 1)]
            if gaps:
                med = statistics.median(gaps)
                jitter = (max(gaps) - min(gaps)) if len(gaps) > 1 else 0
                regular = jitter <= max(1.0, med * 0.5)
                if regular and med > 0:
                    heartbeats.append({"method": method, "interval_s_median": med, "count": len(tss),
                                       "jitter_s": round(jitter, 2), "confidence": "observed" if len(tss) >= 5 else "likely"})

    # retry detection: same method twice within 5s and before any answer
    retries = []
    for method, tss in by_method.items():
        tss = sorted(t for t in tss if t)
        for i in range(len(tss) - 1):
            if 0 < (tss[i + 1] - tss[i]) <= 5.0:
                retries.append({"method": method, "gap_s": round(tss[i + 1] - tss[i], 2)})

    rtts = [p["rtt_ms"] for p in pairs]
    stats = {
        "quests": len(quests), "answers": len(answers), "pairs": len(pairs),
        "pushes": len(pushes), "unanswered": len(unanswered),
        "rtt_ms": {"min": round(min(rtts), 2), "median": round(statistics.median(rtts), 2),
                   "max": round(max(rtts), 2)} if rtts else None,
    }
    return {"stats": stats, "pairs": pairs, "pushes": pushes, "unanswered": unanswered,
            "heartbeats": heartbeats, "retries": retries[:50]}
