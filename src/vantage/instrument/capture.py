#!/usr/bin/env python3
"""
capture.py — Phase 5 FPNN capture launcher (OBSERVATION ONLY).

Loads the FPNN capture agent, reassembles per-(fd,direction) TCP byte streams
from the streamed chunks, splits them into FPNN frames, decodes MessagePack, and
writes:
    captures/session_<ts>/events.jsonl     raw agent events (incl. base64 chunks)
    captures/session_<ts>/streams/<fd>_<dir>.bin   reassembled raw streams
    captures/session_<ts>/frames.jsonl      parsed FPNN frames (+ decoded payload)
    captures/session_<ts>/connections.json  connection map / lifetimes

Does not modify, inject, replay, or generate any traffic. It records what the
app sends/receives during NORMAL play, which you drive by hand (see Objective 7).
"""
import argparse
import base64
import json
import os
import sys
import time
from collections import defaultdict

try:
    import frida
except ImportError:
    frida = None

from vantage.instrument.process import Logger, C, load_json, get_device

import os
PKG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # src/vantage
AGENT = os.path.join(PKG, "agent")
CONFIGS = os.path.join(PKG, "configs")
HERE = PKG
from vantage.protocol.fpnn import iter_stream

AGENT_FILES = [
    "agent/core/logger.js", "agent/core/utils.js", "agent/core/state.js",
    "agent/hooks/fpnn_capture.js",
]
BOOTSTRAP = "(function(){ KS.phase5.init(); rpc.exports={ping:function(){return 'pong';}}; " \
            "KS.log.important('BOOT','capture_ready',{}); })();"


def build_agent(config):
    parts = ["globalThis.KS_CONFIG = %s;" % json.dumps(config)]
    for rel in AGENT_FILES:
        with open(os.path.join(PKG, rel), encoding="utf-8") as f:
            parts.append("// %s\n%s" % (rel, f.read()))
    parts.append(BOOTSTRAP)
    return "\n".join(parts)


def main():
    if frida is None:
        sys.stderr.write("[!] frida not installed. pip install 'vantage[instrument]'\n"); sys.exit(2)
    ap = argparse.ArgumentParser(description="Phase 5 FPNN capture (observation only)")
    m = ap.add_mutually_exclusive_group()
    m.add_argument("--spawn", action="store_true")
    m.add_argument("--attach", action="store_true")
    ap.add_argument("--package", default=None)
    ap.add_argument("--device", default=None)
    ap.add_argument("--host", default=None)
    ap.add_argument("--config", default=os.path.join(CONFIGS, "default.json"))
    ap.add_argument("--out", default=None)
    ap.add_argument("--label", default=None, help="tag this capture (e.g. 'login', 'send_march') for gameplay-event mapping")
    ap.add_argument("--duration", type=float, default=0, help="auto-stop after N seconds (0 = until Ctrl+C)")
    args = ap.parse_args()

    config = load_json(args.config, {}) or {}
    if args.package:
        config["package"] = args.package
    pkg = config.get("package", "com.example.unitygame")

    ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
    out_dir = args.out or os.path.join(os.getcwd(), "vantage_data", "captures", "session_" + ts + (("_" + args.label) if args.label else ""))
    os.makedirs(os.path.join(out_dir, "streams"), exist_ok=True)
    logger = Logger(out_dir, quiet=False)

    # reassembly buffers: (fd,dir) -> {chunks:{seq:bytes}, next:int, buf:bytearray}
    streams = defaultdict(lambda: {"chunks": {}, "next": 0, "buf": bytearray(), "peer": None})
    conns = {}
    frames_out = open(os.path.join(out_dir, "frames.jsonl"), "a", buffering=1, encoding="utf-8")
    frame_count = [0]

    print(f"{C.GRN}[*] FPNN capture -> {out_dir}"
          f"{('  label='+args.label) if args.label else ''}{C.RESET}")
    print(f"{C.YEL}[i] OBSERVATION ONLY — no injection/replay/modification. Drive ONE gameplay "
          f"action at a time to map it (Objective 7).{C.RESET}")

    def flush_stream(key):
        s = streams[key]
        # append any in-order chunks
        while s["next"] in s["chunks"]:
            s["buf"].extend(s["chunks"].pop(s["next"]))
            s["next"] += 1
        # parse complete frames, keep remainder
        consumed = 0
        for rec, a, b in iter_stream(bytes(s["buf"])):
            if rec.get("desync_skipped"):
                consumed = b
                continue
            rec["_fd"], rec["_dir"], rec["_peer"] = key[0], key[1], s["peer"]
            rec["_ts"] = time.time()
            frames_out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            frame_count[0] += 1
            consumed = b
        if consumed:
            del s["buf"][:consumed]

    def on_message(message, data):
        if message.get("type") != "send":
            if message.get("type") == "error":
                logger.raw("JS error: " + json.dumps(message))
            return
        payload = message.get("payload")
        if not (isinstance(payload, dict) and payload.get("__ks")):
            return
        logger.event(payload, binary=data)
        ev, d = payload.get("event"), payload.get("data", {})
        if ev == "conn_open":
            conns[d["fd"]] = {"peer": d.get("peer"), "open_ts": time.time(), "close_ts": None}
        elif ev == "conn_close":
            if d["fd"] in conns:
                conns[d["fd"]]["close_ts"] = time.time()
                conns[d["fd"]]["lifetime_ms"] = d.get("lifetime_ms")
        elif ev == "fpnn_chunk" and data:
            key = (d["fd"], d["dir"])
            s = streams[key]
            s["peer"] = d.get("peer")
            s["chunks"][d["seq"]] = data
            # also persist raw stream
            with open(os.path.join(out_dir, "streams", f"{d['fd']}_{d['dir']}.bin"), "ab") as f:
                f.write(data)
            flush_stream(key)

    try:
        device = get_device(args)
    except Exception as e:
        print(f"{C.RED}[!] device: {e}{C.RESET}"); sys.exit(3)

    session = script = None
    try:
        if args.attach:
            session = device.attach(pkg)
        else:
            pid = device.spawn([pkg]); session = device.attach(pid)
        script = session.create_script(build_agent(config))
        script.on("message", on_message)
        script.load()
        if not args.attach:
            device.resume(pid)
    except Exception as e:
        print(f"{C.RED}[!] attach/spawn: {e}{C.RESET}"); sys.exit(5)

    print(f"{C.GRN}[*] capturing… Ctrl+C to stop.{C.RESET}")
    try:
        if args.duration > 0:
            time.sleep(args.duration)
        else:
            while True:
                time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            if script: script.unload()
            if session: session.detach()
        except Exception:
            pass
        frames_out.close()
        with open(os.path.join(out_dir, "connections.json"), "w", encoding="utf-8") as f:
            json.dump({"label": args.label, "connections": conns}, f, indent=2, ensure_ascii=False)
        logger.close(summary={"frames": frame_count[0], "connections": len(conns), "label": args.label})
        print(f"\n{C.GRN}[*] {frame_count[0]} FPNN frames, {len(conns)} connections -> {out_dir}{C.RESET}")
        print(f"{C.GRN}[*] next: python3 fpnn/build_protocol.py {out_dir}{C.RESET}")


if __name__ == "__main__":
    main()
