#!/usr/bin/env python3
"""
the target application runtime-instrumentation launcher (Frida) — OBSERVATION ONLY.

Builds the agent by concatenating the modular JS files (core + phases + index),
injects config + optional il2cpp offsets, attaches/spawns the target, and
streams structured JSON events to timestamped logs.

This tool does NOT bypass, patch, or disable any protection, anti-cheat,
certificate pinning, signing, or integrity mechanism, and does NOT modify
network traffic. It only records runtime behavior for analysis.

Usage:
    python3 launcher.py --spawn
    python3 launcher.py --attach
    python3 launcher.py --spawn --device <serial> --config config/config.json
    python3 launcher.py --spawn --no-D_decrypt --phases A_process,E_network

Requires: frida, frida-tools  (pip install -r requirements.txt) and a
frida-server on the device whose ABI matches the TARGET PROCESS (this build ships
armeabi-v7a -> use a 32-bit frida-server if the process runs 32-bit).
"""

import argparse
import base64
import json
import os
import signal
import sys
import time
from datetime import datetime, timezone

try:
    import frida
except ImportError:  # frida is an optional runtime dependency
    frida = None

import os
PKG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # src/vantage
AGENT = os.path.join(PKG, "agent")
CONFIGS = os.path.join(PKG, "configs")
HERE = PKG

# Concatenation order: config/offsets are injected as globals BEFORE the code.
AGENT_SUBDIR = "agent"
AGENT_FILES = [
    "agent/core/logger.js",
    "agent/core/utils.js",
    "agent/core/state.js",
    "agent/hooks/process.js",
    "agent/hooks/il2cpp_api.js",
    "agent/hooks/metadata.js",
    "agent/hooks/decrypt_observer.js",
    "agent/hooks/network.js",
    "agent/hooks/requests.js",
    "agent/hooks/assets.js",
    "agent/hooks/strings.js",
    "agent/hooks/lua.js",
    "agent/bootstrap.js",
]

# ---- console colors -------------------------------------------------------
class C:
    RESET = "\033[0m"; DIM = "\033[2m"; RED = "\033[31m"; GRN = "\033[32m"
    YEL = "\033[33m"; BLU = "\033[34m"; MAG = "\033[35m"; CYN = "\033[36m"
PHASE_COLOR = {"A": C.CYN, "B": C.BLU, "C": C.MAG, "D": C.RED, "E": C.GRN,
               "F": C.GRN, "G": C.YEL, "H": C.MAG, "I": C.YEL, "CORE": C.DIM, "BOOT": C.DIM}


class Logger:
    """Structured JSONL sink + human console."""
    def __init__(self, out_dir, quiet=False):
        self.dir = out_dir
        os.makedirs(out_dir, exist_ok=True)
        self.jsonl = open(os.path.join(out_dir, "events.jsonl"), "a", buffering=1, encoding="utf-8")
        self.errlog = open(os.path.join(out_dir, "errors.log"), "a", buffering=1, encoding="utf-8")
        self.quiet = quiet
        self.count = 0
        self.by_phase = {}

    def event(self, rec, binary=None):
        if binary:
            rec.setdefault("data", {})["_payload_b64"] = base64.b64encode(binary).decode("ascii")
        self.jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self.count += 1
        ph = rec.get("phase", "?")
        self.by_phase[ph] = self.by_phase.get(ph, 0) + 1
        if not self.quiet:
            self._console(rec)

    def _console(self, rec):
        ph = rec.get("phase", "?")
        col = PHASE_COLOR.get(ph, "")
        ts = rec.get("ts", {}).get("iso", "")[11:23]
        ev = rec.get("event", "")
        data = rec.get("data", {})
        brief = {k: v for k, v in data.items() if k not in ("bt", "_payload_b64", "stack")}
        s = json.dumps(brief, ensure_ascii=False)
        if len(s) > 320:
            s = s[:320] + "…"
        sys.stdout.write(f"{C.DIM}{ts}{C.RESET} {col}[{ph}]{C.RESET} {ev} {s}\n")

    def raw(self, line):
        self.errlog.write(line + "\n")
        if not self.quiet:
            sys.stdout.write(f"{C.RED}[frida] {line}{C.RESET}\n")

    def close(self, summary=None):
        if summary:
            self.jsonl.write(json.dumps({"phase": "HOST", "event": "session_summary", "data": summary}) + "\n")
        self.jsonl.close(); self.errlog.close()


def build_agent(config, offsets):
    parts = []
    parts.append("globalThis.KS_CONFIG = %s;" % json.dumps(config))
    parts.append("globalThis.KS_OFFSETS = %s;" % json.dumps(offsets or {}))
    for rel in AGENT_FILES:
        path = os.path.join(PKG, rel)
        if not os.path.exists(path):
            raise FileNotFoundError(f"agent file missing: {rel}")
        with open(path, "r", encoding="utf-8") as f:
            parts.append("// ==== %s ====\n%s" % (rel, f.read()))
    return "\n".join(parts)


def load_json(path, default=None):
    if not path or not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def apply_phase_flags(config, args):
    ph = config.setdefault("phases", {})
    if args.phases:
        want = set(x.strip() for x in args.phases.split(",") if x.strip())
        for k in list(ph.keys()):
            ph[k] = k in want
        for k in want:
            ph[k] = True
    for k in list(ph.keys()):
        if getattr(args, "no_" + k, False):
            ph[k] = False
    return config


def get_device(args):
    if args.device:
        return frida.get_device(args.device, timeout=10)
    if args.host:
        return frida.get_device_manager().add_remote_device(args.host)
    return frida.get_usb_device(timeout=10)


def main():
    if frida is None:
        sys.stderr.write("[!] frida not installed. pip install 'vantage[instrument]'\n"); sys.exit(2)
    ap = argparse.ArgumentParser(description="the target application Frida instrumentation launcher (observation only)")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--spawn", action="store_true", help="spawn the package fresh (best coverage of early init)")
    mode.add_argument("--attach", action="store_true", help="attach to the already-running package")
    ap.add_argument("--package", default=None, help="override package name")
    ap.add_argument("--device", default=None, help="frida device id/serial (adb)")
    ap.add_argument("--host", default=None, help="remote frida-server host:port")
    ap.add_argument("--config", default=os.path.join(CONFIGS, "default.json"))
    ap.add_argument("--offsets", default=None, help="il2cpp offsets json (default: config.il2cpp.offsets_file)")
    ap.add_argument("--out", default=None, help="log output dir (default logs/session_<ts>)")
    ap.add_argument("--phases", default=None, help="comma list of phases to ENABLE exclusively, e.g. A_process,E_network")
    ap.add_argument("--quiet", action="store_true", help="JSONL only, no console stream")
    for k in ["A_process", "B_il2cpp", "C_metadata", "D_decrypt", "E_network",
              "F_requests", "G_assets", "H_strings", "I_lua"]:
        ap.add_argument("--no-" + k, dest="no_" + k, action="store_true", help="disable phase " + k)
    args = ap.parse_args()

    config = load_json(args.config, {}) or {}
    if args.package:
        config["package"] = args.package
    config = apply_phase_flags(config, args)
    pkg = config.get("package", "com.example.unitygame")

    offs_path = args.offsets or os.path.join(HERE, (config.get("il2cpp", {}) or {}).get("offsets_file", "offsets/offsets.json"))
    offsets = load_json(offs_path, {}) or {}

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_dir = args.out or os.path.join(os.getcwd(), "vantage_data", "logs", "session_" + ts)
    logger = Logger(out_dir, quiet=args.quiet)
    print(f"{C.GRN}[*] logs -> {out_dir}{C.RESET}")
    print(f"{C.YEL}[i] OBSERVATION ONLY — no bypass/patch/packet-modification. "
          f"HTProtect may detect Frida and terminate the app; that is expected and not worked around.{C.RESET}")

    try:
        device = get_device(args)
    except Exception as e:
        logger.raw(f"device error: {e}")
        print(f"{C.RED}[!] Could not get device. Is frida-server running and adb connected?{C.RESET}")
        sys.exit(3)

    agent_src = build_agent(config, offsets)

    session = None
    script = None
    stop = {"flag": False}

    def on_message(message, data):
        if message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict) and payload.get("__ks"):
                logger.event(payload, binary=data)
            else:
                logger.raw("send: " + json.dumps(payload))
        elif message.get("type") == "error":
            logger.raw("JS error: " + json.dumps(message))
        else:
            logger.raw("msg: " + json.dumps(message))

    def on_detached(reason, *rest):
        logger.raw(f"session detached: {reason}")
        print(f"{C.RED}[!] detached: {reason} "
              f"(HTProtect/NIS anti-tamper or process exit — not bypassed by design){C.RESET}")
        stop["flag"] = True

    try:
        if args.attach:
            print(f"{C.GRN}[*] attaching to {pkg} …{C.RESET}")
            session = device.attach(pkg)
        else:
            print(f"{C.GRN}[*] spawning {pkg} …{C.RESET}")
            pid = device.spawn([pkg])
            session = device.attach(pid)
        session.on("detached", on_detached)
        script = session.create_script(agent_src)
        script.on("message", on_message)
        script.load()
        if not args.attach:
            device.resume(pid)
        print(f"{C.GRN}[*] agent loaded. Ctrl+C to stop.{C.RESET}")
    except frida.ProcessNotFoundError:
        print(f"{C.RED}[!] {pkg} not running. Launch it, or use --spawn.{C.RESET}")
        sys.exit(4)
    except Exception as e:
        logger.raw(f"attach/spawn error: {e}")
        print(f"{C.RED}[!] {e}{C.RESET}")
        sys.exit(5)

    def shutdown(*_):
        stop["flag"] = True

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        while not stop["flag"]:
            time.sleep(0.4)
    finally:
        summary = None
        try:
            if script:
                summary = script.exports_sync.summary() if hasattr(script, "exports_sync") else script.exports.summary()
        except Exception:
            pass
        try:
            if script:
                script.unload()
        except Exception:
            pass
        try:
            if session:
                session.detach()
        except Exception:
            pass
        logger.close(summary={"events": logger.count, "by_phase": logger.by_phase, "agent_summary": summary})
        print(f"\n{C.GRN}[*] done. {logger.count} events. by_phase={logger.by_phase}{C.RESET}")
        print(f"{C.GRN}[*] events -> {os.path.join(out_dir, 'events.jsonl')}{C.RESET}")


if __name__ == "__main__":
    main()
