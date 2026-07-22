#!/usr/bin/env python3
"""
recover.py — Phase 4 IL2CPP runtime metadata recovery launcher (OBSERVATION ONLY).

Locates the IL2CPP read-only API in memory (offsets or, opt-in, behavioral
export-index probing), then walks Assembly -> Image -> Class -> Method using the
runtime's own accessors, classifies networking/serialization/etc. classes, and
streams the results to timestamped JSON. It does NOT decrypt metadata, extract
keys, patch memory, modify packets, or bypass HTProtect/anti-cheat.

Usage:
    python3 recover.py --spawn --warmup 15
    python3 recover.py --attach --names-only
    python3 recover.py --attach --max-classes 8000 --method-cap 256
    python3 recover.py --attach --allow-probe        # opt into L3 behavioral probing (risky)

Requires il2cpp API RVAs in offsets/offsets.json for a hardened HTProtect build,
UNLESS --allow-probe successfully validates the export-index auto-map.
"""
import argparse
import json
import os
import sys
import time

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

AGENT_FILES_P4 = [
    "agent/core/logger.js",
    "agent/core/utils.js",
    "agent/core/state.js",
    "agent/hooks/process.js",       # module discovery + dlopen (libil2cpp base, JNI)
    "agent/il2cpp/api_defs.js",
    "agent/il2cpp/classify.js",
    "agent/il2cpp/correlate.js",
    "agent/il2cpp/regscan.js",
    "agent/il2cpp/api_locator.js",
    "agent/il2cpp/traverse.js",
    "agent/hooks/metadata_recovery.js",
]

BOOTSTRAP = r"""
// ==== phase4 bootstrap ====
(function () {
  try { if (KS.phaseA && KS.phaseA.init) KS.phaseA.init(); } catch (e) { KS.log.error('BOOT','phaseA',{err:String(e)}); }
  try { KS.phase4.init(); } catch (e) { KS.log.error('BOOT','phase4',{err:String(e)}); }
  rpc.exports = {
    recover: function (o) { return KS.phase4.recover(o || {}); },
    modules: function () { return KS.state.modules; },
    stats:   function () { return KS.state.il2cpp.stats || null; },
    ping:    function () { return 'pong'; }
  };
  KS.log.important('BOOT','recover_agent_ready',{});
})();
"""


def build_agent(config, offsets):
    parts = ["globalThis.KS_CONFIG = %s;" % json.dumps(config),
             "globalThis.KS_OFFSETS = %s;" % json.dumps(offsets or {})]
    for rel in AGENT_FILES_P4:
        p = os.path.join(PKG, rel)
        with open(p, "r", encoding="utf-8") as f:
            parts.append("// ==== %s ====\n%s" % (rel, f.read()))
    parts.append(BOOTSTRAP)
    return "\n".join(parts)


def main():
    if frida is None:
        sys.stderr.write("[!] frida not installed. pip install 'vantage[instrument]'\n"); sys.exit(2)
    ap = argparse.ArgumentParser(description="Phase 4 IL2CPP runtime metadata recovery (observation only)")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--spawn", action="store_true")
    mode.add_argument("--attach", action="store_true")
    ap.add_argument("--package", default=None)
    ap.add_argument("--device", default=None)
    ap.add_argument("--host", default=None)
    ap.add_argument("--config", default=os.path.join(CONFIGS, "default.json"))
    ap.add_argument("--offsets", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--warmup", type=float, default=12.0, help="seconds to wait for il2cpp_init/domain before recovery")
    ap.add_argument("--names-only", action="store_true", help="skip method enumeration (fast class inventory)")
    ap.add_argument("--max-classes", type=int, default=None)
    ap.add_argument("--method-cap", type=int, default=None)
    ap.add_argument("--allow-probe", action="store_true", help="enable L3 behavioral export-index probing (may crash/flag)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    config = load_json(args.config, {}) or {}
    if args.package:
        config["package"] = args.package
    rc = config.setdefault("il2cpp_recovery", {})
    if args.allow_probe:
        rc["allow_behavioral_probe"] = True
    pkg = config.get("package", "com.example.unitygame")

    offs_path = args.offsets or os.path.join(HERE, (config.get("il2cpp", {}) or {}).get("offsets_file", "offsets/offsets.json"))
    offsets = load_json(offs_path, {}) or {}

    ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
    out_dir = args.out or os.path.join(os.getcwd(), "vantage_data", "logs", "metadata_" + ts)
    logger = Logger(out_dir, quiet=args.quiet)
    recovered = []  # accumulate 'recovered_class' events

    print(f"{C.GRN}[*] Phase 4 metadata recovery -> {out_dir}{C.RESET}")
    print(f"{C.YEL}[i] OBSERVATION ONLY — reads in-memory metadata via the runtime's own API. "
          f"No decryption, no key extraction, no patching, no bypass.{C.RESET}")
    if not offsets.get("libil2cpp.so") and not rc.get("allow_behavioral_probe"):
        print(f"{C.YEL}[i] No il2cpp offsets and probing disabled: recovery will report the locator "
              f"remedy + regscan candidates only. Add offsets/offsets.json or pass --allow-probe.{C.RESET}")

    def on_message(message, data):
        if message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict) and payload.get("__ks"):
                logger.event(payload, binary=data)
                if payload.get("event") == "recovered_class":
                    recovered.append(payload.get("data"))
            else:
                logger.raw("send: " + json.dumps(payload))
        elif message.get("type") == "error":
            logger.raw("JS error: " + json.dumps(message))

    try:
        device = get_device(args)
    except Exception as e:
        print(f"{C.RED}[!] device: {e}{C.RESET}"); sys.exit(3)

    agent_src = build_agent(config, offsets)
    session = script = None
    try:
        if args.attach:
            session = device.attach(pkg)
        else:
            pid = device.spawn([pkg]); session = device.attach(pid)
        script = session.create_script(agent_src)
        script.on("message", on_message)
        script.load()
        if not args.attach:
            device.resume(pid)
    except Exception as e:
        print(f"{C.RED}[!] attach/spawn: {e}{C.RESET}"); sys.exit(5)

    print(f"{C.GRN}[*] agent loaded; warming up {args.warmup}s for il2cpp_init/domain …{C.RESET}")
    time.sleep(args.warmup)

    result = None
    try:
        exports = script.exports_sync if hasattr(script, "exports_sync") else script.exports
        print(f"{C.GRN}[*] starting recovery …{C.RESET}")
        result = exports.recover({
            "names_only": bool(args.names_only),
            "max_classes": args.max_classes,
            "method_cap": args.method_cap,
        })
    except Exception as e:
        logger.raw(f"recover() error: {e}")
        print(f"{C.RED}[!] recover() failed (HTProtect may have terminated the session): {e}{C.RESET}")

    # persist structured metadata
    meta = {"result": result, "recovered_classes": recovered, "count": len(recovered)}
    with open(os.path.join(out_dir, "metadata.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    try:
        if script: script.unload()
        if session: session.detach()
    except Exception:
        pass
    logger.close(summary={"events": logger.count, "recovered_classes": len(recovered), "result": result})
    print(f"\n{C.GRN}[*] recovered {len(recovered)} classified classes.{C.RESET}")
    print(f"{C.GRN}[*] metadata.json + events.jsonl -> {out_dir}{C.RESET}")
    print(f"{C.GRN}[*] reduce with: python3 analyze_metadata.py {out_dir}{C.RESET}")


if __name__ == "__main__":
    main()
