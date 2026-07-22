"""
kb/updater.py — incremental updater. Scans a captures root for session dirs and
imports only new/changed ones (content-hash gate in the importer makes unchanged
re-imports a no-op). Safe to run repeatedly / on a schedule.
"""
import os

from vantage.kb import importer


def scan_and_import(db, captures_root, version="unknown"):
    results = []
    if not os.path.isdir(captures_root):
        return {"error": f"not a dir: {captures_root}"}
    for name in sorted(os.listdir(captures_root)):
        d = os.path.join(captures_root, name)
        if not os.path.isdir(d):
            continue
        if os.path.exists(os.path.join(d, "frames.jsonl")):
            r = importer.import_capture(db, d, version=version)
            results.append({"dir": name, "result": r})
    imported = [r for r in results if "session" in r.get("result", {})]
    skipped = [r for r in results if "skipped" in r.get("result", {})]
    return {"scanned": len(results), "imported": len(imported), "skipped": len(skipped), "details": results}
