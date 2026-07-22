"""
kb/cli.py — unified CLI for the protocol knowledge base.

Subcommands:
  init                          create/upgrade the DB
  import <path> [--version V] [--label L]   import any artifact (auto-detected)
  update <captures_root> [--version V]       incremental import of new sessions
  docs [--version V] [--out DIR]             regenerate all documentation
  viewer [--version V] [--out DIR]           build the self-contained HTML viewer
  serve [--out DIR] [--port N]               serve the viewer locally
  diff <v1> <v2> [--out FILE]                version comparison / migration report
  search <query> [args...]                   canned queries (see below) or --sql "SELECT ..."
  stats                                      DB summary

All operations are read-or-append only; nothing is transmitted or modified in the
target app. `docs` + `viewer` are auto-run after `import`/`update` unless --no-docs.
"""
import argparse
import json
import os
import sys

from vantage.kb.db import open_db
from vantage.kb import importer, updater, docgen, viewer, versions, search

DEFAULT_DB = os.path.join(os.getcwd(), "vantage_data", "protocol.db")
DEFAULT_DOCS = os.path.join(os.getcwd(), "vantage_data", "docs")
DEFAULT_SITE = os.path.join(os.getcwd(), "vantage_data", "site")


def _auto_regen(db, version, quiet=False):
    docgen.regenerate(db, DEFAULT_DOCS, version)
    viewer.build(db, DEFAULT_SITE, None)
    if not quiet:
        print(f"[*] docs -> {DEFAULT_DOCS}  ·  viewer -> {os.path.join(DEFAULT_SITE,'index.html')}")


def cmd_stats(db, args):
    for t in ["sessions", "connections", "commands", "packets", "requests", "responses", "schemas",
              "schema_fields", "classes", "methods", "strings", "assets", "gameplay_actions",
              "confidence_history", "relationships", "unknown_fields", "versions"]:
        n = db.q1(f"SELECT COUNT(*) n FROM {t}")["n"]
        print(f"  {t:20} {n}")
    obs = db.q1("SELECT COALESCE(SUM(obs_count),0) o FROM packets")["o"]
    print(f"  {'packet_observations':20} {obs}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="kbctl", description="the target application protocol knowledge base (observation-only)")
    ap.add_argument("--db", default=DEFAULT_DB)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init")
    p = sub.add_parser("import"); p.add_argument("path"); p.add_argument("--version", default="unknown"); p.add_argument("--label"); p.add_argument("--no-docs", action="store_true")
    p = sub.add_parser("update"); p.add_argument("root"); p.add_argument("--version", default="unknown"); p.add_argument("--no-docs", action="store_true")
    p = sub.add_parser("docs"); p.add_argument("--version", default="unknown"); p.add_argument("--out", default=DEFAULT_DOCS)
    p = sub.add_parser("viewer"); p.add_argument("--version", default=None); p.add_argument("--out", default=DEFAULT_SITE)
    p = sub.add_parser("serve"); p.add_argument("--out", default=DEFAULT_SITE); p.add_argument("--port", type=int, default=8765)
    p = sub.add_parser("diff"); p.add_argument("v1"); p.add_argument("v2"); p.add_argument("--out")
    p = sub.add_parser("search"); p.add_argument("query"); p.add_argument("rest", nargs="*"); p.add_argument("--sql"); p.add_argument("--version")
    sub.add_parser("stats")

    args = ap.parse_args(argv)
    db = open_db(args.db)

    try:
        if args.cmd == "init":
            print(f"[*] KB ready at {args.db}")

        elif args.cmd == "import":
            kind, res = importer.import_path(db, args.path, version=args.version, label=args.label)
            print(f"[*] imported ({kind}): {json.dumps(res, ensure_ascii=False)}")
            if not args.no_docs:
                _auto_regen(db, args.version)

        elif args.cmd == "update":
            res = updater.scan_and_import(db, args.root, version=args.version)
            print(f"[*] update: scanned={res.get('scanned')} imported={res.get('imported')} skipped={res.get('skipped')}")
            if not args.no_docs:
                _auto_regen(db, args.version)

        elif args.cmd == "docs":
            names = docgen.regenerate(db, args.out, args.version)
            print(f"[*] regenerated {len(names)} docs -> {args.out}")

        elif args.cmd == "viewer":
            path = viewer.build(db, args.out, args.version)
            print(f"[*] viewer -> {path}")

        elif args.cmd == "serve":
            viewer.serve(args.out, args.port)

        elif args.cmd == "diff":
            d = versions.diff(db, args.v1, args.v2)
            md = versions.migration_report_md(d)
            if args.out:
                with open(args.out, "w", encoding="utf-8") as f:
                    f.write(md)
                print(f"[*] migration report -> {args.out}")
            print(json.dumps(d["summary"], indent=2))

        elif args.cmd == "search":
            if args.sql:
                rows = search.run_sql(db, args.sql)
            elif args.query in search.CANNED:
                fn, params = search.CANNED[args.query]
                rows = fn(db, *(args.rest[:len(params)]))
            else:
                print(f"unknown query '{args.query}'. Canned: {list(search.CANNED)} or --sql \"SELECT ...\"")
                return
            print(json.dumps(rows, indent=2, ensure_ascii=False, default=str))

        elif args.cmd == "stats":
            cmd_stats(db, args)
    finally:
        db.close()


if __name__ == "__main__":
    main()
