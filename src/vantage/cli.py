"""
vantage.cli — unified command-line entry point.

    vantage version
    vantage kb <...>                 protocol knowledge base (import/search/diff/docs/serve)
    vantage protocol build <dirs>    build FPNN protocol artifacts from captures
    vantage protocol from-pcap <f>   decode FPNN sessions from a Wireshark pcap/pcapng
    vantage protocol synth <out>     write a synthetic sample capture session
    vantage classify <...>           classify a managed-class inventory
    vantage instrument <tool> ...    run an observation-only Frida tool (needs 'vantage[instrument]')
    vantage plugins [list]           list discovered plugins

Sub-tool arguments are passed through verbatim (e.g. ``vantage kb --db x import ...``).
Every subcommand is observation-only: nothing is injected, replayed, modified, or automated.
"""
import sys

from vantage import __version__

USAGE = __doc__

INSTRUMENT = {
    "process": "vantage.instrument.process",
    "recover": "vantage.instrument.il2cpp",
    "capture": "vantage.instrument.capture",
    "analyze": "vantage.instrument.analyze",
    "analyze-metadata": "vantage.instrument.analyze_metadata",
}


def _run(mod_path, argv):
    import importlib
    rc = importlib.import_module(mod_path).main(argv)
    return 0 if rc is None else rc


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0
    cmd, rest = argv[0], argv[1:]

    if cmd in ("version", "--version"):
        print(f"vantage {__version__}")
        return 0

    if cmd == "kb":
        return _run("vantage.kb.cli", rest)

    if cmd == "classify":
        return _run("vantage.metadata.inventory", rest)

    if cmd == "protocol":
        if rest and rest[0] == "build":
            return _run("vantage.protocol.build", rest[1:])
        if rest and rest[0] == "from-pcap":
            return _run("vantage.protocol.pcap", rest[1:])
        if rest and rest[0] == "synth":
            if len(rest) < 2:
                print("usage: vantage protocol synth <out_dir> [--label L]"); return 1
            label = "synthetic"
            if "--label" in rest:
                label = rest[rest.index("--label") + 1]
            from vantage.protocol.synthetic import write_session
            out = write_session(rest[1], label=label)
            print(f"[*] synthetic capture session -> {out}  (records are marked _synthetic)")
            return 0
        print("usage: vantage protocol {build|synth|from-pcap} ..."); return 1

    if cmd == "instrument":
        if not rest or rest[0] not in INSTRUMENT:
            print(f"usage: vantage instrument {{{'|'.join(INSTRUMENT)}}} ..."); return 1
        return _run(INSTRUMENT[rest[0]], rest[1:])

    if cmd == "plugins":
        from vantage.plugins import discover
        plugins = discover()
        if not plugins:
            print("  (no plugins found; drop *.py into ./plugins or set VANTAGE_PLUGINS_DIR)")
        for p in plugins:
            print(f"  {p['name']:26} {p.get('description', '')}")
        return 0

    print(USAGE)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
