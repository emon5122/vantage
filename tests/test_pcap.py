"""Tests for the pcap/pcapng reader + TCP reassembly + FPNN extraction.

Builds SYNTHETIC classic-pcap and pcapng files (Ethernet/IPv4/TCP) carrying
spec-conformant FPNN frames, then runs the real decode path. No real capture is
used; this validates the tooling on fabricated input.
"""
import json
import os
import struct

from vantage.protocol.synthetic import synthetic_session
from vantage.protocol import pcap


def _eth_ipv4_tcp(src, sport, dst, dport, seq, payload):
    def ipnum(s):
        return bytes(int(x) for x in s.split("."))
    eth = b"\x00" * 6 + b"\x00" * 6 + struct.pack(">H", 0x0800)
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, (5 << 4), 0x18, 65535, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH", 0x45, 0, total, 0, 0x4000, 64, 6, 0) + ipnum(src) + ipnum(dst)
    return eth + ip + tcp


def _segment_stream(stream, base_seq, mtu=40):
    """Yield (seq, chunk) splitting a byte stream into small TCP segments."""
    off = 0
    while off < len(stream):
        chunk = stream[off:off + mtu]
        yield (base_seq + off) & 0xFFFFFFFF, chunk
        off += mtu


def _write_classic_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # Ethernet
        for ts, data in packets:
            f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(data), len(data)))
            f.write(data)


def _write_pcapng(path, packets):
    with open(path, "wb") as f:
        # SHB
        shb = struct.pack("<III", 0x0A0D0D0A, 28, 0x1A2B3C4D) + struct.pack("<HHq", 1, 0, -1) + struct.pack("<I", 28)
        f.write(shb)
        # IDB (linktype 1 = Ethernet)
        idb = struct.pack("<II", 0x00000001, 20) + struct.pack("<HHI", 1, 0, 65535) + struct.pack("<I", 20)
        f.write(idb)
        for ts, data in packets:
            tstick = int(ts * 1e6)
            pad = (4 - len(data) % 4) % 4
            body = struct.pack("<IIII", 0, tstick >> 32, tstick & 0xFFFFFFFF, len(data)) + \
                struct.pack("<I", len(data)) + data + b"\x00" * pad
            total = 12 + len(body)
            f.write(struct.pack("<II", 0x00000006, total) + body + struct.pack("<I", total))


def _build_packets():
    """A client<->server FPNN exchange over TCP, split across segments."""
    tx, ts_tx, rx, ts_rx = synthetic_session()
    CLIENT, SPORT, SERVER, DPORT = "10.0.0.2", 41000, "203.0.113.9", 13013
    packets = []
    t = 1_700_000_000.0
    for seq, chunk in _segment_stream(tx, base_seq=1000):
        packets.append((t, _eth_ipv4_tcp(CLIENT, SPORT, SERVER, DPORT, seq, chunk)))
        t += 0.001
    for seq, chunk in _segment_stream(rx, base_seq=5000):
        packets.append((t, _eth_ipv4_tcp(SERVER, DPORT, CLIENT, SPORT, seq, chunk)))
        t += 0.001
    return packets, (SERVER, DPORT)


def _check_session(out_dir, server):
    frames = [json.loads(l) for l in open(os.path.join(out_dir, "frames.jsonl"))]
    methods = [f.get("method") for f in frames if f.get("_dir") == "tx"]
    assert "login" in methods
    assert methods.count("ping") == 5
    # server push observed on rx
    assert any(f["header"]["mtype"] == 0 and f.get("_dir") == "rx" for f in frames)
    # timestamps preserved from packets
    assert all(f["_ts"] is not None for f in frames)
    conns = json.load(open(os.path.join(out_dir, "connections.json")))
    peer = list(conns["connections"].values())[0]["peer"]
    assert (peer["ip"], peer["port"]) == server


def test_from_classic_pcap(tmp_path):
    packets, server = _build_packets()
    p = str(tmp_path / "cap.pcap")
    _write_classic_pcap(p, packets)
    res = pcap.to_session(p, str(tmp_path / "sess"), label="login")
    assert res["frames"] >= 13
    _check_session(str(tmp_path / "sess"), server)


def test_from_pcapng(tmp_path):
    packets, server = _build_packets()
    p = str(tmp_path / "cap.pcapng")
    _write_pcapng(p, packets)
    res = pcap.to_session(p, str(tmp_path / "sess"), label="login")
    assert res["frames"] >= 13
    _check_session(str(tmp_path / "sess"), server)


def test_pcap_session_imports_into_kb(tmp_path, kb):
    packets, _ = _build_packets()
    p = str(tmp_path / "cap.pcapng")
    _write_pcapng(p, packets)
    out = str(tmp_path / "sess")
    pcap.to_session(p, out, label="login")
    from vantage.kb import importer
    res = importer.import_capture(kb, out, version="1.0.0", label="login")
    assert res["frames"] >= 13 and res["commands"] >= 3
