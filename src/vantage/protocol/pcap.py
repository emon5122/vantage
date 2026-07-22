"""
vantage.protocol.pcap — turn a packet capture into a Vantage capture session.

Reads a ``.pcap`` or ``.pcapng`` file (e.g. exported from Wireshark or PCAPdroid),
reassembles TCP flows, auto-detects the FPNN streams, decodes them, and writes a
capture-session directory (``frames.jsonl`` + ``connections.json``) that drops
straight into ``vantage kb import``.

OBSERVATION ONLY. This parses a file you already recorded of your OWN device's
traffic. It never touches a device or network, never emits or modifies packets,
and has no third-party dependencies (keeps the offline core dependency-free).

Supported:
  * capture formats: classic pcap (us + ns), pcapng
  * link types: Ethernet (1, incl. 802.1Q VLAN), raw IPv4/IPv6 (101/12/14/228/229),
    Linux SLL (113), null/loopback (0)
  * IPv4 + IPv6, TCP reassembly (in-order with overlap/retransmit handling)

Timing: per-frame timestamps are recovered from the packet that carried each
frame's first byte, so heartbeat/RTT analysis works on real capture timing.
"""
import bisect
import json
import os
import struct

from vantage.protocol.fpnn import iter_stream, parse_message, TCP_MAGIC

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100


# --------------------------------------------------------------------------- #
# capture-file readers -> yield (ts_seconds: float, linktype: int, data: bytes)
# --------------------------------------------------------------------------- #
def read_packets(path):
    with open(path, "rb") as f:
        head = f.read(4)
        f.seek(0)
        if head == b"\x0a\x0d\x0d\x0a":
            yield from _read_pcapng(f)
        else:
            yield from _read_pcap(f)


def _read_pcap(f):
    magic = f.read(4)
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian, ns = ">", magic == b"\xa1\xb2\x3c\x4d"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian, ns = "<", magic == b"\x4d\x3c\xb2\xa1"
    else:
        raise ValueError("not a pcap/pcapng file")
    # global header after magic: ver_major(2) ver_minor(2) tz(4) sig(4) snaplen(4) linktype(4)
    _ = f.read(16)
    linktype = struct.unpack(endian + "I", f.read(4))[0]
    while True:
        rec = f.read(16)
        if len(rec) < 16:
            return
        ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII", rec)
        data = f.read(incl)
        if len(data) < incl:
            return
        ts = ts_sec + (ts_frac / 1e9 if ns else ts_frac / 1e6)
        yield ts, linktype, data


def _read_pcapng(f):
    interfaces = []  # linktype per interface index
    tsresol = []     # seconds-per-tick per interface
    endian = "<"
    while True:
        hdr = f.read(8)
        if len(hdr) < 8:
            return
        btype = hdr[:4]
        if btype == b"\x0a\x0d\x0d\x0a":  # Section Header Block: sets endianness
            bom = f.read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            total = struct.unpack(endian + "I", hdr[4:8])[0]
            f.read(total - 12)  # consume remainder of SHB (incl. trailing length)
            continue
        total = struct.unpack(endian + "I", hdr[4:8])[0]
        if total < 12:
            return
        body = f.read(total - 12)
        f.read(4)  # trailing block_total_length
        if len(body) < total - 12:
            return
        btype_i = struct.unpack(endian + "I", btype)[0]
        if btype_i == 0x00000001:  # Interface Description Block
            linktype = struct.unpack(endian + "H", body[0:2])[0]
            interfaces.append(linktype)
            tsresol.append(1e-6)
            _parse_idb_tsresol(body[8:], endian, tsresol)
        elif btype_i == 0x00000006:  # Enhanced Packet Block
            ifid, ts_hi, ts_lo, caplen, _orig = struct.unpack(endian + "IIIII", body[0:20])
            data = body[20:20 + caplen]
            res = tsresol[ifid] if ifid < len(tsresol) else 1e-6
            ts = ((ts_hi << 32) | ts_lo) * res
            lt = interfaces[ifid] if ifid < len(interfaces) else 1
            yield ts, lt, data
        elif btype_i == 0x00000003:  # Simple Packet Block
            orig = struct.unpack(endian + "I", body[0:4])[0]
            data = body[4:4 + orig]
            lt = interfaces[0] if interfaces else 1
            yield 0.0, lt, data
        # other block types ignored


def _parse_idb_tsresol(opts, endian, tsresol):
    i = 0
    while i + 4 <= len(opts):
        code, ln = struct.unpack(endian + "HH", opts[i:i + 4])
        i += 4
        val = opts[i:i + ln]
        i += ln + ((4 - ln % 4) % 4)  # pad to 4
        if code == 0:
            break
        if code == 9 and ln >= 1:  # if_tsresol
            b = val[0]
            tsresol[-1] = (10.0 ** -(b & 0x7f)) if not (b & 0x80) else (2.0 ** -(b & 0x7f))


# --------------------------------------------------------------------------- #
# link / IP / TCP extraction
# --------------------------------------------------------------------------- #
def _ip_from_link(linktype, data):
    try:
        if linktype == 1:  # Ethernet
            if len(data) < 14:
                return None
            eth = struct.unpack(">H", data[12:14])[0]
            off = 14
            while eth == ETH_P_8021Q and len(data) >= off + 4:
                eth = struct.unpack(">H", data[off + 2:off + 4])[0]
                off += 4
            if eth == ETH_P_IP:
                return 4, data[off:]
            if eth == ETH_P_IPV6:
                return 6, data[off:]
            return None
        if linktype == 113:  # Linux SLL
            if len(data) < 16:
                return None
            proto = struct.unpack(">H", data[14:16])[0]
            return (4, data[16:]) if proto == ETH_P_IP else ((6, data[16:]) if proto == ETH_P_IPV6 else None)
        if linktype == 0:  # null/loopback: 4-byte address family (host order)
            if len(data) < 4:
                return None
            fam = struct.unpack("<I", data[0:4])[0]
            return (4, data[4:]) if fam in (2,) else ((6, data[4:]) if fam in (24, 28, 30) else None)
        if linktype in (101, 12, 14, 228, 229):  # raw IP
            if not data:
                return None
            v = data[0] >> 4
            return (4, data) if v == 4 else ((6, data) if v == 6 else None)
    except Exception:
        return None
    return None


def _tcp_from_ip(ver, ip):
    try:
        if ver == 4:
            ihl = (ip[0] & 0x0F) * 4
            if ip[9] != 6:  # protocol != TCP
                return None
            src = ".".join(str(b) for b in ip[12:16])
            dst = ".".join(str(b) for b in ip[16:20])
            total_len = struct.unpack(">H", ip[2:4])[0]
            l4 = ip[ihl:total_len] if total_len else ip[ihl:]
        else:
            if ip[6] != 6:  # next header != TCP (chained headers not handled)
                return None
            src = _ipv6(ip[8:24])
            dst = _ipv6(ip[24:40])
            plen = struct.unpack(">H", ip[4:6])[0]
            l4 = ip[40:40 + plen] if plen else ip[40:]
        if len(l4) < 20:
            return None
        sport, dport, seq = struct.unpack(">HHI", l4[0:8])
        data_off = (l4[12] >> 4) * 4
        payload = l4[data_off:]
        return {"src": src, "sport": sport, "dst": dst, "dport": dport, "seq": seq, "payload": payload}
    except Exception:
        return None


def _ipv6(b):
    return ":".join("%x" % ((b[i] << 8) | b[i + 1]) for i in range(0, 16, 2))


# --------------------------------------------------------------------------- #
# TCP reassembly
# --------------------------------------------------------------------------- #
class DirStream:
    """One direction of a TCP connection: ordered payload + byte->timestamp map."""

    def __init__(self):
        self.segs = []  # (seq, payload, ts)
        self.first_ts = None

    def add(self, seq, payload, ts):
        if payload:
            self.segs.append((seq, payload, ts))
            if self.first_ts is None:
                self.first_ts = ts

    def reassemble(self):
        buf = bytearray()
        checkpoints = []  # (byte_offset, ts) at each accepted segment boundary
        next_seq = None
        for seq, payload, ts in sorted(self.segs, key=lambda s: s[0]):
            if next_seq is None:
                next_seq = seq
            if seq == next_seq:
                checkpoints.append((len(buf), ts))
                buf += payload
                next_seq = (seq + len(payload)) & 0xFFFFFFFF
            elif ((seq - next_seq) & 0xFFFFFFFF) > 0x7FFFFFFF:  # seq < next_seq (overlap/retransmit)
                overlap = (next_seq - seq) & 0xFFFFFFFF
                if overlap < len(payload):
                    checkpoints.append((len(buf), ts))
                    buf += payload[overlap:]
                    next_seq = (seq + len(payload)) & 0xFFFFFFFF
            else:
                break  # gap (missing segment) — stop this direction
        return bytes(buf), checkpoints


def _ts_for_offset(checkpoints, offset):
    if not checkpoints:
        return None
    i = bisect.bisect_right([c[0] for c in checkpoints], offset) - 1
    return checkpoints[max(i, 0)][1]


def _first_frame(stream):
    try:
        rec, total = parse_message(stream, 0, decode_payload=False)
        return rec
    except Exception:
        return None


def _is_ephemeral(port):
    return port >= 32768


# --------------------------------------------------------------------------- #
# top-level: pcap -> capture session
# --------------------------------------------------------------------------- #
def to_session(pcap_path, out_dir, ports=None, label=None):
    directed = {}  # (src,sport,dst,dport) -> DirStream
    for ts, linktype, data in read_packets(pcap_path):
        ipp = _ip_from_link(linktype, data)
        if not ipp:
            continue
        tcp = _tcp_from_ip(*ipp)
        if not tcp or not tcp["payload"]:
            continue
        if ports and tcp["sport"] not in ports and tcp["dport"] not in ports:
            continue
        key = (tcp["src"], tcp["sport"], tcp["dst"], tcp["dport"])
        directed.setdefault(key, DirStream()).add(tcp["seq"], tcp["payload"], ts)

    # pair directed streams into flows
    flows = {}  # frozenset(endpointA, endpointB) -> {"a": (key, DirStream), "b": (...)}
    for key, ds in directed.items():
        src, sport, dst, dport = key
        fk = frozenset(((src, sport), (dst, dport)))
        flows.setdefault(fk, {})[(src, sport)] = (key, ds)

    os.makedirs(out_dir, exist_ok=True)
    frames_path = os.path.join(out_dir, "frames.jsonl")
    conns = {}
    n_frames = 0
    fd = 0
    with open(frames_path, "w", encoding="utf-8") as fout:
        for fk, ends in flows.items():
            items = list(ends.values())
            reassembled = []
            for key, ds in items:
                buf, cps = ds.reassemble()
                reassembled.append((key, buf, cps, ds.first_ts))
            # keep only FPNN-bearing streams
            fpnn = [(k, b, c, t) for (k, b, c, t) in reassembled if b[:4] == TCP_MAGIC]
            if not fpnn:
                continue
            fd += 1
            # decide direction: quest(mtype 0/1) => tx(client), answer(mtype 2) => rx(server)
            tagged = {}
            for key, buf, cps, ts in fpnn:
                rec = _first_frame(buf)
                mt = rec["header"]["mtype"] if rec else None
                tagged[key] = (buf, cps, ts, mt)
            tx_key = rx_key = None
            for key, (buf, cps, ts, mt) in tagged.items():
                if mt in (0, 1) and tx_key is None:
                    tx_key = key
                elif mt == 2 and rx_key is None:
                    rx_key = key
            keys = list(tagged)
            if tx_key is None:  # fall back to server-port heuristic
                tx_key = min(keys, key=lambda k: (_is_ephemeral(k[3]), k[3]))
            if rx_key is None:
                rx_key = next((k for k in keys if k != tx_key), None)

            server_ip, server_port = tx_key[2], tx_key[3]
            conns[str(fd)] = {"peer": {"ip": server_ip, "port": server_port},
                              "lifetime_ms": None}
            for key, (buf, cps, ts, mt) in tagged.items():
                direction = "tx" if key == tx_key else "rx"
                for rec, a, b in iter_stream(buf):
                    if rec.get("desync_skipped"):
                        continue
                    rec["_dir"] = direction
                    rec["_ts"] = _ts_for_offset(cps, a)
                    rec["_fd"] = fd
                    rec["_peer"] = {"ip": server_ip, "port": server_port}
                    rec["_source"] = "pcap"
                    fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    n_frames += 1

    with open(os.path.join(out_dir, "connections.json"), "w", encoding="utf-8") as f:
        json.dump({"label": label or os.path.splitext(os.path.basename(pcap_path))[0],
                   "source": "pcap", "connections": conns}, f, indent=2, ensure_ascii=False)
    return {"pcap": pcap_path, "out": out_dir, "flows": len(conns), "frames": n_frames}


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="vantage protocol from-pcap",
                                 description="Decode FPNN sessions from a pcap/pcapng capture (observation only)")
    ap.add_argument("pcap", help="path to a .pcap or .pcapng file")
    ap.add_argument("--out", default=None, help="output capture-session dir (default: <pcap>.session)")
    ap.add_argument("--label", default=None, help="gameplay label for the session")
    ap.add_argument("--port", type=int, action="append", default=None,
                    help="only consider these TCP ports (repeatable); default: all, FPNN auto-detected")
    args = ap.parse_args(argv)
    out = args.out or (os.path.splitext(args.pcap)[0] + ".session")
    res = to_session(args.pcap, out, ports=set(args.port) if args.port else None, label=args.label)
    print(f"[*] {res['frames']} FPNN frames across {res['flows']} flow(s) -> {res['out']}")
    print(f"[*] next: vantage kb import {res['out']} --version <v> --label {args.label or '<label>'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
