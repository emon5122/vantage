"""
fpnn_frame.py — FPNN wire-frame parser (observation/decoding only).

FPNN (github.com/highras/fpnn) is an OPEN protocol; applications that embed the FPNN C# SDK
(com.fpnn.*, verified in Phase 4). The framing below is transcribed from the
public FPNN protocol / SDK layout. Each parsed field carries a `confidence`:
  - "spec"  : defined by the public FPNN standard (structural certainty)
  - "observed": confirmed against captured bytes (magic matched, sizes consistent)
This parser NEVER modifies bytes; it splits a captured TCP byte-stream into FPNN
messages and decodes the MessagePack payload.

FPNN TCP message layout (little-endian sizes):
  offset size field      notes
  0      4    magic      "FPNN" (TCP) = 0x46 0x50 0x4E 0x4E ; "FUNN" for UDP
  4      1    version    typically 0x01
  5      1    flag       bit7 0x80 = FLAG_MSGPACK, bit6 0x40 = FLAG_JSON, others reserved/zip
  6      1    mtype      0=one-way quest, 1=two-way quest, 2=answer
  7      1    ss         quest: method-name length ; answer: status (0=ok, else error)
  8      4    psize      payload size (LE)
  --- header end (12 bytes) ---
  12     4    seqNum     sequence / quest-id (LE)   [present for two-way quest & answer;
                         for one-way quest, presence is spec-confirm-by-capture]
  16     ss   method     quest only: the FPNN interface/method name (UTF-8)
  ..     psize payload   MessagePack (if FLAG_MSGPACK) or JSON map
"""
import struct

from vantage.protocol.msgpack import decode as mp_decode, MsgpackError, to_jsonable

TCP_MAGIC = b"FPNN"
UDP_MAGIC = b"FUNN"
FLAG_MSGPACK = 0x80
FLAG_JSON = 0x40
MTYPE = {0: "oneway_quest", 1: "twoway_quest", 2: "answer"}
HEADER_LEN = 12


class FpnnParseError(Exception):
    pass


def looks_like_fpnn(buf):
    return len(buf) >= 4 and (buf[:4] == TCP_MAGIC or buf[:4] == UDP_MAGIC)


def parse_header(buf, off=0):
    if off + HEADER_LEN > len(buf):
        return None
    magic = bytes(buf[off:off + 4])
    if magic not in (TCP_MAGIC, UDP_MAGIC):
        raise FpnnParseError(f"bad magic {magic!r} at {off}")
    version = buf[off + 4]
    flag = buf[off + 5]
    mtype = buf[off + 6]
    ss = buf[off + 7]
    psize = struct.unpack_from("<I", buf, off + 8)[0]
    return {
        "magic": magic.decode("latin1"),
        "transport": "tcp" if magic == TCP_MAGIC else "udp",
        "version": version,
        "flag": flag,
        "flag_msgpack": bool(flag & FLAG_MSGPACK),
        "flag_json": bool(flag & FLAG_JSON),
        "mtype": mtype,
        "mtype_name": MTYPE.get(mtype, f"unknown({mtype})"),
        "ss": ss,
        "psize": psize,
    }


def frame_total_len(hdr):
    """Total bytes of one message given a parsed header (spec layout)."""
    is_quest = hdr["mtype"] in (0, 1)
    has_seq = hdr["mtype"] in (1, 2) or hdr["mtype"] == 0  # spec: seq present; confirm by capture
    total = HEADER_LEN
    total += 4 if has_seq else 0
    if is_quest:
        total += hdr["ss"]  # method name
    total += hdr["psize"]
    return total, has_seq, is_quest


def parse_message(buf, off=0, decode_payload=True):
    """Parse a single FPNN message starting at off. Returns (record, consumed)."""
    hdr = parse_header(buf, off)
    if hdr is None:
        return None, 0
    total, has_seq, is_quest = frame_total_len(hdr)
    if off + total > len(buf):
        return None, 0  # incomplete — need more stream bytes

    p = off + HEADER_LEN
    seq = None
    if has_seq:
        seq = struct.unpack_from("<I", buf, p)[0]; p += 4
    method = None
    if is_quest:
        method = bytes(buf[p:p + hdr["ss"]]).decode("utf-8", "replace"); p += hdr["ss"]
    payload_raw = bytes(buf[p:p + hdr["psize"]]); p += hdr["psize"]

    rec = {
        "header": hdr,
        "seq": seq,
        "method": method,
        "status": hdr["ss"] if hdr["mtype"] == 2 else None,
        "payload_len": hdr["psize"],
        "payload_hex_head": payload_raw[:24].hex(),
        "confidence": {
            "framing": "spec",           # FPNN public standard
            "magic_matched": True,       # magic validated above
            "payload_encoding": "msgpack" if hdr["flag_msgpack"] else ("json" if hdr["flag_json"] else "unknown"),
        },
    }
    if decode_payload and payload_raw:
        if hdr["flag_msgpack"]:
            try:
                val, tnode, consumed = mp_decode(payload_raw, 0)
                rec["payload"] = to_jsonable(val)
                rec["payload_types"] = tnode
                rec["payload_trailing"] = len(payload_raw) - consumed
                rec["confidence"]["payload_decoded"] = "observed"
            except MsgpackError as e:
                rec["payload_error"] = str(e)
                rec["confidence"]["payload_decoded"] = "failed"
        elif hdr["flag_json"]:
            try:
                import json
                rec["payload"] = json.loads(payload_raw.decode("utf-8"))
                rec["confidence"]["payload_decoded"] = "observed"
            except Exception as e:
                rec["payload_error"] = str(e)
    return rec, total


def iter_stream(buf, off=0):
    """Yield (record, start_off, end_off) for every complete FPNN message in a
    reassembled TCP byte-stream. Stops at the first incomplete/desynced frame,
    returning the leftover offset so the caller can append more bytes."""
    pos = off
    while pos < len(buf):
        if not looks_like_fpnn(buf[pos:pos + 4]):
            # resynchronise: scan forward to next magic (stream desync / partial)
            nxt = _find_next_magic(buf, pos + 1)
            if nxt is None:
                break
            yield {"desync_skipped": nxt - pos, "at": pos}, pos, nxt
            pos = nxt
            continue
        try:
            rec, total = parse_message(buf, pos)
        except FpnnParseError:
            nxt = _find_next_magic(buf, pos + 1)
            if nxt is None:
                break
            pos = nxt
            continue
        if rec is None or total == 0:
            break  # incomplete — need more bytes
        yield rec, pos, pos + total
        pos += total
    return


def _find_next_magic(buf, start):
    i = buf.find(TCP_MAGIC, start)
    j = buf.find(UDP_MAGIC, start)
    cands = [x for x in (i, j) if x != -1]
    return min(cands) if cands else None
