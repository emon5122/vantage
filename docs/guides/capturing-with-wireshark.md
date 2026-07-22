# Guide: capturing FPNN traffic with Wireshark / PCAPdroid

This is the **passive, observation-only** path to decode a Unity IL2CPP app's
FPNN protocol traffic: record your **own** device's packets, then decode the
`.pcap`/`.pcapng` offline with Vantage. It does not touch the process, requires no
root for the FPNN game traffic, and never injects, replays, or modifies anything.

> Only capture traffic you are authorised to — your own device and account.
> Application traffic carried over TLS (e.g. the HTTP/2 login/CDN side) appears as
> ciphertext at the network layer; only the **raw-TCP FPNN** traffic is decodable
> this way. Vantage does not decrypt TLS and does not touch the app's protections.

## 1. Record the traffic

Pick whichever fits your setup:

- **Android, no root — PCAPdroid**: uses the VPN API to record your own traffic
  to a `.pcap`/`.pcapng`. Start capture, play normally, stop, export the file.
- **Rooted device — tcpdump**: `tcpdump -i any -w game.pcap`.
- **Desktop / emulator — Wireshark**: capture on the interface the app uses and
  save as `.pcapng` (the default) or `.pcap`.

Capture during a **single, labelled activity** (e.g. just log in, or just open
mail) so the resulting frames are attributable to that action.

## 2. Decode into a Vantage capture session

```bash
vantage protocol from-pcap game.pcapng --out sessions/login --label login
# only look at specific ports (optional; FPNN is auto-detected by magic otherwise):
vantage protocol from-pcap game.pcapng --out sessions/login --label login --port 13013
```

Vantage will:

1. read the capture (classic pcap **and** pcapng; us/ns timestamps; Ethernet,
   Linux SLL, raw IP, loopback link types; IPv4 + IPv6);
2. **reassemble** each TCP flow (handling out-of-order segments and retransmits);
3. auto-detect FPNN streams by the `FPNN` magic and split them into frames;
4. decode the MessagePack payloads and write a capture session
   (`frames.jsonl` + `connections.json`), preserving **per-frame timestamps** from
   the packets so heartbeat/RTT timing is real.

## 3. Load it into the knowledge base

```bash
vantage kb import sessions/login --version 1.0.0 --label login
vantage kb search field '#1'
vantage kb docs --version 1.0.0
vantage kb serve            # self-contained viewer @ 127.0.0.1:8765
```

Import is idempotent and cumulative: capture more sessions (each labelled by the
action you performed) and the schema confidence climbs `Unknown → Likely →
Verified` automatically — no reverse engineering required.

## Notes & limitations

- **One action per capture** is what makes packets attributable — Vantage does not
  drive the game; you do, by hand.
- **Partial captures** are fine: reassembly stops cleanly at a gap and the framer
  resynchronises on the next `FPNN` magic.
- **TLS traffic** (HTTP/2 login/CDN) is not decodable from a pcap; you would only
  see host/port/size. That is by design — Vantage observes, it does not MITM.
- This path never contacts the game server on your behalf; it only reads a file
  you already recorded.
