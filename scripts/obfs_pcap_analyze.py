#!/usr/bin/env python3
"""Parse an obfs pcap: reassemble the client->server TCP payload to :243, skip the
WS GET upgrade request, then decode the WS frames (junk records + nonce + first
data frame) and print their structure — to spot a framing bug in the client."""
import sys, struct

def read_pcap(path):
    d = open(path, "rb").read()
    magic = d[:4]
    le = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
    endian = "<" if le else ">"
    linktype = struct.unpack(endian + "I", d[20:24])[0]
    off = 24; pkts = []
    while off + 16 <= len(d):
        _ts, _tu, caplen, _orig = struct.unpack(endian + "IIII", d[off:off + 16])
        off += 16
        pkts.append(d[off:off + caplen]); off += caplen
    return linktype, pkts

def parse_pkt(link, p):
    # returns (src_port, dst_port, seq, payload) for TCP, else None
    if link == 113:          # DLT_LINUX_SLL
        if len(p) < 16: return None
        eth = struct.unpack(">H", p[14:16])[0]; l3 = p[16:]
    elif link == 276:        # DLT_LINUX_SLL2
        if len(p) < 20: return None
        eth = struct.unpack(">H", p[0:2])[0]; l3 = p[20:]
    elif link == 1:          # EN10MB
        eth = struct.unpack(">H", p[12:14])[0]; l3 = p[14:]
    else:
        l3 = p; eth = 0x0800
    if eth != 0x0800 or len(l3) < 20: return None
    ihl = (l3[0] & 0xF) * 4
    if l3[9] != 6: return None            # not TCP
    ip_len = struct.unpack(">H", l3[2:4])[0]
    tcp = l3[ihl:ip_len]
    if len(tcp) < 20: return None
    sport, dport = struct.unpack(">HH", tcp[0:4])
    seq = struct.unpack(">I", tcp[4:8])[0]
    doff = (tcp[12] >> 4) * 4
    return sport, dport, seq, tcp[doff:]

def reassemble(link, pkts, dport=243):
    # client->server = dst port 243. Reassemble by seq for the FIRST such stream.
    segs = {}; base = None; first_sport = None
    for p in pkts:
        r = parse_pkt(link, p)
        if not r: continue
        sport, dp, seq, payload = r
        if dp != dport or not payload: continue
        if first_sport is None: first_sport = sport
        if sport != first_sport: continue   # only the first client connection
        if base is None: base = seq
        segs[seq - base] = payload
    out = bytearray()
    for off in sorted(segs):
        if off >= len(out): out += b"\x00" * (off - len(out)) + segs[off]
        else: out[off:off + len(segs[off])] = segs[off]
    return bytes(out)

def decode_ws(buf, label):
    # skip the WS GET request up to \r\n\r\n
    i = buf.find(b"\r\n\r\n")
    print(f"\n=== {label}: client->server, {len(buf)} bytes; GET header ends @ {i} ===")
    if i < 0:
        print("  (no \\r\\n\\r\\n found); first 64 bytes hex:", buf[:64].hex()); return
    print("  GET line:", buf[:buf.find(b'\r\n')].decode('latin1', 'replace')[:80])
    off = i + 4; n = 0
    while off + 2 <= len(buf) and n < 12:
        b0, b1 = buf[off], buf[off + 1]
        fin = b0 >> 7; op = b0 & 0xF; masked = b1 >> 7; l7 = b1 & 0x7F
        hoff = off + 2; ln = l7
        if l7 == 126:
            ln = struct.unpack(">H", buf[hoff:hoff + 2])[0]; hoff += 2
        elif l7 == 127:
            ln = struct.unpack(">Q", buf[hoff:hoff + 8])[0]; hoff += 8
        mask = buf[hoff:hoff + 4] if masked else b""; hoff += 4 if masked else 0
        avail = len(buf) - hoff
        print(f"  frame#{n}: FIN={fin} op=0x{op:x} MASK={masked} len={ln} (payload avail {avail}) hdr[{buf[off:off+2].hex()}]")
        off = hoff + ln; n += 1
        if off > len(buf): print("   !! frame extends past captured data — truncated/desync"); break

if __name__ == "__main__":
    for path in sys.argv[1:]:
        link, pkts = read_pcap(path)
        buf = reassemble(link, pkts)
        decode_ws(buf, path.split("\\")[-1])
