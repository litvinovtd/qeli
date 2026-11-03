#!/usr/bin/env python3
"""Probe an isolated WS listener without authenticating or changing host state."""
import base64
import hashlib
import hmac
import json
import socket
import sys


def main():
    address = (sys.argv[1], int(sys.argv[2]))
    key = hashlib.sha256(b"qeli-obfs-key-v1" + sys.argv[3].encode()).digest()
    prk = hmac.new(bytes(32), key, hashlib.sha256).digest()
    path = "/" + base64.urlsafe_b64encode(hmac.new(prk, b"qeli-ws-path-v1\x01", hashlib.sha256).digest()[:18]).decode().rstrip("=")
    token = "AAAAAAAAAAAAAAAAAAAAAA=="
    head = (f"GET {path} HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {token}\r\n\r\n").encode()
    accept = base64.b64encode(hashlib.sha1((token + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
    results = []

    def exchange(name, request, upgrade, frame=None, eof=False):
        with socket.create_connection(address, timeout=3) as connection:
            connection.settimeout(3)
            connection.sendall(request)
            response = bytearray()
            try:
                while not response.endswith(b"\r\n\r\n") and len(response) <= 4096:
                    byte = connection.recv(1)
                    if not byte:
                        break
                    response += byte
            except ConnectionResetError:
                pass
            assert response.startswith(b"HTTP/1.1 101 ") == upgrade, (name, bytes(response))
            if upgrade:
                assert b"\r\nSec-WebSocket-Accept: " + accept + b"\r\n" in response, name
            if frame is not None:
                connection.sendall(frame)
                if eof:
                    connection.shutdown(socket.SHUT_WR)
                try:
                    assert connection.recv(1) == b"", name
                except ConnectionResetError:
                    pass
        results.append(name)

    exchange("valid-upgrade", head, True)
    exchange("zero-body", head[:-2] + b"Content-Length: 0\r\n\r\n", True)
    mutations = {
        "missing-host": head.replace(b"Host: example.com\r\n", b""),
        "missing-version": head.replace(b"Sec-WebSocket-Version: 13\r\n", b""),
        "wrong-version": head.replace(b"Version: 13", b"Version: 12"),
        "wrong-http": head.replace(b"HTTP/1.1", b"HTTP/1.0"),
        "extra-request-field": head.replace(b"HTTP/1.1", b"HTTP/1.1 extra"),
        "space-before-colon": head.replace(b"Upgrade:", b"Upgrade :"),
        "folded-header": head.replace(b"Host:", b" Host:"),
        "control-in-value": head.replace(b"example.com", b"example\0.com"),
        "duplicate-host": head[:-2] + b"Host: other\r\n\r\n",
        "duplicate-key": head[:-2] + f"Sec-WebSocket-Key: {token}\r\n\r\n".encode(),
        "duplicate-version": head[:-2] + b"Sec-WebSocket-Version: 13\r\n\r\n",
        "body": head[:-2] + b"Content-Length: 1\r\n\r\n",
        "transfer-encoding": head[:-2] + b"Transfer-Encoding: chunked\r\n\r\n",
    }
    for name, request in mutations.items():
        exchange(name, request, False)
    for length in (4096, 4097):
        padded = head[:-2] + b"X-Pad: " + b"x" * (length-len(head)-9) + b"\r\n\r\n"
        assert len(padded) == length
        exchange(f"head-{length}", padded, length == 4096)
    # Client directions are masked. Both forms improperly encode a one-byte nonce frame.
    for name, prefix in (("nonminimal-u16", b"\x82\xfe\0\x01"),
                         ("nonminimal-u64", b"\x82\xff" + (1).to_bytes(8, "big"))):
        exchange(name, head, True, prefix + b"\0\0\0\0x")
    exchange("unfinished-fragment-eof", head, True, b"\x02\x81\0\0\0\0x", True)
    def masked_frame(opcode, payload):
        assert len(payload) <= 125
        return bytes([0x80 | opcode, 0x80 | len(payload)]) + bytes(4) + payload

    def exact(connection, length):
        output = bytearray()
        while len(output) < length:
            part = connection.recv(length-len(output))
            assert part, "unexpected EOF"
            output.extend(part)
        return bytes(output)

    def control_exchange(name, payload, close=False, nonce=False, reject=False, after=False):
        with socket.create_connection(address, timeout=3) as connection:
            connection.settimeout(3)
            connection.sendall(head)
            response = bytearray()
            while not response.endswith(b"\r\n\r\n"):
                response.extend(exact(connection, 1))
                assert len(response) <= 4096
            assert response.startswith(b"HTTP/1.1 101 "), name
            if nonce:
                connection.sendall(masked_frame(2, bytes(12)))
                assert exact(connection, 2) == b"\x82\x0c", name
                exact(connection, 12)
            frame = masked_frame(8 if close else 9, payload)
            if after:
                frame += masked_frame(2, b"after-close")
            connection.sendall(frame)
            if reject:
                try:
                    assert connection.recv(1) == b"", name
                except ConnectionResetError:
                    pass
            else:
                assert exact(connection, 2) == bytes([0x88 if close else 0x8a,len(payload)]), name
                assert exact(connection, len(payload)) == payload, name
                if close:
                    assert connection.recv(1) == b"", name
        results.append(name)

    control_exchange("nonce-idle-ping-empty", b"")
    control_exchange("nonce-idle-ping-max", bytes(range(125)))
    control_exchange("pq-idle-ping", b"ping", nonce=True)
    for code in (None,1000,1014,3000,4999):
        payload = b"" if code is None else code.to_bytes(2,"big") + "bye \u043c\u0438\u0440".encode()
        control_exchange(f"valid-close-{code}",payload,close=True)
    for name,payload in (("one-byte",b"x"),("reserved",(1005).to_bytes(2,"big")),("invalid-utf8",b"\x03\xe8\xff")):
        control_exchange("invalid-close-"+name,payload,close=True,reject=True)
    control_exchange("pq-close-discards-later-data",b"\x03\xe8bye",close=True,nonce=True,after=True)
    print(json.dumps({"status": "PASS", "checks_passed": len(results), "cases": results}))


if __name__ == "__main__":
    main()
