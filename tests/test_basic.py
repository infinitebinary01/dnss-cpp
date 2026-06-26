#!/usr/bin/env python3
"""Integration tests for dnss-cpp"""
import socket
import struct
import time
import subprocess
import sys
import os

DNS_PORT = 8055
MON_PORT = 8087
BINARY = os.path.join(os.path.dirname(__file__), '..', 'build', 'dnss')

def build_dns_query(domain, qtype=1):
    tid = 0x1234
    header = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    labels = [len(p) for p in domain.encode().split(b'.')]
    qname = b''
    for i, p in enumerate(domain.encode().split(b'.')):
        qname += bytes([labels[i]]) + p
    qname += b'\x00'
    qtype_qclass = struct.pack('>HH', qtype, 1)
    return header + qname + qtype_qclass

def parse_dns_response(data):
    if len(data) < 12:
        return None
    header = struct.unpack('>HHHHHH', data[:12])
    return {
        'id': header[0],
        'flags': header[1],
        'qdcount': header[2],
        'ancount': header[3],
        'nscount': header[4],
        'arcount': header[5],
        'rcode': header[1] & 0x0f,
    }

def test_udp_query():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    query = build_dns_query('google.com', 1)
    sock.sendto(query, ('127.0.0.1', DNS_PORT))
    data, _ = sock.recvfrom(4096)
    resp = parse_dns_response(data)
    assert resp is not None, "No response"
    assert resp['rcode'] == 0, f"RCODE != 0: {resp['rcode']}"
    assert resp['ancount'] > 0, f"No answer records: {resp['ancount']}"
    print(f"OK: google.com A -> {resp['ancount']} answers, rcode={resp['rcode']}")
    sock.close()

def test_udp_aaaa():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    query = build_dns_query('google.com', 28)
    sock.sendto(query, ('127.0.0.1', DNS_PORT))
    data, _ = sock.recvfrom(4096)
    resp = parse_dns_response(data)
    assert resp is not None, "No response"
    if resp['ancount'] > 0:
        print(f"OK: google.com AAAA -> {resp['ancount']} answers")
    else:
        print(f"OK: google.com AAAA -> no AAAA records (valid response)")
    sock.close()

def test_nxdomain():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    query = build_dns_query('nonexistent-domain-xyzzy-12345.test', 1)
    sock.sendto(query, ('127.0.0.1', DNS_PORT))
    data, _ = sock.recvfrom(4096)
    resp = parse_dns_response(data)
    assert resp is not None, "No response"
    assert resp['rcode'] == 3, f"Expected NXDOMAIN, got rcode={resp['rcode']}"
    print(f"OK: NXDOMAIN correctly returned")
    sock.close()

def test_monitoring_api():
    import http.client
    conn = http.client.HTTPConnection('127.0.0.1', MON_PORT, timeout=5)
    conn.request('GET', '/api/stats')
    resp = conn.getresponse()
    assert resp.status == 200, f"API returned {resp.status}"
    data = resp.read().decode()
    assert 'errorRate' in data, f"Missing errorRate in: {data[:200]}"
    print(f"OK: monitoring API responds ({len(data)} bytes)")
    conn.close()

if __name__ == '__main__':
    tests = [test_udp_query, test_udp_aaaa, test_nxdomain, test_monitoring_api]
    failed = 0
    for t in tests:
        try:
            t()
        except Exception as e:
            print(f"FAIL: {t.__name__}: {e}", file=sys.stderr)
            failed += 1

    if failed:
        print(f"\n{len(tests) - failed}/{len(tests)} passed, {failed} failed")
        sys.exit(1)
    else:
        print(f"\n{len(tests)}/{len(tests)} tests passed")
