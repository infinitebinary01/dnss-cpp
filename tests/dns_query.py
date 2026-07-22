import socket
import struct
import random
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_PORT = 5353

def build_dns_query(domain, qtype=1):
    tid = random.randint(0, 0xFFFF)
    flags = 0x0100  # standard query, recursion desired
    qdcount = 1
    header = struct.pack('>HHHHHH', tid, flags, qdcount, 0, 0, 0)
    qname = b''
    for part in domain.encode().split(b'.'):
        qname += bytes([len(part)]) + part
    qname += b'\x00'
    question = qname + struct.pack('>HH', qtype, 1)
    return header + question

def parse_dns_response(data):
    if len(data) < 12:
        return None, None, None
    tid, flags, qdcount, ancount, _, _ = struct.unpack('>HHHHHH', data[:12])
    rcode = flags & 0x0F
    answers = []
    offset = 12
    for _ in range(qdcount):
        while offset < len(data) and data[offset] != 0:
            offset += data[offset] + 1
        offset += 5
    for _ in range(ancount):
        if offset >= len(data):
            break
        if data[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while offset < len(data) and data[offset] != 0:
                offset += data[offset] + 1
            offset += 1
        if offset + 10 > len(data):
            break
        atype, aclass, ttl, rdlength = struct.unpack('>HHIH', data[offset:offset+10])
        offset += 10
        if offset + rdlength > len(data):
            break
        rdata = data[offset:offset+rdlength]
        offset += rdlength
        if atype == 1 and rdlength == 4:
            answers.append(('.'.join(str(b) for b in rdata), 'A'))
        elif atype == 28 and rdlength == 16:
            ipv6 = ':'.join(f'{b[0]:02x}{b[1]:02x}' for b in (rdata[i:i+2] for i in range(0, 16, 2)))
            answers.append((ipv6, 'AAAA'))
        elif atype == 5:
            name = decode_name(data, offset - rdlength - 10, data)
            answers.append((name, 'CNAME'))
    return tid, rcode, answers

def decode_name(data, start, msg):
    parts = []
    pos = start
    while pos < len(data):
        if data[pos] == 0:
            pos += 1
            break
        if data[pos] & 0xC0 == 0xC0:
            ptr = ((data[pos] & 0x3F) << 8) | data[pos + 1]
            parts.extend(decode_name(msg, ptr, msg).split('.'))
            pos += 2
            break
        length = data[pos]
        pos += 1
        if pos + length > len(data):
            break
        parts.append(data[pos:pos+length].decode())
        pos += length
    return '.'.join(parts)

def query_dns(domain, qtype=1, server='127.0.0.1', port=DEFAULT_PORT, timeout=5, use_tcp=False):
    qdata = build_dns_query(domain, qtype)
    t0 = time.time()
    if use_tcp:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((server, port))
            sock.sendall(struct.pack('>H', len(qdata)) + qdata)
            raw = b''
            while len(raw) < 2:
                chunk = sock.recv(2 - len(raw))
                if not chunk:
                    break
                raw += chunk
            if len(raw) < 2:
                sock.close()
                return None, time.time() - t0
            rlen = struct.unpack('>H', raw)[0]
            resp = b''
            while len(resp) < rlen:
                chunk = sock.recv(rlen - len(resp))
                if not chunk:
                    break
                resp += chunk
            sock.close()
            if len(resp) < 12:
                return None, time.time() - t0
            tid, rcode, _ = parse_dns_response(resp)
            return rcode, time.time() - t0
        except Exception:
            sock.close()
            return None, time.time() - t0
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(qdata, (server, port))
            resp, _ = sock.recvfrom(4096)
            sock.close()
            if len(resp) < 12:
                return None, time.time() - t0
            tid, rcode, _ = parse_dns_response(resp)
            return rcode, time.time() - t0
        except Exception:
            sock.close()
            return None, time.time() - t0

def run_load_test(domains, server='127.0.0.1', port=DEFAULT_PORT,
                  concurrency=10, queries_per_domain=5, qtype=1,
                  timeout=5, use_tcp=False):
    results = []
    errors = 0
    total = 0
    wall_start = time.time()
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        fut_to_domain = {}
        for domain in domains:
            for _ in range(queries_per_domain):
                f = ex.submit(query_dns, domain, qtype, server, port, timeout, use_tcp)
                fut_to_domain[f] = domain
                total += 1
        for f in as_completed(fut_to_domain):
            rcode, elapsed = f.result()
            if rcode is None or (rcode != 0 and rcode != 3):
                errors += 1
            results.append(elapsed)
    wall_time = time.time() - wall_start
    if not results:
        return {'avg_ms': 0, 'p95_ms': 0, 'p99_ms': 0, 'qps': 0,
                'total': 0, 'errors': 0, 'error_rate': 0, 'min_ms': 0, 'max_ms': 0}
    results.sort()
    n = len(results)
    avg = sum(results) / n * 1000
    p95 = results[int(n * 0.95)] * 1000
    p99 = results[int(n * 0.99)] * 1000
    minv = results[0] * 1000
    maxv = results[-1] * 1000
    qps = total / wall_time if wall_time > 0 else 0
    return {
        'avg_ms': round(avg, 2),
        'p95_ms': round(p95, 2),
        'p99_ms': round(p99, 2),
        'min_ms': round(minv, 2),
        'max_ms': round(maxv, 2),
        'qps': round(qps, 1),
        'total': total,
        'errors': errors,
        'error_rate': round(errors / total * 100, 2) if total else 0,
    }

def print_results(label, r):
    print(f"  {label}:")
    print(f"    Total: {r['total']} queries, {r['errors']} errors ({r['error_rate']}%)")
    print(f"    QPS: {r['qps']}")
    print(f"    Latency: avg={r['avg_ms']}ms  p95={r['p95_ms']}ms  p99={r['p99_ms']}ms  min={r['min_ms']}ms  max={r['max_ms']}ms")
