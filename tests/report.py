#!/usr/bin/env python3
"""Generate a professional HTML test report from JSON results."""

import json, os, subprocess, sys
from datetime import datetime

REPORT_HTML = "/home/dustinkarash/Desktop/dnss_mine/dnss-cpp/tests/test-report.html"

def load_results():
    suites = []
    for fname in ['/tmp/lynx-test-functional.json',
                  '/tmp/lynx-test-performance.json',
                  '/tmp/lynx-test-resilience.json']:
        if os.path.exists(fname):
            with open(fname) as f:
                suites.append(json.load(f))
    return suites

def stats_from_monitor():
    import urllib.request
    try:
        resp = urllib.request.urlopen('http://127.0.0.1:8085/api/stats', timeout=5)
        return json.loads(resp.read().decode())
    except:
        return {}

def latency_bars(lat):
    """Return colored bar CSS width percentage."""
    if not lat:
        return '<span class="dim">N/A</span>'
    avg = lat.get('avg_ms', 0)
    cls = 'green' if avg < 10 else 'yellow' if avg < 50 else 'red'
    return f'<span class="latency {cls}">{avg}ms avg</span>'

def gen_html(suites, monitor):
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    total_tests = sum(s['total'] for s in suites)
    total_passed = sum(s['passed'] for s in suites)
    total_failed = sum(s['failed'] for s in suites)
    all_pass = total_failed == 0
    overall = 'PASS' if all_pass else 'FAIL'

    mon = monitor or {}

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Lynx DNS — Test Report</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, sans-serif;
    background: #0f1117; color: #e1e4eb; padding: 2rem; line-height: 1.6;
  }}
  h1, h2, h3 {{ font-weight: 600; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.25rem; }}
  h2 {{ font-size: 1.3rem; margin: 1.5rem 0 0.75rem; color: #9aa0b0; }}
  .subtitle {{ color: #6b7280; margin-bottom: 1.5rem; }}

  .summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px,1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .card {{
    background: #1a1d27; border-radius: 12px; padding: 1.25rem;
    border: 1px solid #2a2d37;
  }}
  .card .label {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: #6b7280; }}
  .card .value {{ font-size: 1.8rem; font-weight: 700; margin-top: 0.25rem; }}
  .card.pass .value {{ color: #34d399; }}
  .card.fail .value {{ color: #f87171; }}
  .card.neutral .value {{ color: #e1e4eb; }}

  .status-badge {{
    display: inline-block; padding: 0.2rem 0.75rem; border-radius: 999px;
    font-size: 0.75rem; font-weight: 600; text-transform: uppercase;
  }}
  .badge-pass {{ background: #065f46; color: #6ee7b7; }}
  .badge-fail {{ background: #7f1d1d; color: #fca5a5; }}

  table {{
    width: 100%; border-collapse: collapse; margin: 0.5rem 0 1.5rem;
    background: #1a1d27; border-radius: 12px; overflow: hidden;
  }}
  th {{
    text-align: left; padding: 0.75rem 1rem; font-size: 0.7rem;
    text-transform: uppercase; letter-spacing: 0.05em; color: #6b7280;
    background: #13161f; border-bottom: 1px solid #2a2d37;
  }}
  td {{ padding: 0.65rem 1rem; border-bottom: 1px solid #22252f; font-size: 0.9rem; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #22252f; }}

  .pass-dot {{ display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 0.5rem; }}
  .dot-green {{ background: #34d399; }}
  .dot-red {{ background: #f87171; }}

  .latency {{ font-weight: 600; }}
  .latency.green {{ color: #34d399; }}
  .latency.yellow {{ color: #fbbf24; }}
  .latency.red {{ color: #f87171; }}

  .progress-bar {{
    width: 100%; height: 6px; background: #2a2d37; border-radius: 3px; margin-top: 0.25rem;
  }}
  .progress-fill {{
    height: 100%; border-radius: 3px; transition: width 0.3s;
  }}
  .fill-green {{ background: #34d399; }}
  .fill-red {{ background: #f87171; }}

  .detail {{ color: #6b7280; font-size: 0.8rem; }}

  .suite-section {{ margin-bottom: 1rem; }}

  .data-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(200px,1fr)); gap: 0.5rem;
    margin: 0.5rem 0 1rem;
  }}
  .data-item {{ background: #13161f; padding: 0.5rem 0.75rem; border-radius: 6px; }}
  .data-item .k {{ font-size: 0.65rem; text-transform: uppercase; color: #6b7280; }}
  .data-item .v {{ font-size: 0.95rem; font-weight: 600; }}
</style>
</head>
<body>

<h1>Lynx DNS — Test Report</h1>
<p class="subtitle">Generated: {ts} &middot; Server: 127.0.0.1:5353</p>

<div class="summary-cards">
  <div class="card pass">
    <div class="label">Overall</div>
    <div class="value"><span class="status-badge badge-{"pass" if all_pass else "fail"}">{overall}</span></div>
  </div>
  <div class="card pass">
    <div class="label">Tests Passed</div>
    <div class="value">{total_passed}<span class="detail">/{total_tests}</span></div>
    <div class="progress-bar"><div class="progress-fill fill-green" style="width:{total_passed/total_tests*100 if total_tests else 0}%"></div></div>
  </div>
  <div class="card fail">
    <div class="label">Tests Failed</div>
    <div class="value">{total_failed}</div>
  </div>
  <div class="card neutral">
    <div class="label">Suites</div>
    <div class="value">{len(suites)}</div>
  </div>
</div>
'''

    if mon:
        err_rate = round(mon.get('errors', {}).get('rate', 0) * 100, 1)
        lat = mon.get('latency', {})
        cache = mon.get('cache', {})
        conns = mon.get('connections', {})
        upstream = mon.get('upstream_health', {}).get('pools', [])
        pending = mon.get('thread_pool', {}).get('pending', 0)

        html += '<h2>Live Server Status</h2>\n<div class="data-grid">\n'
        html += f'  <div class="data-item"><div class="k">Error Rate</div><div class="v" style="color:{"#34d399" if err_rate==0 else "#f87171"}">{err_rate}%</div></div>\n'
        html += f'  <div class="data-item"><div class="k">Latency (avg/p95)</div><div class="v">{lat.get("avg_ms","?")}ms / {lat.get("p95_ms","?")}ms</div></div>\n'
        html += f'  <div class="data-item"><div class="k">Cache Hit Rate</div><div class="v">{cache.get("hit_rate",0)*100:.0f}%</div></div>\n'
        html += f'  <div class="data-item"><div class="k">Connections</div><div class="v">{conns.get("active",0)} active / {conns.get("recommended",0)} recommended</div></div>\n'
        html += f'  <div class="data-item"><div class="k">Thread Pool</div><div class="v">{pending} pending</div></div>\n'

        for p in upstream:
            er = round(p.get('error_ratio', 0) * 100, 1)
            ec = 'green' if er == 0 else 'yellow' if er < 5 else 'red'
            html += f'  <div class="data-item"><div class="k">Upstream</div><div class="v">{p["host"]} <span class="latency {ec}">{er}% err</span></div></div>\n'
        html += '</div>\n'

    for suite in suites:
        html += f'<h2>{suite["suite"]}</h2>\n'
        html += '<table>\n<thead><tr><th style="width:30px"></th><th>Test</th><th>Result</th></tr></thead>\n<tbody>\n'
        for t in suite['tests']:
            dot = 'dot-green' if t['passed'] else 'dot-red'
            detail = t.get('detail', '')
            # For performance tests, show extra data
            data_html = ''
            if 'data' in t and isinstance(t['data'], dict):
                d = t['data']
                parts = []
                for k in ['avg_ms', 'p95_ms', 'qps', 'error_rate', 'min_ms', 'max_ms']:
                    if k in d and d[k] is not None:
                        label = k.replace('_', ' ')
                        parts.append(f'{label}: {d[k]}')
                if parts:
                    data_html = '<br><span class="detail">' + ' | '.join(parts) + '</span>'
            html += f'<tr><td><span class="pass-dot {dot}"></span></td>'
            html += f'<td>{t["name"]}</td>'
            html += f'<td>{"PASS" if t["passed"] else "FAIL"}{" — " + detail if detail else ""}{data_html}</td></tr>\n'
        html += '</tbody>\n</table>\n'

    html += '''
<div style="margin-top: 3rem; text-align: center; color: #4b5563; font-size: 0.8rem;">
  Lynx DNS Test Suite &mdash; Generated by test runner
</div>
</body>
</html>'''

    with open(REPORT_HTML, 'w') as f:
        f.write(html)
    print(f"Report written to {REPORT_HTML}")
    return REPORT_HTML

def main():
    suites = load_results()
    if not suites:
        print("No test results found. Run tests first.")
        sys.exit(1)
    monitor = stats_from_monitor()
    path = gen_html(suites, monitor)

    # Try to open in browser
    try:
        subprocess.run(['xdg-open', path], timeout=2)
    except:
        pass

if __name__ == '__main__':
    main()
