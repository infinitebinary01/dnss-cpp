// Lynx DoH DNS Dashboard — SSE + uPlot + direct DOM updates
(function () {
  'use strict';

  var SAMPLE_LIMIT = 120;
  var latHistory = [];
  var timestamps = [];
  var startTime = Date.now();
  var sseOk = false;

  // ---- DOM cache ----
  var $ = function (id) { return document.getElementById(id); };
  var dom = {
    ts:          $('ts'),
    latAvg:      $('lat-avg'),
    latP95:      $('lat-p95'),
    errRate:     $('err-rate'),
    qps:         $('qps'),
    turboHit:    $('turbo-hit'),
    l2Hit:       $('l2-hit'),
    cacheHit:    $('cache-hit'),
    cacheRefresh:$('cache-refresh'),
    connActive:  $('conn-active'),
    connUtil:    $('conn-util'),
    connBar:     $('conn-bar'),
    tunerGrowth: $('tuner-growth'),
    poolPending: $('pool-pending'),
    poolThreads: $('pool-threads'),
    poolBar:     $('pool-bar'),
    tunerConn:   $('tuner-conn'),
    tunerThreads:$('tuner-threads'),
    tunerRefresh:$('tuner-refresh'),
    tunerFanout: $('tuner-fanout'),
    tunerTrend:  $('tuner-trend'),
    sysUptime:   $('sys-uptime'),
    sysQueries:  $('sys-queries'),
    sysMode:     $('sys-mode'),
    upstreamHealth: $('upstream-health')
  };

  function txt(id, val) { var el = dom[id]; if (el) el.textContent = val; }
  function bar(id, w, cls) { var el = dom[id]; if (el) { el.style.width = w; el.className = 'bar-fill ' + cls; } }
  function cls(id, c) { var el = dom[id]; if (el) el.className = c; }

  // ---- uPlot chart ----
  var chartEl = $('chart');
  var uplot;

  function initChart() {
    if (typeof uPlot === 'undefined') {
      $('chart').innerHTML = '<div style="color:#585b70;padding:20px;text-align:center">uPlot not loaded</div>';
      return;
    }
    var opts = {
      width: chartEl.clientWidth || 800,
      height: 130,
      cursor: { show: false },
      select: { show: false },
      legend: { show: true, width: 4 },
      axes: [
        { show: false },
        {
          show: true,
          size: 16,
          values: function (u, vals) {
            return vals.map(function (v) { return v.toFixed(0) + 'ms'; });
          },
          stroke: '#585b70',
          grid: { stroke: 'rgba(49,50,68,.4)', width: 1 }
        }
      ],
      series: [
        { label: 'time', value: '' },
        {
          label: 'AVG',
          stroke: '#a6e3a1',
          width: 1.5,
          fill: 'rgba(166,227,161,.08)',
          points: { show: false }
        },
        {
          label: 'P95',
          stroke: '#f9e2af',
          width: 1,
          fill: 'rgba(249,226,175,.04)',
          points: { show: false }
        }
      ]
    };

    var now = Date.now();
    for (var i = 0; i < SAMPLE_LIMIT; i++) {
      timestamps.push((now - (SAMPLE_LIMIT - i) * 1000) / 1000);
      latHistory.push(0);
    }

    uplot = new uPlot(opts, [
      timestamps.slice(),
      latHistory.slice(),
      latHistory.slice()
    ], chartEl);
  }

  function updateChart(avg, p95) {
    if (!uplot) return;
    latHistory.push(avg);
    if (latHistory.length > SAMPLE_LIMIT) latHistory.shift();
    var n = Date.now() / 1000;
    timestamps.push(n);
    if (timestamps.length > SAMPLE_LIMIT) timestamps.shift();
    uplot.setData([
      timestamps.slice(),
      latHistory.slice(),
      latHistory.map(function () { return p95; })
    ]);
  }

  // ---- Data processor ----
  function processData(d) {
    sseOk = true;
    var avg = d.latency.avg_ms || 0;
    var p95 = d.latency.p95_ms || 0;
    var er = d.errors.rate || 0;
    var hr = d.cache.hit_rate || 0;
    var thr = d.cache.turbo_hit_rate || 0;
    var l2r = Math.max(0, hr * (1 - thr));
    var active = d.connections.active || 0;
    var total = d.connections.recommended || 1;
    var util = d.connections.utilization || 0;
    var pending_t = d.thread_pool.pending || 0;
    var workers = d.thread_pool.workers || 1;
    var threads = d.thread_pool.recommended || 1;
    var refresh = d.auto_tuner.cache_refresh_pct || 0;
    var fanout = d.auto_tuner.fan_out;
    var trend = d.auto_tuner.latency_trend || 0;
    var qps = d.auto_tuner.qps || 0;
    var totalQ = d.auto_tuner.total_queries || 0;
    var elapsed = Math.floor((Date.now() - startTime) / 1000);
    var hh = String(Math.floor(elapsed / 3600)).padStart(2, '0');
    var mm = String(Math.floor((elapsed % 3600) / 60)).padStart(2, '0');
    var ss = String(elapsed % 60).padStart(2, '0');

    // Direct DOM updates
    txt('ts', new Date().toISOString().slice(11, 19));

    txt('latAvg', (avg < 1 ? avg.toFixed(2) : avg.toFixed(1)) + 'ms');
    txt('latP95', (p95 < 1 ? p95.toFixed(2) : p95.toFixed(1)) + 'ms');
    cls('latAvg', avg < 100 ? 'good' : avg < 500 ? 'warn' : 'bad');
    cls('latP95', p95 < 200 ? 'good' : p95 < 1000 ? 'warn' : 'bad');

    txt('errRate', (er * 100).toFixed(2) + '%');
    cls('errRate', er < 0.03 ? 'good' : 'bad');
    txt('qps', qps.toFixed(1) + '/s');

    txt('cacheHit', (hr * 100).toFixed(1) + '%');
    cls('cacheHit', hr > 0.5 ? 'good' : 'warn');
    txt('turboHit', (thr * 100).toFixed(1) + '%');
    cls('turboHit', thr > 0.3 ? 'good' : 'warn');
    txt('l2Hit', (l2r * 100).toFixed(1) + '%');
    cls('l2Hit', l2r > 0.3 ? 'good' : 'warn');
    txt('cacheRefresh', refresh + '%');

    txt('connActive', active + ' / ' + total);
    txt('connUtil', (util * 100).toFixed(1) + '%');
    bar('connBar', Math.min(util * 100, 100) + '%',
      util < 0.7 ? 'bar-good' : util < 0.9 ? 'bar-warn' : 'bar-bad');
    txt('tunerGrowth', d.auto_tuner.connection_growth_per_cycle
      ? '+' + d.auto_tuner.connection_growth_per_cycle + '/cycle' : '--');

    txt('poolPending', pending_t);
    txt('poolThreads', workers);
    bar('poolBar', Math.min(pending_t / workers, 1) * 100 + '%', 'bar-cyan');

    txt('tunerConn', total);
    txt('tunerThreads', threads);
    txt('tunerRefresh', refresh + '%');
    txt('tunerFanout', fanout ? 'ON' : 'OFF');
    cls('tunerFanout', fanout ? 'good' : 'warn');
    txt('tunerTrend', trend.toFixed(1));
    cls('tunerTrend', trend < 5 ? 'good' : 'warn');

    txt('sysUptime', hh + ':' + mm + ':' + ss);
    txt('sysQueries', totalQ.toLocaleString());
    txt('sysMode', 'DoH active');

    var uh = d.upstream_health;
    if (uh) {
      var html = '';
      if (uh.pools && uh.pools.length) {
        for (var i = 0; i < uh.pools.length; i++) {
          var p = uh.pools[i];
          var connClass = p.connected > 0 ? 'good' : 'bad';
          var errClass = p.error_ratio < 10 ? 'good' : p.error_ratio < 30 ? 'warn' : 'bad';
          var label = p.host + ':' + p.port + (p.ip && p.ip != p.host ? ' (' + p.ip + ')' : '');
          html += '<div class="stat-row" style="margin-top:6px"><span>' + label + '</span></div>';
          html += '<div class="stat-row"><span>Connections</span><span class="' + connClass + '">' + p.connected + '/' + p.total + '</span></div>';
          html += '<div class="stat-row"><span>Error Ratio</span><span class="' + errClass + '">' + p.error_ratio + '%</span></div>';
        }
      }
      if (dom.upstreamHealth) dom.upstreamHealth.innerHTML = html;
    }

    updateChart(avg, p95);
  }

  // ---- Matrix rain ----
  var canvas = $('matrix');
  var ctx = canvas.getContext('2d');
  var cols, drops;
  function resizeCanvas() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    cols = Math.floor(canvas.width / 14);
    drops = Array(cols).fill(1);
  }
  resizeCanvas();
  var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<>/{}[]|~';
  function drawMatrix() {
    ctx.fillStyle = 'rgba(30,30,46,0.07)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#a6e3a1';
    ctx.font = '14px monospace';
    for (var i = 0; i < drops.length; i++) {
      ctx.fillText(chars[Math.floor(Math.random() * chars.length)], i * 14, drops[i] * 14);
      if (drops[i] * 14 > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
  }
  setInterval(drawMatrix, 50);
  window.addEventListener('resize', resizeCanvas);

  // ---- SSE (EventSource /api/stream) ----
  function connectSSE() {
    var es = new EventSource('/api/stream');
    es.onmessage = function (evt) {
      try {
        var d = JSON.parse(evt.data);
        processData(d);
      } catch (e) {
        console.warn('SSE parse error:', e);
      }
    };
    es.onerror = function () {
      console.warn('SSE disconnected, browser will auto-reconnect');
    };
    return es;
  }

  // ---- Init ----
  initChart();
  var es = connectSSE();

  window.addEventListener('resize', function () {
    if (uplot && chartEl) {
      uplot.setSize({ width: chartEl.clientWidth || 800, height: 130 });
    }
  });

})();
