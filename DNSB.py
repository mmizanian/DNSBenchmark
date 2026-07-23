#!/usr/bin/env python3
"""
DNS Benchmark - A GUI application to benchmark public DNS servers,
detect DNS hijacking, and change the system DNS on Windows.
"""

import asyncio
import ipaddress
import json
import random
import re
import statistics
import string
import subprocess
import threading
import time
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Any, Dict, List, Optional, Tuple

import dns.asyncquery
import dns.asyncresolver
import dns.message
import dns.resolver

import ctypes

CONFIG_PATH = Path("config.json")
ALL_ADAPTERS_NAME = "All adapters"
SCAN_MAX_HOSTS = 512


@dataclass
class DNSServer:
    id: str
    name: str
    primary: str
    secondary: str = ""
    port: int = 53

    @property
    def address_string(self) -> str:
        return f"{self.primary}:{self.port}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "primary": self.primary,
            "secondary": self.secondary,
            "port": self.port,
        }

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "DNSServer":
        return cls(**value)


DEFAULT_DNS_SERVERS = [
    DNSServer("cf_standard", "Cloudflare", "1.1.1.1", "1.0.0.1"),
    DNSServer("cf_security", "Cloudflare Security", "1.1.1.2", "1.0.0.2"),
    DNSServer("google", "Google Public DNS", "8.8.8.8", "8.8.4.4"),
    DNSServer("opendns", "OpenDNS (Cisco)", "208.67.222.222", "208.67.220.220"),
    DNSServer("level3", "Lumen / Level3", "4.2.2.1", "4.2.2.2"),
    DNSServer("lumen_alt", "Lumen (Alternative)", "209.244.0.3", "209.244.0.4"),
    DNSServer("verisign", "Verisign", "64.6.64.6", "64.6.65.6"),
    DNSServer("he", "Hurricane Electric", "74.82.42.42", ""),
    DNSServer("dyn", "Oracle Dyn", "216.146.35.35", "216.146.36.36"),
    DNSServer("neustar", "Neustar UltraDNS", "156.154.70.1", "156.154.71.1"),
    DNSServer("quad9_secured", "Quad9 (Secured)", "9.9.9.9", "149.112.112.112"),
    DNSServer("quad9_unsecured", "Quad9 Unsecured", "9.9.9.10", "149.112.112.10"),
    DNSServer("controld_malware", "Control D Malware", "76.76.2.1", "76.76.10.1"),
    DNSServer("controld", "Control D Unfiltered", "76.76.2.0", "76.76.10.0"),
    DNSServer("cleanbrowsing", "CleanBrowsing Security", "185.228.168.9", "185.228.169.9"),
    DNSServer("dns0_eu", "dns0.eu ZERO", "193.110.81.0", "185.253.5.0"),
    DNSServer("comodo", "Comodo Secure DNS", "8.26.56.26", "8.20.247.20"),
    DNSServer("neustar_threat", "Neustar Threat", "156.154.70.2", "156.154.71.2"),
    DNSServer("yandex_safe", "Yandex Safe", "77.88.8.88", "77.88.8.2"),
    DNSServer("safedns", "SafeDNS", "195.46.39.39", "195.46.39.40"),
    DNSServer("adguard", "AdGuard DNS", "94.140.14.140", "94.140.14.141"),
    DNSServer("adguard_default", "AdGuard Default", "94.140.14.14", "94.140.15.15"),
    DNSServer("mullvad", "Mullvad Base", "194.242.2.2", "194.242.2.3"),
    DNSServer("nextdns", "NextDNS Anycast", "45.90.28.0", "45.90.30.0"),
    DNSServer("dns_watch", "DNS.WATCH", "84.200.69.80", "84.200.70.40"),
    DNSServer("uncensored", "UncensoredDNS", "91.239.100.100", "89.233.43.71"),
    DNSServer("dnssb", "DNS.SB", "185.222.222.222", "185.184.222.222"),
    DNSServer("libredns", "LibreDNS", "116.202.176.26", ""),
    DNSServer("dnsforge", "DNSForge", "217.147.219.50", "217.147.219.51"),
    DNSServer("applied_privacy", "Applied Privacy DNS", "146.255.56.98", "146.255.56.99"),
    DNSServer("aha_dns", "AhaDNS Unfiltered", "45.67.219.208", "45.67.219.209"),
    DNSServer("switch_ch", "Switch.ch", "130.59.31.251", "130.59.31.250"),
    DNSServer("fdn_france", "FDN France", "80.67.169.12", "80.67.169.40"),
    DNSServer("ccc", "Chaos Computer Club (CCC)", "178.63.26.173", ""),
    DNSServer("alidns", "AliDNS (Alibaba)", "223.5.5.5", "223.6.6.6"),
    DNSServer("dnspod", "DNSPod (Tencent)", "119.29.29.29", "1.12.12.12"),
    DNSServer("114dns", "114DNS", "114.114.114.114", "114.114.115.115"),
    DNSServer("baidu", "Baidu DNS", "180.76.76.76", ""),
    DNSServer("twnic", "TWNIC Quad101", "101.101.101.101", "101.102.103.104"),
    DNSServer("yandex_basic", "Yandex Basic", "77.88.8.8", "77.88.8.1"),
    DNSServer("freedns", "FreeDNS", "37.235.1.174", "37.235.1.177"),
    DNSServer("alternate_dns", "Alternate DNS", "76.76.19.19", "76.223.122.150"),
]

DEFAULT_TEST_DOMAINS = [
    "google.com",
    "bing.com",
    "wikipedia.org",
    "github.com",
    "stackoverflow.com",
    "amazon.com",
    "reddit.com",
    "youtube.com",
]

DEFAULT_SCAN_RANGES = [
    "2.176.0.0/12",
    "5.22.0.0/15",
    "5.52.0.0/14",
    "5.106.0.0/15",
    "5.112.0.0/12",
    "5.160.0.0/11",
    "5.200.0.0/13",
    "5.208.0.0/14",
    "5.232.0.0/13",
    "10.202.0.0/16",
    "31.2.0.0/15",
    "31.56.0.0/14",
    "37.114.0.0/15",
    "37.152.0.0/14",
    "37.156.0.0/14",
    "37.202.0.0/15",
    "37.255.0.0/16",
    "78.38.0.0/15",
    "79.127.0.0/16",
    "80.191.0.0/16",
    "85.15.0.0/17",
    "85.185.0.0/16",
    "91.99.0.0/16",
    "178.131.0.0/16",
    "185.120.0.0/14",
    "185.143.204.0/22",
    "185.208.172.0/22",
    "188.158.0.0/15",
    "188.211.0.0/16",
    "217.218.0.0/15",
]


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def load_config() -> Dict[str, Any]:
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                config = json.load(f)
        except Exception:
            config = {}
    else:
        config = {}
    config["dns_servers"] = [server.to_dict() for server in DEFAULT_DNS_SERVERS]
    config.setdefault("custom_dns", [])
    config.setdefault("test_domains", DEFAULT_TEST_DOMAINS.copy())
    config.setdefault("selected_adapter", None)
    timeout = config.get("timeout", 2000)
    if isinstance(timeout, (int, float)) and timeout <= 10:
        timeout = int(timeout * 1000)
    config.setdefault("timeout", int(timeout))
    config.setdefault("queries_per_domain", 10)
    config.setdefault("port", 53)
    save_config(config)
    return config


def save_config(config: Dict[str, Any]) -> None:
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)


def flush_dns() -> Tuple[bool, str]:
    try:
        result = subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, check=False)
        if "Successfully flushed the DNS Resolver Cache" in result.stdout:
            return True, "DNS cache flushed successfully."
        return False, result.stdout.strip() or result.stderr.strip()
    except Exception as exc:
        return False, str(exc)


def get_network_adapters() -> List[Dict[str, Any]]:
    adapters: List[Dict[str, Any]] = []
    try:
        output = subprocess.check_output("ipconfig", text=True, encoding="utf-8", errors="replace")
    except Exception:
        output = ""

    if output:
        blocks = re.split(r"\r?\n\s*\r?\n", output.strip())
        for block in blocks:
            lines = block.splitlines()
            if not lines:
                continue
            header = lines[0].strip()
            name_match = re.match(r".*adapter\s+(.+?)\s*:\s*$", header, re.IGNORECASE)
            if name_match:
                name = name_match.group(1).strip()
            elif ':' in header:
                name = header.rsplit(':', 1)[0].strip()
            else:
                continue
            has_gw = any(re.search(r"gateway[ .]*:\s*(\d{1,3}(?:\.\d{1,3}){3})", line, re.IGNORECASE) for line in lines)
            adapters.append({"name": name, "has_gateway": has_gw})

    if not adapters:
        try:
            netsh_output = subprocess.check_output(["netsh", "interface", "show", "interface"], text=True, encoding="utf-8", errors="replace")
            lines = netsh_output.splitlines()
            start = False
            for line in lines:
                if '-----' in line:
                    start = True
                    continue
                if start and line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        iface_name = ' '.join(parts[3:])
                        adapters.append({"name": iface_name, "has_gateway": False})
        except Exception:
            pass

    return adapters


def get_active_adapter_name() -> Optional[str]:
    for adapter in get_network_adapters():
        if adapter.get("has_gateway"):
            return adapter["name"]
    adapters = get_network_adapters()
    return adapters[0]["name"] if adapters else None


def parse_scan_targets(spec: str) -> List[str]:
    specs = [line.strip() for line in re.split(r"[\r\n,;]+", spec) if line.strip()]
    if not specs:
        raise ValueError("Empty scan target")
    hosts: List[str] = []
    for item in specs:
        if '/' in item:
            network = ipaddress.ip_network(item, strict=False)
            hosts.extend(str(ip) for ip in network.hosts())
        elif '-' in item:
            start_str, end_str = item.split('-', 1)
            start = ipaddress.IPv4Address(start_str.strip())
            end = ipaddress.IPv4Address(end_str.strip())
            if end < start:
                raise ValueError("Invalid range: end address is before start address")
            hosts.extend(str(ipaddress.IPv4Address(int(start) + i)) for i in range(int(end) - int(start) + 1))
        else:
            hosts.append(str(ipaddress.IPv4Address(item)))
        if len(hosts) > SCAN_MAX_HOSTS:
            raise ValueError(f"Scan target too large ({len(hosts)}) hosts; limit is {SCAN_MAX_HOSTS}")
    return hosts


async def probe_dns_host(host: str, port: int, timeout: float) -> bool:
    query = dns.message.make_query("example.com", dns.rdatatype.A)
    try:
        response = await dns.asyncquery.udp(query, host, port=port, timeout=timeout)
        return response is not None
    except Exception:
        return False


async def scan_dns_targets(
    hosts: List[str],
    port: int,
    timeout: float,
    progress_callback: Optional[Any] = None,
    cancel_event: Optional[threading.Event] = None,
) -> List[str]:
    semaphore = asyncio.Semaphore(50)
    found: List[str] = []
    progress_lock = asyncio.Lock()
    completed = 0

    async def probe(host: str) -> None:
        nonlocal completed
        if cancel_event is not None and cancel_event.is_set():
            return
        async with semaphore:
            if cancel_event is not None and cancel_event.is_set():
                return
            if await probe_dns_host(host, port, timeout):
                found.append(host)
            await asyncio.sleep(0.01)
        async with progress_lock:
            completed += 1
            if progress_callback is not None and not (cancel_event is not None and cancel_event.is_set()):
                progress_callback(completed, len(hosts))

    tasks = [asyncio.create_task(probe(host)) for host in hosts]
    await asyncio.gather(*tasks)
    return found


def set_dns(adapter_name: str, dns_server: DNSServer) -> Tuple[bool, str]:
    if not is_admin():
        return False, "Administrator privileges required."
    try:
        cmd = ["netsh", "interface", "ip", "set", "dns", f'name="{adapter_name}"', "static", dns_server.primary]
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        if dns_server.secondary:
            cmd2 = ["netsh", "interface", "ip", "add", "dns", f'name="{adapter_name}"', dns_server.secondary, "index=2"]
            subprocess.run(cmd2, capture_output=True, text=True, check=True)
            return True, f"DNS set to {dns_server.primary}, secondary {dns_server.secondary} added"
        return True, f"DNS set to {dns_server.primary}"
    except subprocess.CalledProcessError as exc:
        return False, exc.stderr.strip() if exc.stderr else str(exc)


def set_dhcp(adapter_name: str) -> Tuple[bool, str]:
    if not is_admin():
        return False, "Administrator privileges required."
    try:
        cmd = ["netsh", "interface", "ip", "set", "dns", f'name="{adapter_name}"', "dhcp"]
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        return True, "DHCP enabled for DNS"
    except subprocess.CalledProcessError as exc:
        return False, exc.stderr.strip() if exc.stderr else str(exc)


async def single_query(resolver: dns.asyncresolver.Resolver, domain: str, timeout: float) -> Tuple[bool, float]:
    start = time.monotonic()
    try:
        answer = await resolver.resolve(domain, "A", lifetime=timeout)
        elapsed = time.monotonic() - start
        if answer.rrset and len(answer.rrset) > 0:
            return True, elapsed
        return False, elapsed
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return False, time.monotonic() - start
    except dns.resolver.LifetimeTimeout:
        return False, timeout
    except Exception:
        return False, time.monotonic() - start


def make_random_subdomain(domain: str, length: int = 10) -> str:
    token = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return f"{token}.{domain}"


async def query_a_records(resolver: dns.asyncresolver.Resolver, name: str, timeout: float) -> Tuple[bool, List[str], int, str]:
    try:
        answer = await resolver.resolve(name, "A", lifetime=timeout)
        ips = [rdata.address for rdata in answer]
        ttl = answer.rrset.ttl if answer.rrset else 0
        return True, ips, ttl, "NOERROR"
    except dns.resolver.NXDOMAIN:
        return False, [], 0, "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return False, [], 0, "NOANSWER"
    except dns.resolver.LifetimeTimeout:
        return False, [], 0, "TIMEOUT"
    except Exception:
        return False, [], 0, "ERROR"


async def run_speed_test(
    server: DNSServer,
    domains: List[str],
    timeout: float,
    queries_per_domain: int,
    turbo_enabled: bool = False,
    turbo_timeout_ms: int = 0,
    cancel_event: Optional[threading.Event] = None,
) -> Dict[str, Any]:
    async def benchmark_address(address: str) -> Dict[str, Any]:
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = [address]
        resolver.port = server.port
        success_times: List[float] = []
        total = len(domains) * queries_per_domain
        query_timeout = timeout
        if turbo_enabled and turbo_timeout_ms > 0:
            query_timeout = min(timeout, turbo_timeout_ms / 1000.0)

        for domain in domains:
            if cancel_event is not None and cancel_event.is_set():
                break
            domain_had_slow = False
            for i in range(queries_per_domain):
                if cancel_event is not None and cancel_event.is_set():
                    break
                if i > 0:
                    await asyncio.sleep(0.01)
                success, elapsed = await single_query(resolver, domain, query_timeout)
                if success:
                    success_times.append(elapsed)
                if turbo_enabled and turbo_timeout_ms > 0 and elapsed * 1000.0 >= turbo_timeout_ms:
                    domain_had_slow = True
                    break
            if domain_had_slow:
                continue

        success_rate = (len(success_times) / total * 100.0) if total > 0 else 0.0
        stats = {
            "success_count": len(success_times),
            "total_queries": total,
            "success_rate": round(success_rate, 2),
            "success_times": success_times,
        }
        if success_times:
            avg = statistics.mean(success_times) * 1000.0
            min_ = min(success_times) * 1000.0
            max_ = max(success_times) * 1000.0
            std = statistics.stdev(success_times) * 1000.0 if len(success_times) > 1 else 0.0
            stats.update({
                "avg_ms": round(avg, 2),
                "min_ms": round(min_, 2),
                "max_ms": round(max_, 2),
                "std_dev_ms": round(std, 2),
            })
        else:
            stats.update({"avg_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0, "std_dev_ms": 0.0})

        hijacked = False
        test_domain = f"nxdomain-check-{random.randint(100000,999999)}.example.com"
        try:
            answer = await resolver.resolve(test_domain, "A", lifetime=timeout)
            if answer.rrset and len(answer.rrset) > 0:
                hijacked = True
        except dns.resolver.NXDOMAIN:
            hijacked = False
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
            hijacked = False
        except Exception:
            hijacked = False

        suspicious_real_domain = False
        suspect_ips: List[str] = []
        real_domains = ["google.com", "microsoft.com", "github.com", "wikipedia.org"]
        for domain in real_domains:
            if cancel_event is not None and cancel_event.is_set():
                break
            random_name = make_random_subdomain(domain)
            resolved, ips, _, rcode = await query_a_records(resolver, random_name, timeout)
            if resolved and ips and rcode == "NOERROR":
                suspicious_real_domain = True
                suspect_ips.extend(ips)
                break
            await asyncio.sleep(0.01)

        if suspicious_real_domain:
            hijacked = True
            stats["hijack_reason"] = "random real-domain subdomain resolved"
            stats["hijack_ips"] = suspect_ips

        stats["hijacked"] = hijacked
        stats["score"] = round(-9999.0 if hijacked else (stats["success_rate"] * 10.0 - stats["avg_ms"] * 0.2 - stats["std_dev_ms"] * 0.1), 2)
        return stats

    primary_stats = await benchmark_address(server.primary)
    primary_times = list(primary_stats.get("success_times", []))
    primary_stats.pop("success_times", None)

    secondary_stats: Dict[str, Any] = {}
    secondary_times: List[float] = []
    if server.secondary:
        secondary_stats = await benchmark_address(server.secondary)
        secondary_times = list(secondary_stats.get("success_times", []))
        secondary_stats.pop("success_times", None)

    all_success_times = primary_times + secondary_times
    combined_total = primary_stats.get("total_queries", 0) + secondary_stats.get("total_queries", 0)
    combined_success = primary_stats.get("success_count", 0) + secondary_stats.get("success_count", 0)
    combined_success_rate = (combined_success / combined_total * 100.0) if combined_total > 0 else 0.0
    if all_success_times:
        combined_avg = statistics.mean(all_success_times) * 1000.0
        combined_min = min(all_success_times) * 1000.0
        combined_max = max(all_success_times) * 1000.0
        combined_std = statistics.stdev(all_success_times) * 1000.0 if len(all_success_times) > 1 else 0.0
    else:
        combined_avg = combined_min = combined_max = combined_std = 0.0

    stats = {
        "success_count": combined_success,
        "total_queries": combined_total,
        "success_rate": round(combined_success_rate, 2),
        "avg_ms": round(combined_avg, 2),
        "min_ms": round(combined_min, 2),
        "max_ms": round(combined_max, 2),
        "std_dev_ms": round(combined_std, 2),
        "primary": primary_stats,
        "secondary": secondary_stats,
        "hijacked": primary_stats.get("hijacked", False) or secondary_stats.get("hijacked", False),
        "score": round(
            -9999.0
            if (primary_stats.get("hijacked", False) or secondary_stats.get("hijacked", False))
            else (combined_success_rate * 10.0 - combined_avg * 0.2 - combined_std * 0.1),
            2,
        ),
    }
    if primary_stats.get("hijack_reason"):
        stats["hijack_reason"] = primary_stats["hijack_reason"]
    if secondary_stats.get("hijack_reason"):
        stats["hijack_reason"] = secondary_stats["hijack_reason"]
    if primary_stats.get("hijack_ips"):
        stats["hijack_ips"] = primary_stats["hijack_ips"]
    if secondary_stats.get("hijack_ips"):
        stats["hijack_ips"] = secondary_stats["hijack_ips"]
    return stats


class BaseDialog(tk.Toplevel):
    def __init__(self, parent: tk.Tk, title: str):
        super().__init__(parent)
        self.parent = parent
        self.title(title)
        self.result = None
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)

    def on_cancel(self) -> None:
        self.result = None
        self.destroy()

    def show(self) -> Any:
        self.wait_window()
        return self.result


class AddEditDNSDialog(BaseDialog):
    def __init__(self, parent: tk.Tk, server: Optional[DNSServer] = None) -> None:
        super().__init__(parent, "Edit DNS" if server else "Add DNS")
        self.server = server
        self.name_var = tk.StringVar(value=server.name if server else "")
        self.primary_var = tk.StringVar(value=server.primary if server else "")
        self.secondary_var = tk.StringVar(value=server.secondary if server else "")
        self.port_var = tk.StringVar(value=str(server.port if server else 53))
        self.build()

    def build(self) -> None:
        frame = ttk.Frame(self)
        frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="Name:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(frame, textvariable=self.name_var, width=40).grid(row=0, column=1, sticky=tk.EW)
        ttk.Label(frame, text="Primary IP:").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(frame, textvariable=self.primary_var, width=40).grid(row=1, column=1, sticky=tk.EW)
        ttk.Label(frame, text="Secondary IP:").grid(row=2, column=0, sticky=tk.W)
        ttk.Entry(frame, textvariable=self.secondary_var, width=40).grid(row=2, column=1, sticky=tk.EW)
        ttk.Label(frame, text="Port:").grid(row=3, column=0, sticky=tk.W)
        ttk.Entry(frame, textvariable=self.port_var, width=10).grid(row=3, column=1, sticky=tk.W)
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=(10, 0), sticky=tk.E)
        ttk.Button(button_frame, text="Save", command=self.on_save).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Cancel", command=self.on_cancel).pack(side=tk.LEFT)
        frame.columnconfigure(1, weight=1)

    def on_save(self) -> None:
        name = self.name_var.get().strip()
        primary = self.primary_var.get().strip()
        secondary = self.secondary_var.get().strip()
        port_text = self.port_var.get().strip()
        if not name or not primary:
            messagebox.showerror("Validation", "Name and primary IP are required.", parent=self)
            return
        try:
            port = int(port_text)
        except ValueError:
            messagebox.showerror("Validation", "Invalid port.", parent=self)
            return
        try:
            ipaddress.IPv4Address(primary)
        except ipaddress.AddressValueError:
            messagebox.showerror("Validation", "Invalid primary IP.", parent=self)
            return
        if secondary:
            try:
                ipaddress.IPv4Address(secondary)
            except ipaddress.AddressValueError:
                messagebox.showerror("Validation", "Invalid secondary IP.", parent=self)
                return
        server_id = self.server.id if self.server else f"custom_{int(time.time())}_{random.randint(1000, 9999)}"
        self.result = DNSServer(server_id, name, primary, secondary, port)
        self.destroy()


class BenchmarkSettingsDialog(BaseDialog):
    def __init__(self, parent: tk.Tk, timeout: float, queries: int) -> None:
        super().__init__(parent, "Benchmark Settings")
        self.timeout_var = tk.StringVar(value=str(timeout))
        self.queries_var = tk.StringVar(value=str(queries))
        self.build()

    def build(self) -> None:
        frame = ttk.Frame(self)
        frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="Max delay (milliseconds):").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(frame, textvariable=self.timeout_var, width=20).grid(row=0, column=1, sticky=tk.W)
        ttk.Label(frame, text="Queries per domain:").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(frame, textvariable=self.queries_var, width=20).grid(row=1, column=1, sticky=tk.W)
        ttk.Label(frame, text="Set the timeout and # queries for each domain.").grid(row=2, column=0, columnspan=2, pady=(5, 10), sticky=tk.W)
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=3, column=0, columnspan=2, sticky=tk.E)
        ttk.Button(button_frame, text="Save", command=self.on_save).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Cancel", command=self.on_cancel).pack(side=tk.LEFT)
        frame.columnconfigure(1, weight=1)

    def on_save(self) -> None:
        try:
            timeout = float(self.timeout_var.get())
            queries = int(self.queries_var.get())
        except ValueError:
            messagebox.showerror("Validation", "Timeout must be a number and queries must be an integer.", parent=self)
            return
        if timeout <= 0 or queries <= 0:
            messagebox.showerror("Validation", "Timeout and queries must be positive.", parent=self)
            return
        self.result = (timeout, queries)
        self.destroy()


class ManageDomainsDialog(BaseDialog):
    def __init__(self, parent: tk.Tk, domains: List[str]) -> None:
        super().__init__(parent, "Manage Test Domains")
        self.domains = domains
        self.build()

    def build(self) -> None:
        frame = ttk.Frame(self)
        frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="Enter one domain per line:").pack(anchor=tk.W)
        self.text = tk.Text(frame, width=60, height=12)
        self.text.pack(fill=tk.BOTH, expand=True)
        self.text.insert("1.0", "\n".join(self.domains))
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(button_frame, text="Save", command=self.on_save).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Cancel", command=self.on_cancel).pack(side=tk.LEFT)

    def on_save(self) -> None:
        text_value = self.text.get("1.0", tk.END).strip()
        if not text_value:
            messagebox.showerror("Validation", "Enter at least one domain.", parent=self)
            return
        self.result = [line.strip() for line in text_value.splitlines() if line.strip()]
        self.destroy()


class ScanDNSDialog(BaseDialog):
    def __init__(self, parent: tk.Tk) -> None:
        super().__init__(parent, "Scan DNS Hosts")
        self.port_var = tk.StringVar(value="53")
        self.build()

    def build(self) -> None:
        frame = ttk.Frame(self)
        frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="IP range(s) or CIDR(s) (one per line):").grid(row=0, column=0, sticky=tk.W)
        self.targets_text = tk.Text(frame, width=60, height=12)
        self.targets_text.grid(row=1, column=0, columnspan=2, sticky=tk.NSEW, pady=(6, 0))
        self.targets_text.insert("1.0", "\n".join(DEFAULT_SCAN_RANGES))
        ttk.Label(frame, text="Port:").grid(row=2, column=0, sticky=tk.W, pady=(10, 0))
        ttk.Entry(frame, textvariable=self.port_var, width=10).grid(row=2, column=1, sticky=tk.W, pady=(10, 0))
        ttk.Label(frame, text="Scan for DNS servers on the specified IP ranges.").grid(row=3, column=0, columnspan=2, pady=(5, 10), sticky=tk.W)
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=4, column=0, columnspan=2, sticky=tk.E)
        ttk.Button(button_frame, text="Scan", command=self.on_scan).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Cancel", command=self.on_cancel).pack(side=tk.LEFT)
        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=0)
        frame.rowconfigure(1, weight=1)

    def on_scan(self) -> None:
        target = self.targets_text.get("1.0", tk.END).strip()
        if not target:
            messagebox.showerror("Validation", "Enter at least one IP range.", parent=self)
            return
        try:
            port = int(self.port_var.get())
        except ValueError:
            messagebox.showerror("Validation", "Invalid port.", parent=self)
            return
        if port < 1 or port > 65535:
            messagebox.showerror("Validation", "Port must be between 1 and 65535.", parent=self)
            return
        self.result = (target, port)
        self.destroy()


class AdapterSelectDialog(BaseDialog):
    def __init__(self, parent: tk.Tk, adapters: List[Dict[str, Any]], active: Optional[str]) -> None:
        super().__init__(parent, "Select Network Adapter")
        self.adapters = [{"name": ALL_ADAPTERS_NAME, "has_gateway": False}] + adapters
        self.active = active
        self.build()

    def build(self) -> None:
        frame = ttk.Frame(self)
        frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.listbox = tk.Listbox(frame, height=10)
        for adapter in self.adapters:
            label = adapter["name"]
            if adapter["name"] == self.active:
                label += " (active)"
            self.listbox.insert(tk.END, label)
        self.listbox.pack(fill=tk.BOTH, expand=True)
        if self.active:
            for idx, adapter in enumerate(self.adapters):
                if adapter["name"] == self.active:
                    self.listbox.selection_set(idx)
                    break
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(button_frame, text="Select", command=self.on_select).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Cancel", command=self.on_cancel).pack(side=tk.LEFT)

    def on_select(self) -> None:
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showwarning("Selection", "Select an adapter.", parent=self)
            return
        self.result = self.adapters[selection[0]]["name"]
        self.destroy()


class DNSBenchmarkApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("DNS Benchmark")
        self.geometry("1200x760")
        self.config_obj = load_config()
        builtin = [DNSServer.from_dict(item) for item in self.config_obj["dns_servers"]]
        custom = [DNSServer.from_dict(item) for item in self.config_obj["custom_dns"]]
        self.all_servers = builtin + custom
        self.custom_default_server = custom[0] if custom else None
        self.test_domains = self.config_obj["test_domains"]
        self.benchmark_results: Dict[str, Dict[str, Any]] = {}
        self.benchmark_thread: Optional[threading.Thread] = None
        self.benchmark_cancel_event = threading.Event()
        self.scan_thread: Optional[threading.Thread] = None
        self.scan_cancel_event = threading.Event()
        self.discovered_scan_hosts: List[str] = []
        self.create_widgets()
        self.refresh_table()

    def create_widgets(self) -> None:
        self.title("MiziDNS")
        self.geometry("1200x760")
        self.minsize(1100, 700)
        style = ttk.Style(self)
        try:
            style.theme_use("default")
        except Exception:
            style.theme_use("default")
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("Header.TLabel", font=("Segoe UI", 10, "bold"))
        style.configure("Section.TLabel", font=("Segoe UI", 9, "bold"))
        style.configure("TLabel", font=("Segoe UI", 9))
        style.configure("TButton", font=("Segoe UI", 9))
        style.configure("TEntry", font=("Segoe UI", 9))
        style.configure("Treeview", font=("Segoe UI", 9), rowheight=24)
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        style.configure("TNotebook", background="#f1f1f1")
        style.configure("TNotebook.Tab", font=("Segoe UI", 9, "bold"), padding=(8, 4))

        header_frame = ttk.Frame(self, padding=(12, 10, 12, 6))
        header_frame.pack(fill=tk.X)
        title_label = ttk.Label(header_frame, text="MiziDNS", style="Title.TLabel")
        title_label.pack(side=tk.LEFT, anchor=tk.W)
        donate_label = ttk.Label(header_frame, text="Please Donate", foreground="#1a73e8", cursor="hand2")
        donate_label.pack(side=tk.RIGHT, anchor=tk.E)
        donate_label.bind("<Button-1>", lambda _: self.open_donate_link())

        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 10))

        control_tab = ttk.Frame(notebook)
        benchmark_tab = ttk.Frame(notebook)
        scanner_tab = ttk.Frame(notebook)
        notebook.add(control_tab, text="DNS Control")
        notebook.add(benchmark_tab, text="Fastest DNS")
        notebook.add(scanner_tab, text="DNS Scanner")

        main_frame = ttk.Frame(control_tab, padding=(10, 10))
        main_frame.pack(fill=tk.BOTH, expand=True)

        sidebar = tk.Frame(main_frame, bg="#f0f0f0", bd=1, relief=tk.FLAT)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        sidebar_title = tk.Label(sidebar, text="Main Actions", font=("Segoe UI", 10, "bold"), bg="#f0f0f0")
        sidebar_title.pack(anchor=tk.W, pady=(10, 8), padx=10)
        action_buttons = [
            ("🖧 Apply DNS", self.on_set_dns),
            ("⚡ Fastest DNS", self.on_run_benchmark),
            ("🔄 Flush DNS", self.on_flush_dns),
            ("⚙ Options", self.on_benchmark_settings),
            ("🔎 Scan DNS", self.on_scan_dns),
        ]
        for text, command in action_buttons:
            btn = ttk.Button(sidebar, text=text, command=command)
            btn.pack(fill=tk.X, padx=10, pady=4)

        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        adapter_section = ttk.LabelFrame(right_panel, text="Select Network Adapter", padding=(10, 10))
        adapter_section.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(adapter_section, text="Select Network Adapter", style="Section.TLabel").grid(row=0, column=0, sticky=tk.W)
        self.adapter_var = tk.StringVar(value=self.config_obj.get("selected_adapter") or ALL_ADAPTERS_NAME)
        self.adapter_combo = ttk.Combobox(adapter_section, textvariable=self.adapter_var, state="readonly", width=42)
        self.adapter_combo.grid(row=1, column=0, sticky=tk.W, pady=(6, 8))
        self.adapter_refresh_button = ttk.Button(adapter_section, text="⟳", width=3, command=self.update_adapter_list)
        self.adapter_refresh_button.grid(row=1, column=1, sticky=tk.W, padx=(6, 0), pady=(6, 8))

        dns_section = ttk.LabelFrame(right_panel, text="Choose a DNS Server", padding=(10, 10))
        dns_section.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(dns_section, text="Choose a DNS Server", style="Section.TLabel").grid(row=0, column=0, sticky=tk.W)
        self.server_var = tk.StringVar(value="Custom DNS")
        self.dns_combo = ttk.Combobox(dns_section, textvariable=self.server_var, state="readonly", width=42)
        self.dns_combo.grid(row=1, column=0, sticky=tk.W, pady=(6, 8))
        self.dns_combo.bind("<<ComboboxSelected>>", lambda event: self.on_dropdown_server_selected())
        self.server_refresh_button = ttk.Button(dns_section, text="≡", width=3, command=self.update_dns_server_list)
        self.server_refresh_button.grid(row=1, column=1, sticky=tk.W, padx=(6, 0), pady=(6, 8))
        self.server_settings_button = ttk.Button(dns_section, text="⚙", width=3, command=self.on_benchmark_settings)
        self.server_settings_button.grid(row=1, column=2, sticky=tk.W, padx=(6, 0), pady=(6, 8))
        self.server_search_button = ttk.Button(dns_section, text="🔍", width=3, command=self.on_scan_dns)
        self.server_search_button.grid(row=1, column=3, sticky=tk.W, padx=(6, 0), pady=(6, 8))

        manage_frame = ttk.Frame(dns_section)
        manage_frame.grid(row=2, column=0, columnspan=4, pady=(6, 0), sticky=tk.W)
        ttk.Button(manage_frame, text="Add DNS", command=self.on_add_dns).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(manage_frame, text="Edit DNS", command=self.on_edit_dns).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(manage_frame, text="Remove DNS", command=self.on_remove_dns).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(manage_frame, text="Edit Domains", command=self.on_manage_domains).pack(side=tk.LEFT)

        options_section = ttk.LabelFrame(right_panel, text="Custom DNS Server", padding=(10, 10))
        options_section.pack(fill=tk.X, pady=(0, 10))
        self.custom_dns_enabled = tk.BooleanVar(value=True)
        self.dhcp_enabled = tk.BooleanVar(value=False)
        self.custom_primary_var = tk.StringVar(value=self.custom_default_server.primary if self.custom_default_server else "")
        self.custom_secondary_var = tk.StringVar(value=self.custom_default_server.secondary if self.custom_default_server else "")
        self.custom_check = ttk.Checkbutton(options_section, text="Custom DNS Server", variable=self.custom_dns_enabled, command=self.toggle_custom_dns)
        self.custom_check.grid(row=0, column=0, sticky=tk.W)
        self.dhcp_check = ttk.Checkbutton(options_section, text="Enable DHCP", variable=self.dhcp_enabled, command=self.toggle_dhcp)
        self.dhcp_check.grid(row=0, column=1, sticky=tk.W, padx=(20, 0))
        # IPv6 support is currently disabled/commented out.
        # self.use_ipv6_enabled = tk.BooleanVar(value=False)
        # self.ipv6_check = ttk.Checkbutton(options_section, text="Use IPv6 DNS", variable=self.use_ipv6_enabled)
        # self.ipv6_check.grid(row=0, column=2, sticky=tk.W, padx=(20, 0))

        dns_fields_frame = ttk.Frame(right_panel)
        dns_fields_frame.pack(fill=tk.X, pady=(0, 10))

        primary_frame = ttk.Frame(dns_fields_frame)
        primary_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        ttk.Label(primary_frame, text="Primary DNS", style="Section.TLabel").pack(anchor=tk.W)
        self.custom_primary_entry = ttk.Entry(primary_frame, textvariable=self.custom_primary_var, width=30, state="disabled")
        self.custom_primary_entry.pack(fill=tk.X, pady=(6, 0))
        self.check_primary_button = ttk.Button(primary_frame, text="Check Resolve Time", command=self.on_check_resolve_time)
        self.check_primary_button.pack(fill=tk.X, pady=(8, 0))

        swap_button = ttk.Button(dns_fields_frame, text="↔", width=3, command=self.update_dns_server_list)
        swap_button.pack(side=tk.LEFT, padx=4, pady=24)

        secondary_frame = ttk.Frame(dns_fields_frame)
        secondary_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))
        ttk.Label(secondary_frame, text="Secondary DNS", style="Section.TLabel").pack(anchor=tk.W)
        self.custom_secondary_entry = ttk.Entry(secondary_frame, textvariable=self.custom_secondary_var, width=30, state="disabled")
        self.custom_secondary_entry.pack(fill=tk.X, pady=(6, 0))
        self.check_secondary_button = ttk.Button(secondary_frame, text="Check Resolve Time", command=self.on_check_resolve_time)
        self.check_secondary_button.pack(fill=tk.X, pady=(8, 0))

        benchmark_frame = ttk.Frame(benchmark_tab, padding=(12, 12))
        benchmark_frame.pack(fill=tk.BOTH, expand=True)

        benchmark_table_section = ttk.Frame(benchmark_frame)
        benchmark_table_section.pack(fill=tk.BOTH, expand=True)

        benchmark_columns = [
            "DNS Server Name",
            "DNS 1",
            "DNS 2",
            "Status",
            "Hijacked",
            "Score",
            "Success %",
            "Avg ms",
            "Min ms",
            "Max ms",
            "Std Dev ms",
        ]
        self.benchmark_table = ttk.Treeview(benchmark_table_section, columns=benchmark_columns, show="headings", selectmode="browse")
        self.tree = self.benchmark_table
        column_settings = {
            "DNS Server Name": {"anchor": tk.W, "width": 220},
            "DNS 1": {"anchor": tk.W, "width": 120},
            "DNS 2": {"anchor": tk.W, "width": 120},
            "Status": {"anchor": tk.CENTER, "width": 90},
            "Hijacked": {"anchor": tk.CENTER, "width": 90},
            "Score": {"anchor": tk.CENTER, "width": 80},
            "Success %": {"anchor": tk.CENTER, "width": 90},
            "Avg ms": {"anchor": tk.CENTER, "width": 90},
            "Min ms": {"anchor": tk.CENTER, "width": 90},
            "Max ms": {"anchor": tk.CENTER, "width": 90},
            "Std Dev ms": {"anchor": tk.CENTER, "width": 100},
        }
        for col in benchmark_columns:
            self.benchmark_table.heading(col, text=col)
            settings = column_settings.get(col, {})
            self.benchmark_table.column(col, anchor=settings.get("anchor", tk.CENTER), width=settings.get("width", 120))
        self.benchmark_table.grid(row=0, column=0, sticky=tk.NSEW)
        self.benchmark_table.bind("<Double-1>", lambda event: self.on_table_double_clicked(self.benchmark_table.selection()[0] if self.benchmark_table.selection() else None, 0))
        benchmark_scrollbar = ttk.Scrollbar(benchmark_table_section, orient=tk.VERTICAL, command=self.benchmark_table.yview)
        self.benchmark_table.configure(yscroll=benchmark_scrollbar.set)
        benchmark_scrollbar.grid(row=0, column=1, sticky=tk.NS)
        benchmark_table_section.columnconfigure(0, weight=1)
        benchmark_table_section.rowconfigure(0, weight=1)

        self.benchmark_table.tag_configure("fast", foreground="#1a7f24")
        self.benchmark_table.tag_configure("error", foreground="#c00")
        self.benchmark_table.tag_configure("hijacked", foreground="#c00")

        controls_bottom = ttk.Frame(benchmark_frame)
        controls_bottom.pack(fill=tk.X, pady=(12, 0))

        preview_frame = ttk.LabelFrame(controls_bottom, text="Recommended DNS", padding=(10, 10))
        preview_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.primary_var = tk.StringVar()
        self.secondary_var = tk.StringVar()
        self.safe_var = tk.StringVar(value="Unknown")
        ttk.Label(preview_frame, text="Primary:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(preview_frame, textvariable=self.primary_var, width=24, state="readonly").grid(row=0, column=1, sticky=tk.W, padx=(8, 16))
        ttk.Label(preview_frame, text="Secondary:").grid(row=1, column=0, sticky=tk.W, pady=(6, 0))
        ttk.Entry(preview_frame, textvariable=self.secondary_var, width=24, state="readonly").grid(row=1, column=1, sticky=tk.W, padx=(8, 16), pady=(6, 0))
        ttk.Label(preview_frame, text="Score:").grid(row=2, column=0, sticky=tk.W, pady=(6, 0))
        ttk.Entry(preview_frame, textvariable=self.safe_var, width=24, state="readonly").grid(row=2, column=1, sticky=tk.W, padx=(8, 16), pady=(6, 0))

        right_controls = ttk.Frame(controls_bottom)
        right_controls.pack(side=tk.RIGHT, fill=tk.X)
        self.turbo_var = tk.StringVar(value="30")
        self.turbo_enabled_var = tk.BooleanVar(value=True)

        turbo_frame = ttk.Frame(right_controls)
        turbo_frame.pack(side=tk.LEFT, padx=(0, 10))
        ttk.Checkbutton(turbo_frame, text="Turbo Resolve", variable=self.turbo_enabled_var).pack(side=tk.LEFT)
        ttk.Spinbox(turbo_frame, from_=1, to=100, textvariable=self.turbo_var, width=5).pack(side=tk.LEFT, padx=(6, 0))

        self.start_test_button = ttk.Button(right_controls, text="Start DNS Test", command=self.on_toggle_benchmark)
        self.start_test_button.pack(side=tk.LEFT, padx=(8, 2))
        self.apply_server_button = ttk.Button(right_controls, text="Apply DNS Server", command=self.on_set_dns)
        self.apply_server_button.pack(side=tk.LEFT, padx=(2, 0))
        self.apply_mixed_button = ttk.Button(right_controls, text="Apply Mixed DNS", command=self.on_apply_mixed_dns)
        self.apply_mixed_button.pack(side=tk.LEFT, padx=(2, 0))

        self.recommend_frame = ttk.Labelframe(benchmark_frame, text="Recommended DNS", padding=(10, 10))
        ttk.Button(self.recommend_frame, text="Apply Recommended DNS", command=self.on_apply_recommended).pack(side=tk.LEFT)
        self.recommend_frame.pack(fill=tk.X, pady=(10, 0))
        self.recommend_frame.pack_forget()

        scanner_frame = ttk.Frame(scanner_tab, padding=(12, 12))
        scanner_frame.pack(fill=tk.BOTH, expand=True)
        self.scan_status_var = tk.StringVar(value="Idle")
        ttk.Label(scanner_frame, text="Scanner Status", style="Section.TLabel").pack(anchor=tk.W)
        self.scan_status_label = ttk.Label(scanner_frame, textvariable=self.scan_status_var)
        self.scan_status_label.pack(anchor=tk.W, pady=(4, 12))
        self.scan_progress_bar = ttk.Progressbar(scanner_frame, maximum=100, mode="indeterminate")
        self.scan_progress_bar.pack(fill=tk.X, pady=(0, 12))
        self.scan_stop_button = ttk.Button(scanner_frame, text="Stop Scan", command=self.cancel_scan, state="disabled")
        self.scan_stop_button.pack(anchor=tk.W, pady=(0, 12))

        summary_frame = ttk.LabelFrame(scanner_frame, text="Scan Summary", padding=(10, 10))
        summary_frame.pack(fill=tk.X, pady=(0, 10))
        self.scan_target_var = tk.StringVar(value="-")
        self.scan_port_var = tk.StringVar(value="-")
        self.scan_total_var = tk.StringVar(value="0")
        self.scan_found_var = tk.StringVar(value="0")
        self.scan_added_var = tk.StringVar(value="0")
        ttk.Label(summary_frame, text="Target:").grid(row=0, column=0, sticky=tk.W)
        ttk.Label(summary_frame, textvariable=self.scan_target_var).grid(row=0, column=1, sticky=tk.W, padx=(8, 16))
        ttk.Label(summary_frame, text="Port:").grid(row=0, column=2, sticky=tk.W)
        ttk.Label(summary_frame, textvariable=self.scan_port_var).grid(row=0, column=3, sticky=tk.W, padx=(8, 16))
        ttk.Label(summary_frame, text="Hosts checked:").grid(row=1, column=0, sticky=tk.W, pady=(6, 0))
        ttk.Label(summary_frame, textvariable=self.scan_total_var).grid(row=1, column=1, sticky=tk.W, padx=(8, 16), pady=(6, 0))
        ttk.Label(summary_frame, text="Found:").grid(row=1, column=2, sticky=tk.W, pady=(6, 0))
        ttk.Label(summary_frame, textvariable=self.scan_found_var).grid(row=1, column=3, sticky=tk.W, padx=(8, 16), pady=(6, 0))
        ttk.Label(summary_frame, text="Added:").grid(row=2, column=0, sticky=tk.W, pady=(6, 0))
        ttk.Label(summary_frame, textvariable=self.scan_added_var).grid(row=2, column=1, sticky=tk.W, padx=(8, 16), pady=(6, 0))

        results_frame = ttk.Frame(scanner_frame)
        results_frame.pack(fill=tk.BOTH, expand=True)
        self.scan_log = tk.Text(results_frame, height=12, wrap=tk.WORD)
        self.scan_log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        self.scan_log.insert(tk.END, "Scanner log ready.\n")
        found_hosts_frame = ttk.LabelFrame(results_frame, text="Discovered Hosts", padding=(8, 8))
        found_hosts_frame.pack(side=tk.RIGHT, fill=tk.Y)
        self.scan_hosts_list = tk.Listbox(found_hosts_frame, width=30, height=12)
        self.scan_hosts_list.pack(fill=tk.BOTH, expand=True)
        self.add_discovered_button = ttk.Button(scanner_frame, text="Add All Discovered DNS", command=self.on_add_discovered_dns)
        self.add_discovered_button.pack(anchor=tk.W, pady=(10, 0))

        status_frame = ttk.Frame(self)
        status_frame.pack(fill=tk.X, padx=12, pady=(0, 10))
        self.progress_bar = ttk.Progressbar(status_frame, maximum=100, mode="determinate")
        self.progress_bar.pack(fill=tk.X, side=tk.LEFT, expand=True)
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var)
        self.status_label.pack(side=tk.LEFT, padx=(10, 0))

        self.adapter_combo['values'] = []
        self.dns_combo['values'] = []
        self.update_adapter_list(default_to_all=True)
        self.update_dns_server_list()
        self.toggle_custom_dns()
        self.refresh_table()
        self.update_idletasks()
        required_width = max(self.winfo_reqwidth(), 1180)
        required_height = max(self.winfo_reqheight(), 740)
        self.geometry(f"{required_width}x{required_height}")

    def set_status(self, message: str) -> None:
        self.status_var.set(message)

    def on_toggle_benchmark(self) -> None:
        if self.benchmark_thread and self.benchmark_thread.is_alive():
            self.cancel_benchmark()
        else:
            self.on_run_benchmark()

    def cancel_benchmark(self) -> None:
        if self.benchmark_cancel_event.is_set():
            return
        self.benchmark_cancel_event.set()
        self.set_status("Stopping benchmark...")
        self.start_test_button.config(text="Start DNS Test")

    def on_benchmark_cancelled(self) -> None:
        self.set_status("Benchmark cancelled.")
        self.start_test_button.config(text="Start DNS Test")

    def cancel_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_cancel_event.set()
            self.scan_status_var.set("Stopping scan...")
            self.set_status("Stopping scan...")
            self.scan_stop_button.config(state="disabled")
            return
        self.scan_stop_button.config(state="disabled")

    def update_adapter_list(self, default_to_all: bool = False) -> None:
        adapters = [adapter["name"] for adapter in get_network_adapters()]
        if adapters:
            adapters = [ALL_ADAPTERS_NAME] + adapters
        else:
            adapters = ["No adapters found"]
        self.adapter_combo["values"] = adapters
        selected = self.config_obj.get("selected_adapter")
        if default_to_all and ALL_ADAPTERS_NAME in adapters:
            self.adapter_var.set(ALL_ADAPTERS_NAME)
        elif selected in adapters:
            self.adapter_var.set(selected)
        elif ALL_ADAPTERS_NAME in adapters:
            self.adapter_var.set(ALL_ADAPTERS_NAME)
        elif adapters:
            active = get_active_adapter_name()
            self.adapter_var.set(active if active in adapters else adapters[0])

    def get_selected_adapter_name(self) -> Optional[str]:
        adapter = self.adapter_var.get().strip()
        if adapter and adapter != "No adapters found":
            return adapter
        return None

    def validate_dns_address(self, address: str) -> bool:
        if not address:
            return False
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    def update_dns_server_list(self) -> None:
        values = ["Custom DNS"] + [server.name for server in self.all_servers]
        self.dns_combo["values"] = values
        if self.custom_dns_enabled.get():
            self.server_var.set("Custom DNS")
        elif self.all_servers:
            self.server_var.set(self.all_servers[0].name)

    def on_dropdown_server_selected(self) -> None:
        selected_name = self.server_var.get()
        if selected_name == "Custom DNS":
            return
        server = next((s for s in self.all_servers if s.name == selected_name), None)
        if server and hasattr(self, 'benchmark_table') and self.benchmark_table.exists(server.id):
            self.benchmark_table.selection_set(server.id)
            self.benchmark_table.see(server.id)

    def on_table_double_clicked(self, item_id: Optional[str], column: int) -> None:
        if not item_id:
            return
        if hasattr(self, 'benchmark_table') and self.benchmark_table.exists(item_id):
            self.benchmark_table.selection_set(item_id)
            self.benchmark_table.see(item_id)

    def get_selected_dns_server(self) -> Optional[DNSServer]:
        if self.custom_dns_enabled.get():
            primary = self.custom_primary_var.get().strip()
            secondary = self.custom_secondary_var.get().strip()
            if not self.validate_dns_address(primary):
                return None
            return DNSServer("custom_dns", "Custom DNS", primary, secondary)
        selected_name = self.server_var.get()
        if selected_name == "Custom DNS":
            return None
        return next((s for s in self.all_servers if s.name == selected_name), None)

    def toggle_custom_dns(self) -> None:
        state = "normal" if self.custom_dns_enabled.get() else "disabled"
        self.custom_primary_entry.config(state=state)
        self.custom_secondary_entry.config(state=state)
        if self.custom_dns_enabled.get():
            self.server_var.set("Custom DNS")
            self.dhcp_enabled.set(False)
            self.dns_combo.config(state="readonly")
            self.custom_check.state(["!disabled"])
            self.dhcp_check.state(["!disabled"])
        else:
            if self.all_servers:
                self.server_var.set(self.all_servers[0].name)
            self.dns_combo.config(state="readonly")

    def toggle_dhcp(self) -> None:
        if self.dhcp_enabled.get():
            self.custom_dns_enabled.set(False)
            self.custom_check.state(["disabled"])
            self.custom_primary_entry.config(state="disabled")
            self.custom_secondary_entry.config(state="disabled")
            self.dns_combo.config(state="disabled")
            self.server_var.set("")
        else:
            self.custom_check.state(["!disabled"])
            self.dns_combo.config(state="readonly")
            self.toggle_custom_dns()

    def on_check_resolve_time(self) -> None:
        primary = self.custom_primary_var.get().strip()
        secondary = self.custom_secondary_var.get().strip()
        if not self.validate_dns_address(primary):
            messagebox.showerror("Custom DNS", "Enter a valid primary DNS IP address.", parent=self)
            return
        dns_server = DNSServer("custom_check", "Custom DNS", primary, secondary)

        def check_worker() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                timeout_ms = self.config_obj.get("timeout", 2000)
                stats = loop.run_until_complete(run_speed_test(dns_server, self.test_domains, timeout_ms / 1000.0, self.config_obj.get("queries_per_domain", 10)))
                if stats.get("hijacked"):
                    title = "Resolve Time"
                    message = f"DNS appears hijacked.\nPrimary: {primary}\nSecurity: Unsafe"
                else:
                    message = (
                        f"Primary: {primary}\n"
                        f"Secondary: {secondary or 'None'}\n"
                        f"Success: {stats.get('success_rate', 0):.1f}%\n"
                        f"Avg: {stats.get('avg_ms', 0):.2f} ms\n"
                        f"Min: {stats.get('min_ms', 0):.2f} ms\n"
                        f"Max: {stats.get('max_ms', 0):.2f} ms\n"
                        f"Std Dev: {stats.get('std_dev_ms', 0):.2f} ms"
                    )
                    title = "Resolve Time"
                self.after(0, lambda: messagebox.showinfo(title, message, parent=self))
                self.after(0, lambda: self.set_status(f"Checked custom DNS {primary}."))
            except Exception as exc:
                self.after(0, lambda: messagebox.showerror("Resolve Time", str(exc), parent=self))
                self.after(0, lambda: self.set_status("Resolve check failed."))
            finally:
                loop.close()

        threading.Thread(target=check_worker, daemon=True).start()

    def get_status_for_result(self, res: Dict[str, Any], testing: bool = False) -> str:
        if testing:
            return "Testing..."
        if res.get("hijacked"):
            return "Hijacked!"
        if res:
            return "Done"
        return "Idle"

    def get_score_label(self, res: Optional[Dict[str, Any]]) -> str:
        if not res:
            return "-"
        if res.get("hijacked"):
            return "Unsafe"
        try:
            score = float(res.get("score", 0.0))
        except (TypeError, ValueError):
            score = 0.0
        if score >= 80:
            return "Strong"
        if score >= 45:
            return "Good"
        if score >= 10:
            return "Fair"
        return "Avoid"

    def get_row_tags(self, res: Dict[str, Any]) -> List[str]:
        tags: List[str] = []
        if res.get("hijacked"):
            tags.append("hijacked")
        else:
            score_label = self.get_score_label(res)
            if score_label in {"Strong", "Good"}:
                tags.append("fast")
            elif score_label == "Avoid":
                tags.append("error")
        return tags

    def format_row_values(self, server: DNSServer, res: Dict[str, Any], status: Optional[str] = None) -> Tuple[str, str, str, str, str, str, str, str, str, str, str]:
        if status is None:
            status = self.get_status_for_result(res)
        hijacked_text = "Yes" if res.get("hijacked") else ("No" if res else "-")
        score_text = self.get_score_label(res)
        primary_stats = res.get("primary", {}) if res else {}
        secondary_stats = res.get("secondary", {}) if res else {}
        primary_label = f"{server.primary} ({primary_stats.get('success_rate', 0):.1f}% / {primary_stats.get('avg_ms', 0):.2f} ms)" if res else server.primary
        secondary_label = f"{server.secondary} ({secondary_stats.get('success_rate', 0):.1f}% / {secondary_stats.get('avg_ms', 0):.2f} ms)" if server.secondary and res else (server.secondary or "-")
        return (
            server.name,
            primary_label,
            secondary_label,
            status,
            hijacked_text,
            score_text,
            f"{res.get('success_rate', 0):.1f}%" if res else "-",
            f"{res.get('avg_ms', 0):.2f}" if res else "-",
            f"{res.get('min_ms', 0):.2f}" if res else "-",
            f"{res.get('max_ms', 0):.2f}" if res else "-",
            f"{res.get('std_dev_ms', 0):.2f}" if res else "-",
        )

    def refresh_table(self, sort_results: bool = False) -> None:
        if hasattr(self, 'benchmark_table'):
            for row in self.benchmark_table.get_children():
                self.benchmark_table.delete(row)
        servers = self.all_servers
        if sort_results and self.benchmark_results:
            servers = sorted(
                servers,
                key=lambda srv: (
                    self.benchmark_results.get(srv.id, {}).get("hijacked", False),
                    -self.benchmark_results.get(srv.id, {}).get("score", -999.0),
                ),
            )
            self.all_servers = servers
        for server in servers:
            res = self.benchmark_results.get(server.id, {})
            if hasattr(self, 'benchmark_table'):
                self.benchmark_table.insert(
                    "",
                    tk.END,
                    iid=server.id,
                    values=self.format_row_values(server, res),
                    tags=self.get_row_tags(res),
                )

    def update_row(self, server_id: str, status: Optional[str] = None) -> None:
        server = next((s for s in self.all_servers if s.id == server_id), None)
        if server is None:
            return
        res = self.benchmark_results.get(server_id, {})
        if hasattr(self, 'benchmark_table') and self.benchmark_table.exists(server_id):
            self.benchmark_table.item(
                server_id,
                values=self.format_row_values(server, res, status=status),
                tags=self.get_row_tags(res),
            )

    def on_run_benchmark(self) -> None:
        if self.benchmark_thread and self.benchmark_thread.is_alive():
            messagebox.showinfo("Benchmark", "Benchmark is already running.", parent=self)
            return
        self.benchmark_cancel_event.clear()
        self.benchmark_results = {}
        self.refresh_table()
        self.set_status("Running benchmark...")
        self.progress_bar.config(maximum=len(self.all_servers), value=0)
        self.recommend_frame.pack_forget()
        self.start_test_button.config(text="Stop DNS Test")
        self.benchmark_thread = threading.Thread(target=self.benchmark_worker, daemon=True)
        self.benchmark_thread.start()

    def benchmark_worker(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._benchmark_coro())
        finally:
            loop.close()

    async def _benchmark_coro(self) -> None:
        ok, msg = flush_dns()
        self.after(0, self.set_status, msg)
        timeout_ms = self.config_obj.get("timeout", 2000)
        queries = self.config_obj.get("queries_per_domain", 10)
        turbo_enabled = self.turbo_enabled_var.get()
        try:
            turbo_ms = int(self.turbo_var.get())
        except ValueError:
            turbo_ms = 0
        for index, server in enumerate(self.all_servers, start=1):
            if self.benchmark_cancel_event.is_set():
                break
            self.after(0, self.update_row, server.id, "Testing...")
            self.after(0, self.set_status, f"Benchmarking {server.name} ({index}/{len(self.all_servers)})...")
            stats = await run_speed_test(
                server,
                self.test_domains,
                timeout_ms / 1000.0,
                queries,
                turbo_enabled=turbo_enabled,
                turbo_timeout_ms=turbo_ms if turbo_enabled else 0,
                cancel_event=self.benchmark_cancel_event,
            )
            if self.benchmark_cancel_event.is_set():
                break
            self.benchmark_results[server.id] = stats
            self.after(0, self.update_row, server.id)
            self.after(0, self.progress_bar.step, 1)
            await asyncio.sleep(0)
        if self.benchmark_cancel_event.is_set():
            self.after(0, self.on_benchmark_cancelled)
        else:
            self.after(0, self.on_benchmark_complete)

    def on_benchmark_complete(self) -> None:
        self.refresh_table(sort_results=True)
        self.set_status("Benchmark completed. Recommended DNS is shown below.")
        self.show_recommended_dns()

    def on_benchmark_settings(self) -> None:
        dialog = BenchmarkSettingsDialog(self, self.config_obj.get("timeout", 2000), self.config_obj.get("queries_per_domain", 10))
        result = dialog.show()
        if result is None:
            return
        timeout, queries = result
        self.config_obj["timeout"] = timeout
        self.config_obj["queries_per_domain"] = queries
        save_config(self.config_obj)
        self.set_status(f"Benchmark settings updated: timeout={timeout}ms, queries={queries}")

    def show_recommended_dns(self) -> None:
        winners = [server for server in self.all_servers if server.id in self.benchmark_results and not self.benchmark_results[server.id].get("hijacked")]
        winners.sort(key=lambda srv: self.benchmark_results[srv.id].get("score", -1.0), reverse=True)
        if not winners:
            self.recommend_frame.pack_forget()
            self.safe_var.set("Unsafe")
            return
        primary = winners[0].primary
        secondary = winners[0].secondary or (winners[1].primary if len(winners) > 1 else "")
        best_score = self.benchmark_results[winners[0].id]
        self.primary_var.set(primary)
        self.secondary_var.set(secondary)
        self.custom_primary_var.set(primary)
        self.custom_secondary_var.set(secondary)
        self.safe_var.set(self.get_score_label(best_score))
        self.recommend_frame.pack(fill=tk.X, padx=6, pady=(0, 6))

    def open_donate_link(self) -> None:
        try:
            import webbrowser
            webbrowser.open("https://github.com/sponsors")
        except Exception:
            pass

    def on_apply_recommended(self) -> None:
        if self.dhcp_enabled.get():
            adapter = self.get_selected_adapter_name()
            if adapter is None:
                messagebox.showerror("Adapter Selection", "Select a network adapter first.", parent=self)
                return
            self.apply_dhcp_to_adapter(adapter)
            return
        primary = self.primary_var.get().strip()
        secondary = self.secondary_var.get().strip()
        if not primary:
            messagebox.showerror("Recommended DNS", "Primary DNS address is required.", parent=self)
            return
        adapter = self.get_selected_adapter_name()
        if adapter is None:
            messagebox.showerror("Adapter Selection", "Select a network adapter first.", parent=self)
            return
        self.apply_dns_to_adapter(adapter, primary, secondary)

    def on_apply_mixed_dns(self) -> None:
        adapter = self.get_selected_adapter_name()
        if adapter is None:
            messagebox.showerror("Adapter Selection", "Select a network adapter first.", parent=self)
            return
        winners = [server for server in self.all_servers if server.id in self.benchmark_results and not self.benchmark_results[server.id].get("hijacked")]
        winners.sort(key=lambda srv: self.benchmark_results[srv.id].get("score", -1.0), reverse=True)
        if len(winners) < 2:
            messagebox.showwarning("Mixed DNS", "Need at least two non-hijacked benchmarked DNS servers.", parent=self)
            return
        primary = winners[0].primary
        secondary = winners[1].primary
        self.primary_var.set(primary)
        self.secondary_var.set(secondary)
        self.apply_dns_to_adapter(adapter, primary, secondary)

    def apply_dns_to_adapter(self, adapter_name: str, primary: str, secondary: str) -> None:
        dns_server = DNSServer("recommended", "Recommended DNS", primary, secondary)
        self.set_status("Applying DNS...")
        self.apply_server_button.config(state="disabled")
        self.start_test_button.config(state="disabled")
        thread = threading.Thread(target=self._apply_dns_worker, args=(adapter_name, dns_server), daemon=True)
        thread.start()

    def _apply_dns_worker(self, adapter_name: str, dns_server: DNSServer) -> None:
        messages: List[str] = []
        all_ok = True
        adapters = [a["name"] for a in get_network_adapters()] if adapter_name == ALL_ADAPTERS_NAME else [adapter_name]
        for adapter in adapters:
            ok, msg = set_dns(adapter, dns_server)
            all_ok = all_ok and ok
            messages.append(f"{adapter}: {msg}")
        flush_dns()
        status = "DNS applied to all adapters." if all_ok else "Some adapters failed."
        self.after(0, self.set_status, status)
        if adapter_name != ALL_ADAPTERS_NAME and all_ok:
            self.config_obj["selected_adapter"] = adapter_name
            save_config(self.config_obj)
        self.after(0, lambda: messagebox.showinfo("Set DNS", "\n".join(messages), parent=self))
        self.after(0, lambda: self.apply_server_button.config(state="normal"))
        self.after(0, lambda: self.start_test_button.config(state="normal"))

    def apply_dhcp_to_adapter(self, adapter_name: str) -> None:
        messages: List[str] = []
        all_ok = True
        adapters = [a["name"] for a in get_network_adapters()] if adapter_name == ALL_ADAPTERS_NAME else [adapter_name]
        for adapter in adapters:
            ok, msg = set_dhcp(adapter)
            all_ok = all_ok and ok
            messages.append(f"{adapter}: {msg}")
        flush_dns()
        self.set_status("DHCP enabled on all adapters." if all_ok else "Some adapters failed.")
        if adapter_name != ALL_ADAPTERS_NAME and all_ok:
            self.config_obj["selected_adapter"] = adapter_name
            save_config(self.config_obj)
        messagebox.showinfo("DHCP", "\n".join(messages), parent=self)

    def get_selected_custom_dns(self) -> Optional[DNSServer]:
        selected_name = self.server_var.get()
        custom = [DNSServer.from_dict(item) for item in self.config_obj["custom_dns"]]
        return next((s for s in custom if s.name == selected_name), None)

    def on_add_dns(self) -> None:
        dialog = AddEditDNSDialog(self)
        result = dialog.show()
        if result is None:
            return
        custom = [DNSServer.from_dict(item) for item in self.config_obj["custom_dns"]]
        custom.append(result)
        self.config_obj["custom_dns"] = [server.to_dict() for server in custom]
        save_config(self.config_obj)
        self.all_servers = [DNSServer.from_dict(item) for item in self.config_obj["dns_servers"]] + custom
        self.update_dns_server_list()
        self.refresh_table()
        self.set_status(f"Added {result.name}.")

    def on_edit_dns(self) -> None:
        server = self.get_selected_custom_dns()
        if server is None:
            messagebox.showwarning("Edit DNS", "Select a custom DNS server from the dropdown first.", parent=self)
            return
        dialog = AddEditDNSDialog(self, server)
        result = dialog.show()
        if result is None:
            return
        custom = [DNSServer.from_dict(item) for item in self.config_obj["custom_dns"]]
        for index, item in enumerate(custom):
            if item.id == result.id:
                custom[index] = result
                break
        self.config_obj["custom_dns"] = [server.to_dict() for server in custom]
        save_config(self.config_obj)
        self.all_servers = [DNSServer.from_dict(item) for item in self.config_obj["dns_servers"]] + custom
        self.update_dns_server_list()
        self.refresh_table()
        self.set_status(f"Updated {result.name}.")

    def on_remove_dns(self) -> None:
        server = self.get_selected_custom_dns()
        if server is None:
            messagebox.showwarning("Remove DNS", "Select a custom DNS server from the dropdown first.", parent=self)
            return
        custom = [DNSServer.from_dict(item) for item in self.config_obj["custom_dns"]]
        custom = [item for item in custom if item.id != server.id]
        self.config_obj["custom_dns"] = [item.to_dict() for item in custom]
        save_config(self.config_obj)
        self.all_servers = [DNSServer.from_dict(item) for item in self.config_obj["dns_servers"]] + custom
        self.update_dns_server_list()
        self.refresh_table()
        self.set_status("Removed custom DNS server.")

    def on_manage_domains(self) -> None:
        dialog = ManageDomainsDialog(self, self.test_domains)
        result = dialog.show()
        if result is None:
            return
        self.test_domains = result
        self.config_obj["test_domains"] = result
        save_config(self.config_obj)
        self.set_status("Test domains updated.")

    def on_scan_dns(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Scan DNS", "A scan is already running. Use Stop Scan to cancel it.", parent=self)
            return
        dialog = ScanDNSDialog(self)
        result = dialog.show()
        if result is None:
            return
        target_spec, port = result
        self.scan_cancel_event.clear()
        self.discovered_scan_hosts = []
        self.scan_log.delete("1.0", tk.END)
        self.scan_hosts_list.delete(0, tk.END)
        self.scan_target_var.set(target_spec)
        self.scan_port_var.set(str(port))
        self.scan_total_var.set("0")
        self.scan_found_var.set("0")
        self.scan_added_var.set("0")
        self.scan_log.insert(tk.END, f"Starting scan for {target_spec}:{port}\n")
        self.scan_status_var.set(f"Scanning {target_spec}:{port}...")
        self.set_status(f"Scanning {target_spec}:{port}...")
        self.progress_bar.config(mode="indeterminate")
        self.progress_bar.start(15)
        self.scan_progress_bar.config(mode="indeterminate")
        self.scan_progress_bar.start(15)
        self.scan_stop_button.config(state="normal")
        self.scan_thread = threading.Thread(target=self.scan_worker, args=(target_spec, port), daemon=True)
        self.scan_thread.start()

    def on_add_discovered_dns(self) -> None:
        if not self.discovered_scan_hosts:
            messagebox.showinfo("Add Discovered DNS", "Run a scan first to discover hosts.", parent=self)
            return
        custom = [DNSServer.from_dict(item) for item in self.config_obj["custom_dns"]]
        existing_ips = {server.primary for server in custom} | {server.primary for server in [DNSServer.from_dict(item) for item in self.config_obj["dns_servers"]]}
        new_entries: List[DNSServer] = []
        for host in self.discovered_scan_hosts:
            if host in existing_ips:
                continue
            new_server = DNSServer(f"discovered_{host.replace('.', '_')}_{int(time.time())}", f"Discovered DNS {host}", host, "", self.scan_port_var.get())
            custom.append(new_server)
            new_entries.append(new_server)
            existing_ips.add(host)
        self.config_obj["custom_dns"] = [server.to_dict() for server in custom]
        save_config(self.config_obj)
        self.all_servers = [DNSServer.from_dict(item) for item in self.config_obj["dns_servers"]] + custom
        self.update_dns_server_list()
        self.refresh_table(sort_results=True)
        self.scan_added_var.set(str(len(new_entries)))
        self.scan_log.insert(tk.END, f"Added {len(new_entries)} discovered DNS entries to the custom list.\n")
        self.set_status(f"Added {len(new_entries)} discovered DNS entries.")

    def scan_worker(self, target_spec: str, port: int) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            hosts = parse_scan_targets(target_spec)
            self.after(0, self.scan_status_var.set, f"Scanning DNS hosts 0/{len(hosts)}...")
            self.after(0, self.scan_total_var.set, str(len(hosts)))
            self.after(0, self.scan_log.insert, tk.END, f"Preparing {len(hosts)} hosts to test.\n")
            found_hosts: List[str] = []

            def update_progress(done: int, total: int) -> None:
                if self.scan_cancel_event.is_set():
                    return
                self.after(0, self.scan_status_var.set, f"Scanning DNS hosts {done}/{total}...")
                self.after(0, self.scan_log.insert, tk.END, f"Probed {done}/{total} hosts\n")

            found_hosts = loop.run_until_complete(
                scan_dns_targets(
                    hosts,
                    port,
                    self.config_obj.get("timeout", 2) / 1000.0,
                    progress_callback=update_progress,
                    cancel_event=self.scan_cancel_event,
                )
            )
            if self.scan_cancel_event.is_set():
                self.after(0, self.scan_status_var.set, "Scan stopped.")
                self.after(0, self.scan_log.insert, tk.END, "Scan was cancelled by the user.\n")
                self.after(0, lambda: self.set_status("Scan stopped."))
                return
            self.discovered_scan_hosts = found_hosts
            if not found_hosts:
                self.after(0, lambda: messagebox.showwarning("Scan DNS", "No DNS services discovered.", parent=self))
                self.after(0, lambda: self.set_status("No DNS services discovered."))
                self.after(0, self.scan_status_var.set, "No DNS services discovered.")
                self.after(0, self.scan_log.insert, tk.END, "No DNS services discovered.\n")
                self.after(0, self.scan_found_var.set, "0")
                self.after(0, self.scan_added_var.set, "0")
                return
            custom = [DNSServer.from_dict(item) for item in self.config_obj["custom_dns"]]
            existing_ips = {server.primary for server in custom} | {server.primary for server in [DNSServer.from_dict(item) for item in self.config_obj["dns_servers"]]}
            discovered_servers: List[str] = []
            for host in found_hosts:
                if host in existing_ips:
                    continue
                discovered_servers.append(host)
            self.after(0, self.scan_found_var.set, str(len(found_hosts)))
            self.after(0, self.scan_added_var.set, str(len(discovered_servers)))
            self.after(0, self.scan_log.insert, tk.END, f"Discovered {len(found_hosts)} host(s); {len(discovered_servers)} new host(s) pending import.\n")
            self.after(0, lambda: self.on_scan_complete(len(found_hosts), len(discovered_servers)))
            self.after(0, self.scan_hosts_list.delete, 0, tk.END)
            for host in found_hosts:
                self.after(0, self.scan_hosts_list.insert, tk.END, host)
            if discovered_servers:
                timeout_ms = self.config_obj.get("timeout", 2000)
                queries = self.config_obj.get("queries_per_domain", 10)
                for host in discovered_servers:
                    if self.scan_cancel_event.is_set():
                        break
                    temp_server = DNSServer(f"discovered_{host.replace('.', '_')}_{int(time.time())}", f"Discovered DNS {host}", host, "", port)
                    stats = loop.run_until_complete(run_speed_test(temp_server, self.test_domains, timeout_ms / 1000.0, queries))
                    self.benchmark_results[temp_server.id] = stats
                    self.after(0, self.scan_log.insert, tk.END, f"Benchmarked discovered host {host}\n")
        except Exception as exc:
            self.after(0, lambda: messagebox.showerror("Scan DNS", str(exc), parent=self))
            self.after(0, self.scan_status_var.set, "Scan failed.")
            self.after(0, self.scan_log.insert, tk.END, f"Scan failed: {exc}\n")
        finally:
            self.after(0, self.progress_bar.stop)
            self.after(0, lambda: self.progress_bar.config(mode="determinate", value=0))
            self.after(0, self.scan_progress_bar.stop)
            self.after(0, lambda: self.scan_progress_bar.config(mode="determinate", value=0))
            self.after(0, self.scan_stop_button.config, state="disabled")
            if not self.scan_cancel_event.is_set():
                self.after(0, lambda: self.set_status("Scan completed."))
                self.after(0, self.scan_status_var.set, "Scan completed.")
                self.after(0, self.scan_log.insert, tk.END, "Scan completed.\n")

    def on_scan_complete(self, found: int, added: int) -> None:
        self.all_servers = [DNSServer.from_dict(item) for item in self.config_obj["dns_servers"]] + [DNSServer.from_dict(item) for item in self.config_obj["custom_dns"]]
        self.refresh_table(sort_results=True)
        self.set_status(f"Discovered {found} hosts, added {added} new entries.")

    def on_flush_dns(self) -> None:
        ok, msg = flush_dns()
        self.set_status(msg)
        if ok:
            messagebox.showinfo("Flush DNS", msg, parent=self)
        else:
            messagebox.showerror("Flush DNS", msg, parent=self)

    def on_set_dns(self) -> None:
        adapter = self.get_selected_adapter_name()
        if adapter is None:
            messagebox.showwarning("Set DNS", "Select a network adapter first.", parent=self)
            return
        if self.dhcp_enabled.get():
            self.apply_dhcp_to_adapter(adapter)
            return
        selected_server = self.get_selected_dns_server()
        if selected_server is None:
            messagebox.showwarning("Set DNS", "Select a server or enter a valid custom DNS first.", parent=self)
            return
        if not self.validate_dns_address(selected_server.primary):
            messagebox.showerror("Set DNS", "Primary DNS address is not valid.", parent=self)
            return
        top_servers = [server for server in self.all_servers
                       if server.id in self.benchmark_results
                       and not self.benchmark_results[server.id].get("hijacked")]
        top_servers.sort(key=lambda srv: self.benchmark_results[srv.id].get("score", -1.0), reverse=True)
        primary = selected_server.primary
        secondary = selected_server.secondary
        if not secondary and not self.custom_dns_enabled.get() and top_servers:
            if top_servers[0].id == selected_server.id and len(top_servers) > 1:
                secondary = top_servers[1].primary
            else:
                for candidate in top_servers:
                    if candidate.id != selected_server.id and candidate.primary != primary:
                        secondary = candidate.primary
                        break
        self.apply_dns_to_adapter(adapter, primary, secondary)


def main() -> None:
    app = DNSBenchmarkApp()
    app.mainloop()


if __name__ == "__main__":
    main()