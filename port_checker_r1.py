#!/usr/bin/env python3
"""
port_checker_r1.py
Version: 1.1.0

Ruckus One readiness checker using Python built-in libraries only.

What it checks
--------------
- DNS resolution for all entries
- TCP connect for TCP services
- UDP basic probe for UDP services
- TLS handshake and certificate validity for TCP/443 services
- Region readiness for Ruckus One zones: GLOBAL, US, EU, APAC

Host file format
----------------
Use markdown-style headings to group services:

    # GLOBAL
    ap-registrar.ruckuswireless.com,443
    sw-registrar.ruckuswireless.com,443
    storage.googleapis.com,443

    # US
    ruckus.cloud,443
    device.ruckus.cloud,443
    edge-docker-registry.ruckus.cloud,443
    outgoing.ruckus.cloud,1812
    outgoing.ruckus.cloud,1813

    # EU
    eu.ruckus.cloud,443
    device.eu.ruckus.cloud,443

    # APAC
    asia.ruckus.cloud,443
    device.asia.ruckus.cloud,443

Input formats supported
-----------------------
    host,port
    host,port,protocol
    host,port,protocol,description
    https://ruckus.cloud
    device.ruckus.cloud:443

Notes
-----
- Markdown headings are recognised: # GLOBAL, ## US, ### EU, # APAC, # ASIA
- Blank lines are ignored.
- Comment lines starting with # are ignored unless they are recognised zone headings.
- If protocol is omitted, TCP is assumed except ports 1812 and 1813, which default to UDP.
- For zone readiness, TCP/443 requires DNS OK, TCP OPEN, TLS OK and cert_valid True.
- TCP/80 and TCP/22 require DNS OK and TCP OPEN.
- UDP services default to DNS-only pass logic to avoid false failure from generic UDP probes.
  Use --udp-strict if you want UDP_NO_RESPONSE to fail readiness.

Example usage
-------------
    python3 port_checker_r1.py -i hosts_r1.csv
    python3 port_checker_r1.py -i hosts_r1.csv -o results.csv -j results.json
    python3 port_checker_r1.py -i hosts_r1.csv --workers 30 --timeout 5
    python3 port_checker_r1.py -i hosts_r1.csv --udp-strict
"""

import argparse
import csv
import json
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

VERSION = "1.1.0"
DEFAULT_TIMEOUT = 5.0
DEFAULT_WORKERS = 20
DEFAULT_CERT_WARNING_DAYS = 30
CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"
UDP_DEFAULT_PORTS = {1812, 1813}
KNOWN_ZONES = {"GLOBAL", "US", "EU", "APAC", "ASIA"}
READINESS_ZONES = ["GLOBAL", "US", "EU", "APAC"]

RESULT_FIELDS = [
    "timestamp_utc", "zone", "service_pass", "service_pass_reason",
    "status", "host", "port", "protocol", "description",
    "dns_status", "dns_ip", "dns_all_ips", "dns_ms",
    "tcp_status", "tcp_ms", "udp_status", "udp_ms",
    "tls_status", "tls_ms", "cert_valid", "cert_status",
    "cert_not_before", "cert_not_after", "cert_days_since_start",
    "cert_days_remaining", "cert_total_days", "cert_subject", "cert_issuer",
    "error",
]

STATUS_PRIORITY = {
    "DNS_FAIL": 10,
    "TCP_TIMEOUT": 20,
    "TCP_FAIL": 30,
    "TLS_FAIL": 40,
    "CERT_INVALID": 50,
    "CERT_NOT_YET_VALID": 55,
    "CERT_EXPIRED": 60,
    "CERT_EXPIRING_SOON": 70,
    "UDP_UNREACHABLE": 80,
    "UDP_NO_RESPONSE": 90,
    "UNSUPPORTED_PROTOCOL": 900,
    "OK": 999,
}


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_zone(value):
    value = (value or "GLOBAL").strip().upper()
    if value == "ASIA":
        return "APAC"
    if value in READINESS_ZONES:
        return value
    return "GLOBAL"


def parse_zone_heading(line):
    stripped = line.strip()
    if not stripped.startswith("#"):
        return None
    text = stripped.lstrip("#").strip()
    if not text:
        return None
    first = text.split()[0].upper()
    if first in KNOWN_ZONES:
        return normalize_zone(first)
    return None


def empty_result(host, port, protocol, zone="GLOBAL", description=""):
    return {
        "timestamp_utc": utc_now_iso(),
        "zone": normalize_zone(zone),
        "service_pass": False,
        "service_pass_reason": "NOT_EVALUATED",
        "status": "UNKNOWN",
        "host": host,
        "port": int(port),
        "protocol": protocol.upper(),
        "description": description,
        "dns_status": "NOT_CHECKED",
        "dns_ip": "",
        "dns_all_ips": "",
        "dns_ms": "",
        "tcp_status": "NOT_CHECKED",
        "tcp_ms": "",
        "udp_status": "NOT_CHECKED",
        "udp_ms": "",
        "tls_status": "NOT_CHECKED",
        "tls_ms": "",
        "cert_valid": "",
        "cert_status": "NOT_CHECKED",
        "cert_not_before": "",
        "cert_not_after": "",
        "cert_days_since_start": "",
        "cert_days_remaining": "",
        "cert_total_days": "",
        "cert_subject": "",
        "cert_issuer": "",
        "error": "",
    }


def infer_port_from_scheme(scheme):
    scheme = (scheme or "").lower()
    if scheme == "https":
        return 443
    if scheme == "http":
        return 80
    return None


def strip_url_to_host_port(value):
    value = value.strip()
    if not value:
        return "", None
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        return parsed.hostname or "", parsed.port or infer_port_from_scheme(parsed.scheme)
    if value.count(":") == 1:
        host_part, port_part = value.rsplit(":", 1)
        if port_part.isdigit():
            return host_part.strip(), int(port_part)
    return value, None


def normalize_protocol(protocol, port):
    if protocol:
        return protocol.strip().upper()
    if int(port) in UDP_DEFAULT_PORTS:
        return "UDP"
    return "TCP"


def is_header_row(fields):
    normalized = [f.strip().lower() for f in fields]
    return bool(normalized and normalized[0] in {"host", "hostname", "fqdn", "url"})


def parse_hosts_file(path):
    targets = []
    path = Path(path)
    current_zone = "GLOBAL"

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue

            heading_zone = parse_zone_heading(line)
            if heading_zone:
                current_zone = heading_zone
                continue

            if line.startswith("#"):
                continue

            if " #" in line:
                line = line.split(" #", 1)[0].strip()

            try:
                fields = next(csv.reader([line]))
            except csv.Error as exc:
                print(f"Skipping line {line_number}: CSV parse error: {exc}", file=sys.stderr)
                continue

            fields = [f.strip() for f in fields]
            if not fields or is_header_row(fields):
                continue

            host = ""
            port = None
            protocol = ""
            description = ""
            explicit_zone = ""

            if len(fields) == 1:
                host, port = strip_url_to_host_port(fields[0])
                if port is None:
                    port = 443
            else:
                host, inferred_port = strip_url_to_host_port(fields[0])
                port_text = fields[1] if len(fields) > 1 else ""
                if port_text:
                    try:
                        port = int(port_text)
                    except ValueError:
                        port = inferred_port or 443
                        protocol = port_text
                else:
                    port = inferred_port or 443
                if len(fields) > 2:
                    protocol = fields[2]
                if len(fields) > 3:
                    description = fields[3]
                if len(fields) > 4:
                    explicit_zone = fields[4]

            if not host:
                print(f"Skipping line {line_number}: empty host", file=sys.stderr)
                continue

            try:
                port = int(port)
                if port < 1 or port > 65535:
                    raise ValueError("port out of range")
            except (TypeError, ValueError):
                print(f"Skipping line {line_number}: invalid port '{port}'", file=sys.stderr)
                continue

            protocol = normalize_protocol(protocol, port)
            zone = normalize_zone(explicit_zone or current_zone)
            targets.append({
                "host": host,
                "port": port,
                "protocol": protocol,
                "description": description,
                "zone": zone,
                "source_line": line_number,
            })

    return targets


def resolve_dns(host, result):
    start = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        ips = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        result["dns_status"] = "OK"
        result["dns_ip"] = ips[0] if ips else ""
        result["dns_all_ips"] = ";".join(ips)
        result["dns_ms"] = round((time.perf_counter() - start) * 1000, 2)
        return ips
    except (socket.gaierror, OSError) as exc:
        result["dns_status"] = "FAIL"
        result["dns_ms"] = round((time.perf_counter() - start) * 1000, 2)
        result["status"] = "DNS_FAIL"
        result["error"] = str(exc)
        return []


def tcp_connect(host, port, timeout, result):
    start = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        result["tcp_status"] = "OPEN"
        result["tcp_ms"] = round((time.perf_counter() - start) * 1000, 2)
        return sock
    except socket.timeout as exc:
        result["tcp_status"] = "TIMEOUT"
        result["tcp_ms"] = round((time.perf_counter() - start) * 1000, 2)
        result["status"] = "TCP_TIMEOUT"
        result["error"] = str(exc)
        return None
    except OSError as exc:
        result["tcp_status"] = "FAIL"
        result["tcp_ms"] = round((time.perf_counter() - start) * 1000, 2)
        result["status"] = "TCP_FAIL"
        result["error"] = str(exc)
        return None


def parse_cert_time(value):
    if not value:
        return None
    return datetime.strptime(value, CERT_DATE_FORMAT).replace(tzinfo=timezone.utc)


def format_cert_name(name_tuple):
    if not name_tuple:
        return ""
    parts = []
    for section in name_tuple:
        for key, value in section:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def set_cert_status(result, not_before, not_after, warning_days):
    now = datetime.now(timezone.utc)
    if not_before:
        result["cert_not_before"] = not_before.isoformat(timespec="seconds")
    if not_after:
        result["cert_not_after"] = not_after.isoformat(timespec="seconds")
    if not_before and not_after:
        result["cert_days_since_start"] = max((now - not_before).days, 0)
        result["cert_days_remaining"] = (not_after - now).days
        result["cert_total_days"] = (not_after - not_before).days
    if not_before and now < not_before:
        result["cert_valid"] = False
        result["cert_status"] = "NOT_YET_VALID"
        result["status"] = "CERT_NOT_YET_VALID"
    elif not_after and now > not_after:
        result["cert_valid"] = False
        result["cert_status"] = "EXPIRED"
        result["status"] = "CERT_EXPIRED"
    else:
        result["cert_valid"] = True
        days_remaining = result.get("cert_days_remaining")
        if isinstance(days_remaining, int) and days_remaining <= warning_days:
            result["cert_status"] = "EXPIRING_SOON"
            result["status"] = "CERT_EXPIRING_SOON"
        else:
            result["cert_status"] = "OK"
            result["status"] = "OK"


def tls_and_cert_check(host, port, timeout, warning_days, result):
    start = time.perf_counter()
    raw_sock = None
    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        context = ssl.create_default_context()
        with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            result["tls_status"] = "OK"
            result["tls_ms"] = round((time.perf_counter() - start) * 1000, 2)
            cert = tls_sock.getpeercert()
            result["cert_subject"] = format_cert_name(cert.get("subject"))
            result["cert_issuer"] = format_cert_name(cert.get("issuer"))
            set_cert_status(
                result,
                parse_cert_time(cert.get("notBefore")),
                parse_cert_time(cert.get("notAfter")),
                warning_days,
            )
    except ssl.SSLCertVerificationError as exc:
        result["tls_status"] = "CERT_VERIFY_FAIL"
        result["tls_ms"] = round((time.perf_counter() - start) * 1000, 2)
        result["cert_valid"] = False
        result["cert_status"] = "VERIFY_FAIL"
        result["status"] = "CERT_INVALID"
        result["error"] = str(exc)
    except ssl.SSLError as exc:
        result["tls_status"] = "TLS_FAIL"
        result["tls_ms"] = round((time.perf_counter() - start) * 1000, 2)
        result["cert_valid"] = False
        result["status"] = "TLS_FAIL"
        result["error"] = str(exc)
    except socket.timeout as exc:
        result["tls_status"] = "TIMEOUT"
        result["tls_ms"] = round((time.perf_counter() - start) * 1000, 2)
        result["status"] = "TLS_FAIL"
        result["error"] = str(exc)
    except OSError as exc:
        result["tls_status"] = "TLS_SOCKET_FAIL"
        result["tls_ms"] = round((time.perf_counter() - start) * 1000, 2)
        result["status"] = "TLS_FAIL"
        result["error"] = str(exc)
    finally:
        try:
            if raw_sock:
                raw_sock.close()
        except OSError:
            pass
    return result


def evaluate_service_pass(result, udp_strict=False):
    protocol = result.get("protocol")
    port = int(result.get("port", 0))
    if result.get("dns_status") != "OK":
        result["service_pass"] = False
        result["service_pass_reason"] = "DNS failed"
        return result

    if protocol == "TCP" and port == 443:
        if result.get("tcp_status") == "OPEN" and result.get("tls_status") == "OK" and result.get("cert_valid") is True:
            result["service_pass"] = True
            if result.get("status") == "CERT_EXPIRING_SOON":
                result["service_pass_reason"] = "PASS with certificate expiry warning"
            else:
                result["service_pass_reason"] = "DNS, TCP, TLS and certificate valid"
        else:
            result["service_pass"] = False
            result["service_pass_reason"] = "443 requires DNS OK, TCP OPEN, TLS OK and valid certificate"
        return result

    if protocol == "TCP":
        result["service_pass"] = result.get("tcp_status") == "OPEN"
        result["service_pass_reason"] = "DNS OK and TCP OPEN" if result["service_pass"] else "TCP not open"
        return result

    if protocol == "UDP":
        if udp_strict:
            result["service_pass"] = result.get("udp_status") == "RESPONSE"
            result["service_pass_reason"] = "UDP response received" if result["service_pass"] else "UDP did not respond"
        else:
            result["service_pass"] = result.get("dns_status") == "OK"
            result["service_pass_reason"] = "DNS OK; UDP response not required in default mode"
        return result

    result["service_pass"] = False
    result["service_pass_reason"] = "Unsupported protocol"
    return result


def check_tcp_target(target, timeout, tls_all, warning_days, udp_strict):
    result = empty_result(target["host"], target["port"], "TCP", target.get("zone", "GLOBAL"), target.get("description", ""))
    if not resolve_dns(target["host"], result):
        return evaluate_service_pass(result, udp_strict)
    sock = tcp_connect(target["host"], int(target["port"]), timeout, result)
    if sock is None:
        return evaluate_service_pass(result, udp_strict)
    try:
        sock.close()
    except OSError:
        pass
    if int(target["port"]) == 443 or tls_all:
        result = tls_and_cert_check(target["host"], int(target["port"]), timeout, warning_days, result)
    else:
        result["status"] = "OK"
    return evaluate_service_pass(result, udp_strict)


def check_udp_target(target, timeout, udp_strict):
    result = empty_result(target["host"], target["port"], "UDP", target.get("zone", "GLOBAL"), target.get("description", ""))
    if not resolve_dns(target["host"], result):
        return evaluate_service_pass(result, udp_strict)

    start = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b"port-check", (target["host"], int(target["port"])))
        try:
            sock.recvfrom(1024)
            result["udp_status"] = "RESPONSE"
            result["udp_ms"] = round((time.perf_counter() - start) * 1000, 2)
            result["status"] = "OK"
        except socket.timeout:
            result["udp_status"] = "NO_RESPONSE"
            result["udp_ms"] = round((time.perf_counter() - start) * 1000, 2)
            result["status"] = "UDP_NO_RESPONSE"
            result["error"] = "No UDP response. This can be normal for UDP services that ignore generic probes."
    except ConnectionRefusedError as exc:
        result["udp_status"] = "UNREACHABLE"
        result["udp_ms"] = round((time.perf_counter() - start) * 1000, 2)
        result["status"] = "UDP_UNREACHABLE"
        result["error"] = str(exc)
    except OSError as exc:
        result["udp_status"] = "FAIL"
        result["udp_ms"] = round((time.perf_counter() - start) * 1000, 2)
        result["status"] = "UDP_UNREACHABLE"
        result["error"] = str(exc)
    finally:
        sock.close()
    return evaluate_service_pass(result, udp_strict)


def check_target(target, timeout, tls_all, warning_days, udp_strict):
    protocol = target.get("protocol", "TCP").upper()
    if protocol == "TCP":
        return check_tcp_target(target, timeout, tls_all, warning_days, udp_strict)
    if protocol == "UDP":
        return check_udp_target(target, timeout, udp_strict)
    result = empty_result(target.get("host", ""), target.get("port", 0), protocol, target.get("zone", "GLOBAL"), target.get("description", ""))
    result["status"] = "UNSUPPORTED_PROTOCOL"
    result["error"] = f"Unsupported protocol: {protocol}"
    return evaluate_service_pass(result, udp_strict)


def sort_results(results):
    zone_order = {"GLOBAL": 0, "US": 1, "EU": 2, "APAC": 3}
    return sorted(results, key=lambda r: (
        zone_order.get(r.get("zone", "GLOBAL"), 9),
        STATUS_PRIORITY.get(r.get("status", "UNKNOWN"), 500),
        str(r.get("host", "")).lower(),
        int(r.get("port", 0)),
        str(r.get("protocol", "")),
    ))


def summarize_status(results):
    summary = {}
    for result in results:
        status = result.get("status", "UNKNOWN")
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items(), key=lambda item: (STATUS_PRIORITY.get(item[0], 500), item[0])))


def zone_stats(results, zone):
    zone = normalize_zone(zone)
    items = [r for r in results if r.get("zone") == zone]
    passed = sum(1 for r in items if r.get("service_pass") is True)
    return {
        "zone": zone,
        "status": "PASS" if items and passed == len(items) else "FAIL",
        "passed": passed,
        "total": len(items),
        "failed": len(items) - passed,
        "failures": [r for r in items if r.get("service_pass") is not True],
    }


def build_readiness(results):
    global_stats = zone_stats(results, "GLOBAL")
    readiness = {"GLOBAL": global_stats}
    for zone in ["US", "EU", "APAC"]:
        local = zone_stats(results, zone)
        overall_failures = list(global_stats["failures"]) + list(local["failures"])
        overall_total = global_stats["total"] + local["total"]
        overall_passed = global_stats["passed"] + local["passed"]
        readiness[zone] = {
            "zone": zone,
            "global_status": global_stats["status"],
            "regional_status": local["status"],
            "status": "PASS" if global_stats["status"] == "PASS" and local["status"] == "PASS" else "FAIL",
            "global_passed": global_stats["passed"],
            "global_total": global_stats["total"],
            "regional_passed": local["passed"],
            "regional_total": local["total"],
            "passed": overall_passed,
            "total": overall_total,
            "failed": overall_total - overall_passed,
            "failures": overall_failures,
        }
    return readiness


def compact_failures(failures, limit=3):
    if not failures:
        return "-"
    items = [f"{r.get('host')}:{r.get('port')} {r.get('status')}" for r in failures[:limit]]
    if len(failures) > limit:
        items.append(f"+{len(failures) - limit} more")
    return "; ".join(items)


def print_readiness_table(readiness):
    print()
    print("RUCKUS ONE READINESS")
    print("=" * 100)
    header = f"{'ZONE':<8} {'GLOBAL':<15} {'REGIONAL':<15} {'OVERALL':<15} {'PASS/TOTAL':<12} {'FAILURES'}"
    print(header)
    print("-" * len(header))

    g = readiness["GLOBAL"]
    print(f"{'GLOBAL':<8} {'-':<15} {'-':<15} {g['status']:<15} {str(g['passed']) + '/' + str(g['total']):<12} {compact_failures(g['failures'])}")
    for zone in ["US", "EU", "APAC"]:
        r = readiness[zone]
        pass_total = f"{r['passed']}/{r['total']}"
        print(f"{zone:<8} {r['global_status']:<15} {r['regional_status']:<15} {r['status']:<15} {pass_total:<12} {compact_failures(r['failures'])}")

    passing = [z for z in ["US", "EU", "APAC"] if readiness[z]["status"] == "PASS"]
    print("-" * len(header))
    if passing:
        print("Recommended available R1 zones: " + ", ".join(passing))
    else:
        print("Recommended available R1 zones: none, because no region has both GLOBAL and regional services passing")


def print_results(results):
    print()
    print("DETAILED CHECK RESULTS")
    print("=" * 100)
    header = (
        f"{'ZONE':<7} {'PASS':<5} {'STATUS':<22} {'HOST':<45} {'PORT':<5} "
        f"{'PROTO':<5} {'DNS':<6} {'TCP':<8} {'TLS':<16} {'CERT':<14} {'DAYS':<6} {'IP':<15}"
    )
    print(header)
    print("-" * len(header))
    for r in results:
        days = r.get("cert_days_remaining", "") or "-"
        passed = "YES" if r.get("service_pass") is True else "NO"
        print(
            f"{r.get('zone',''):<7} {passed:<5} {str(r.get('status','')):<22} "
            f"{str(r.get('host','')):<45} {str(r.get('port','')):<5} {str(r.get('protocol','')):<5} "
            f"{str(r.get('dns_status','-')):<6} {str(r.get('tcp_status','-')):<8} "
            f"{str(r.get('tls_status','-')):<16} {str(r.get('cert_status','-')):<14} "
            f"{str(days):<6} {str(r.get('dns_ip','')):<15}"
        )
    print()
    print("Status summary:")
    for status, count in summarize_status(results).items():
        print(f"  {status:<22} {count}")


def write_csv(path, results):
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=RESULT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in results:
            writer.writerow(row)


def json_ready_readiness(readiness):
    clean = {}
    for zone, data in readiness.items():
        clean[zone] = {k: v for k, v in data.items() if k != "failures"}
        clean[zone]["failures"] = [
            {
                "zone": r.get("zone"),
                "host": r.get("host"),
                "port": r.get("port"),
                "protocol": r.get("protocol"),
                "status": r.get("status"),
                "service_pass_reason": r.get("service_pass_reason"),
                "error": r.get("error"),
            }
            for r in data.get("failures", [])
        ]
    return clean


def build_json_payload(results, readiness, args, started_at, finished_at):
    return {
        "metadata": {
            "tool": "port_checker_r1.py",
            "version": VERSION,
            "started_at_utc": started_at,
            "finished_at_utc": finished_at,
            "input_file": str(args.input),
            "result_count": len(results),
            "timeout_seconds": args.timeout,
            "workers": args.workers,
            "tls_all": args.tls_all,
            "udp_strict": args.udp_strict,
            "cert_warning_days": args.cert_warning_days,
            "status_summary": summarize_status(results),
        },
        "readiness": json_ready_readiness(readiness),
        "results": results,
    }


def write_json(path, payload):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)


def archive_json(payload, archive_dir="json_archive"):
    archive_path = Path(archive_dir)
    archive_path.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive_file = archive_path / f"r1_readiness_{timestamp}.json"
    write_json(archive_file, payload)
    return archive_file


def parse_args():
    parser = argparse.ArgumentParser(description="Ruckus One multi-zone readiness checker.")
    parser.add_argument("-i", "--input", required=True, help="Input hosts CSV/text file")
    parser.add_argument("-o", "--output-csv", default="r1_port_check_results.csv", help="Output CSV file")
    parser.add_argument("-j", "--output-json", default="r1_port_check_results.json", help="Output JSON file")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Socket timeout in seconds")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Concurrent worker threads")
    parser.add_argument("--tls-all", action="store_true", help="Attempt TLS/cert checks for all TCP ports, not only 443")
    parser.add_argument("--udp-strict", action="store_true", help="Require UDP response for UDP services to pass readiness")
    parser.add_argument("--cert-warning-days", type=int, default=DEFAULT_CERT_WARNING_DAYS, help="Warn when certificate has this many days or fewer remaining")
    parser.add_argument("--no-archive", action="store_true", help="Do not create timestamped JSON archive copy")
    return parser.parse_args()


def main():
    args = parse_args()
    started_at = utc_now_iso()
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: Input file not found: {args.input}", file=sys.stderr)
        return 1

    targets = parse_hosts_file(input_path)
    if not targets:
        print("No valid targets found in input file.", file=sys.stderr)
        return 2

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_map = {
            executor.submit(check_target, target, args.timeout, args.tls_all, args.cert_warning_days, args.udp_strict): target
            for target in targets
        }
        for future in as_completed(future_map):
            target = future_map[future]
            try:
                results.append(future.result())
            except Exception as exc:
                result = empty_result(target.get("host", ""), target.get("port", 0), target.get("protocol", ""), target.get("zone", "GLOBAL"), target.get("description", ""))
                result["status"] = "CHECK_ERROR"
                result["error"] = str(exc)
                results.append(result)

    results = sort_results(results)
    readiness = build_readiness(results)
    finished_at = utc_now_iso()
    payload = build_json_payload(results, readiness, args, started_at, finished_at)

    print_readiness_table(readiness)
    print_results(results)

    write_csv(args.output_csv, results)
    write_json(args.output_json, payload)
    print(f"CSV written:  {args.output_csv}")
    print(f"JSON written: {args.output_json}")
    if not args.no_archive:
        archive_file = archive_json(payload)
        print(f"JSON archive: {archive_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
