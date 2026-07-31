#!/usr/bin/env python3
"""
port_checker.py
Version: 1.0.0

Multi-threaded DNS, TCP, UDP, TLS and certificate checker using Python built-in libraries only.

Purpose
-------
Reads a host list from CSV/text and checks outbound connectivity. For TCP/443 targets,
it performs DNS lookup, TCP connect, TLS handshake and certificate validity checks.

Input formats supported
-----------------------
Preferred CSV:
    host,port,protocol,description
    ruckus.cloud,443,TCP,RUCKUS Cloud
    outgoing.ruckus.cloud,1812,UDP,RADIUS Auth

Simplified CSV:
    host,port
    ruckus.cloud,443
    ocsp.entrust.net,80
    outgoing.ruckus.cloud,1812

Also accepted:
    https://ruckus.cloud
    http://ocsp.entrust.net
    device.ruckus.cloud:443
    device.ruckus.cloud,22,TCP

Notes
-----
- Lines starting with # are ignored.
- Blank lines are ignored.
- If protocol is omitted, TCP is assumed except ports 1812 and 1813, which default to UDP.
- URLs are normalized to hostname + inferred port.
- TLS/certificate validation runs automatically for TCP/443.
- Use --tls-all to attempt TLS validation on all TCP ports.

Example usage
-------------
    python3 port_checker.py -i hosts.csv
    python3 port_checker.py -i hosts.csv -o results.csv -j results.json
    python3 port_checker.py -i hosts.csv --workers 20 --timeout 5
    python3 port_checker.py -i hosts.csv --tls-all --cert-warning-days 45

Output
------
- Formatted console table
- CSV result file
- JSON result file with metadata
- Timestamped JSON archive copy, unless disabled with --no-archive
"""

import argparse
import csv
import json
import os
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

VERSION = "1.0.0"
DEFAULT_TIMEOUT = 5.0
DEFAULT_WORKERS = 20
DEFAULT_CERT_WARNING_DAYS = 30
CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"
UDP_DEFAULT_PORTS = {1812, 1813}

RESULT_FIELDS = [
    "timestamp_utc",
    "status",
    "host",
    "port",
    "protocol",
    "description",
    "dns_status",
    "dns_ip",
    "dns_all_ips",
    "dns_ms",
    "tcp_status",
    "tcp_ms",
    "udp_status",
    "udp_ms",
    "tls_status",
    "tls_ms",
    "cert_valid",
    "cert_status",
    "cert_not_before",
    "cert_not_after",
    "cert_days_since_start",
    "cert_days_remaining",
    "cert_total_days",
    "cert_subject",
    "cert_issuer",
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


def empty_result(host, port, protocol, description=""):
    return {
        "timestamp_utc": utc_now_iso(),
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


def normalize_protocol(protocol, port):
    if protocol:
        return protocol.strip().upper()
    if int(port) in UDP_DEFAULT_PORTS:
        return "UDP"
    return "TCP"


def infer_port_from_scheme(scheme):
    scheme = (scheme or "").lower()
    if scheme == "https":
        return 443
    if scheme == "http":
        return 80
    return None


def strip_url_to_host_port(value):
    """Return host, port if input is a URL or host:port. Port may be None."""
    value = value.strip()
    if not value:
        return "", None

    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        host = parsed.hostname or ""
        port = parsed.port or infer_port_from_scheme(parsed.scheme)
        return host, port

    # Handle host:port without breaking IPv6 too badly. Bracketed IPv6 is not a primary target here.
    if value.count(":") == 1:
        host_part, port_part = value.rsplit(":", 1)
        if port_part.isdigit():
            return host_part.strip(), int(port_part)

    return value, None


def is_header_row(fields):
    normalized = [f.strip().lower() for f in fields]
    return bool(normalized and normalized[0] in {"host", "hostname", "fqdn", "url"})


def parse_hosts_file(path):
    targets = []
    path = Path(path)

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            # Remove inline comments only when preceded by whitespace to avoid breaking URLs/fragments.
            if " #" in line:
                line = line.split(" #", 1)[0].strip()

            reader = csv.reader([line])
            try:
                fields = next(reader)
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

            # Single field can be URL, host:port, or hostname. Hostname alone defaults to 443.
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
                        # If second field is not numeric, use inferred/default port and treat it as protocol/description.
                        port = inferred_port or 443
                        protocol = port_text
                else:
                    port = inferred_port or 443

                if len(fields) > 2:
                    protocol = fields[2]

                if len(fields) > 3:
                    description = ",".join(fields[3:]).strip()

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
            targets.append({
                "host": host,
                "port": port,
                "protocol": protocol,
                "description": description,
                "source_line": line_number,
            })

    return targets


def resolve_dns(host, result):
    start = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        elapsed = round((time.perf_counter() - start) * 1000, 2)
        ips = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        result["dns_status"] = "OK"
        result["dns_ip"] = ips[0] if ips else ""
        result["dns_all_ips"] = ";".join(ips)
        result["dns_ms"] = elapsed
        return ips
    except socket.gaierror as exc:
        result["dns_status"] = "FAIL"
        result["dns_ms"] = round((time.perf_counter() - start) * 1000, 2)
        result["status"] = "DNS_FAIL"
        result["error"] = str(exc)
        return []
    except OSError as exc:
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
    tls_start = time.perf_counter()
    raw_sock = None

    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        context = ssl.create_default_context()

        with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            result["tls_status"] = "OK"
            result["tls_ms"] = round((time.perf_counter() - tls_start) * 1000, 2)

            cert = tls_sock.getpeercert()
            result["cert_subject"] = format_cert_name(cert.get("subject"))
            result["cert_issuer"] = format_cert_name(cert.get("issuer"))

            not_before = parse_cert_time(cert.get("notBefore"))
            not_after = parse_cert_time(cert.get("notAfter"))
            set_cert_status(result, not_before, not_after, warning_days)

    except ssl.SSLCertVerificationError as exc:
        result["tls_status"] = "CERT_VERIFY_FAIL"
        result["tls_ms"] = round((time.perf_counter() - tls_start) * 1000, 2)
        result["cert_valid"] = False
        result["cert_status"] = "VERIFY_FAIL"
        result["status"] = "CERT_INVALID"
        result["error"] = str(exc)
    except ssl.SSLError as exc:
        result["tls_status"] = "TLS_FAIL"
        result["tls_ms"] = round((time.perf_counter() - tls_start) * 1000, 2)
        result["cert_valid"] = False
        result["cert_status"] = "NOT_CHECKED"
        result["status"] = "TLS_FAIL"
        result["error"] = str(exc)
    except socket.timeout as exc:
        result["tls_status"] = "TIMEOUT"
        result["tls_ms"] = round((time.perf_counter() - tls_start) * 1000, 2)
        result["status"] = "TLS_FAIL"
        result["error"] = str(exc)
    except OSError as exc:
        result["tls_status"] = "TLS_SOCKET_FAIL"
        result["tls_ms"] = round((time.perf_counter() - tls_start) * 1000, 2)
        result["status"] = "TLS_FAIL"
        result["error"] = str(exc)
    finally:
        try:
            if raw_sock:
                raw_sock.close()
        except OSError:
            pass

    return result


def check_tcp_target(target, timeout, tls_all=False, warning_days=DEFAULT_CERT_WARNING_DAYS):
    host = target["host"]
    port = int(target["port"])
    result = empty_result(host, port, "TCP", target.get("description", ""))

    ips = resolve_dns(host, result)
    if not ips:
        return result

    sock = tcp_connect(host, port, timeout, result)
    if sock is None:
        return result

    try:
        sock.close()
    except OSError:
        pass

    if port == 443 or tls_all:
        # Reconnect for TLS to keep TCP timing and TLS timing distinct.
        return tls_and_cert_check(host, port, timeout, warning_days, result)

    result["status"] = "OK"
    return result


def check_udp_target(target, timeout):
    host = target["host"]
    port = int(target["port"])
    result = empty_result(host, port, "UDP", target.get("description", ""))

    ips = resolve_dns(host, result)
    if not ips:
        return result

    start = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        # Generic UDP probe. Many services, including RADIUS, may not respond to arbitrary payloads.
        sock.sendto(b"port-check", (host, port))
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

    return result


def check_target(target, timeout, tls_all, warning_days):
    protocol = target.get("protocol", "TCP").upper()
    if protocol == "TCP":
        return check_tcp_target(target, timeout, tls_all=tls_all, warning_days=warning_days)
    if protocol == "UDP":
        return check_udp_target(target, timeout)

    result = empty_result(target.get("host", ""), target.get("port", 0), protocol, target.get("description", ""))
    result["status"] = "UNSUPPORTED_PROTOCOL"
    result["error"] = f"Unsupported protocol: {protocol}"
    return result


def sort_results(results):
    return sorted(
        results,
        key=lambda r: (
            STATUS_PRIORITY.get(r.get("status", "UNKNOWN"), 500),
            str(r.get("host", "")).lower(),
            int(r.get("port", 0)),
            str(r.get("protocol", "")),
        ),
    )


def summarize(results):
    summary = {}
    for result in results:
        status = result.get("status", "UNKNOWN")
        summary[status] = summary.get(status, 0) + 1
    return dict(sorted(summary.items(), key=lambda item: (STATUS_PRIORITY.get(item[0], 500), item[0])))


def print_results(results):
    header = (
        f"{'STATUS':<22} "
        f"{'HOST':<48} "
        f"{'PORT':<5} "
        f"{'PROTO':<5} "
        f"{'DNS':<6} "
        f"{'TCP':<8} "
        f"{'TLS':<16} "
        f"{'CERT':<14} "
        f"{'DAYS':<6} "
        f"{'IP':<15}"
    )
    print(header)
    print("-" * len(header))

    for r in results:
        days = r.get("cert_days_remaining", "")
        if days == "":
            days = "-"
        print(
            f"{str(r.get('status', '')):<22} "
            f"{str(r.get('host', '')):<48} "
            f"{str(r.get('port', '')):<5} "
            f"{str(r.get('protocol', '')):<5} "
            f"{str(r.get('dns_status', '-')):<6} "
            f"{str(r.get('tcp_status', '-')):<8} "
            f"{str(r.get('tls_status', '-')):<16} "
            f"{str(r.get('cert_status', '-')):<14} "
            f"{str(days):<6} "
            f"{str(r.get('dns_ip', '')):<15}"
        )

    print()
    print("Summary:")
    for status, count in summarize(results).items():
        print(f"  {status:<22} {count}")


def write_csv(path, results):
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=RESULT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in results:
            writer.writerow(row)


def build_json_payload(results, args, started_at, finished_at):
    return {
        "metadata": {
            "tool": "port_checker.py",
            "version": VERSION,
            "started_at_utc": started_at,
            "finished_at_utc": finished_at,
            "input_file": str(args.input),
            "result_count": len(results),
            "timeout_seconds": args.timeout,
            "workers": args.workers,
            "tls_all": args.tls_all,
            "cert_warning_days": args.cert_warning_days,
            "summary": summarize(results),
        },
        "results": results,
    }


def write_json(path, payload):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)


def archive_json(json_path, payload, archive_dir="json_archive"):
    archive_path = Path(archive_dir)
    archive_path.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive_file = archive_path / f"port_check_{timestamp}.json"
    write_json(archive_file, payload)
    return archive_file


def parse_args():
    parser = argparse.ArgumentParser(
        description="Multi-threaded DNS/TCP/UDP/TLS/certificate port checker."
    )
    parser.add_argument("-i", "--input", required=True, help="Input hosts CSV/text file")
    parser.add_argument("-o", "--output-csv", default="port_check_results.csv", help="Output CSV file")
    parser.add_argument("-j", "--output-json", default="port_check_results.json", help="Output JSON file")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Socket timeout in seconds")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Concurrent worker threads")
    parser.add_argument("--tls-all", action="store_true", help="Attempt TLS/cert checks for all TCP ports, not only 443")
    parser.add_argument("--cert-warning-days", type=int, default=DEFAULT_CERT_WARNING_DAYS, help="Warn when certificate has this many days or fewer remaining")
    parser.add_argument("--no-archive", action="store_true", help="Do not create timestamped JSON archive copy")
    return parser.parse_args()


def main():
    args = parse_args()
    started_at = utc_now_iso()

    targets = parse_hosts_file(args.input)
    if not targets:
        print("No valid targets found in input file.", file=sys.stderr)
        return 2

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_map = {
            executor.submit(check_target, target, args.timeout, args.tls_all, args.cert_warning_days): target
            for target in targets
        }
        for future in as_completed(future_map):
            target = future_map[future]
            try:
                results.append(future.result())
            except Exception as exc:
                result = empty_result(
                    target.get("host", ""),
                    target.get("port", 0),
                    target.get("protocol", ""),
                    target.get("description", ""),
                )
                result["status"] = "CHECK_ERROR"
                result["error"] = str(exc)
                results.append(result)

    results = sort_results(results)
    finished_at = utc_now_iso()
    payload = build_json_payload(results, args, started_at, finished_at)

    print_results(results)
    write_csv(args.output_csv, results)
    write_json(args.output_json, payload)

    print(f"CSV written:  {args.output_csv}")
    print(f"JSON written: {args.output_json}")

    if not args.no_archive:
        archive_file = archive_json(args.output_json, payload)
        print(f"JSON archive: {archive_file}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
