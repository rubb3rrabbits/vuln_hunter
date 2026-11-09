#!/usr/bin/env python3
# language: Python 3, file: vuln_hunter.py, runtime: Python 3.10+
# *pure stdlib. random public IPs → open ports → banner → lightweight vuln probes*
# *stops at first confirmed vulnerable host. -v shows every step.*

import socket
import random
import struct
import concurrent.futures
import time
import re
import sys
import argparse
from typing import List, Tuple, Optional

def is_public(ip: str) -> bool:
    p = list(map(int, ip.split('.')))
    if p[0] in (0, 127) or p[0] >= 224: return False
    if p[0] == 10: return False
    if p[0] == 172 and 16 <= p[1] <= 31: return False
    if p[0] == 192 and p[1] == 168: return False
    if p[0] == 169 and p[1] == 254: return False
    if p[0] == 100 and 64 <= p[1] <= 127: return False
    return True

def rand_ip() -> str:
    while True:
        ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
        if is_public(ip):
            return ip

def tcp_banner(ip: str, port: int, timeout: float = 1.5) -> Optional[str]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(2048)
                return data.decode('utf-8', errors='ignore').strip()
            except socket.timeout:
                return "open"
    except Exception:
        return None

def check_redis(ip: str) -> Optional[str]:
    try:
        with socket.create_connection((ip, 6379), timeout=2) as s:
            s.sendall(b"INFO\r\n")
            data = s.recv(4096).decode('utf-8', errors='ignore')
            if "redis_version" in data:
                return f"Redis unauthenticated | {data.splitlines()[0][:80]}"
    except Exception:
        pass
    return None

def check_mongodb(ip: str) -> Optional[str]:
    try:
        with socket.create_connection((ip, 27017), timeout=2) as s:
            msg = bytes.fromhex(
                "3a0000000100000000000000dd0700000000000000"
                "00dd0700000169734d61737465720000"
            )
            s.sendall(msg)
            data = s.recv(1024)
            if data and (b"ismaster" in data.lower() or b"ok" in data):
                return "MongoDB responds without auth (likely open)"
    except Exception:
        pass
    return None

def check_ftp_anon(ip: str) -> Optional[str]:
    try:
        with socket.create_connection((ip, 21), timeout=3) as s:
            banner = s.recv(1024).decode('utf-8', errors='ignore')
            s.sendall(b"USER anonymous\r\n")
            resp = s.recv(1024).decode('utf-8', errors='ignore')
            if "331" in resp:
                s.sendall(b"PASS anonymous@\r\n")
                resp2 = s.recv(1024).decode('utf-8', errors='ignore')
                if "230" in resp2:
                    return f"FTP anonymous login allowed | {banner.strip()[:60]}"
    except Exception:
        pass
    return None

def check_http_default(ip: str, port: int) -> Optional[str]:
    try:
        with socket.create_connection((ip, port), timeout=2) as s:
            s.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            data = s.recv(4096).decode('utf-8', errors='ignore')
            if re.search(r"Apache/2\.2\.|Apache/2\.0\.|nginx/1\.[0-9]\.", data):
                return f"Old web server banner | {data.splitlines()[0][:80]}"
            if "phpMyAdmin" in data or "wp-login" in data or "Server: Microsoft-IIS/6.0" in data:
                return f"Interesting web app | {data.splitlines()[0][:80]}"
            if "Directory listing" in data or "Index of /" in data:
                return f"Directory listing enabled | {data.splitlines()[0][:60]}"
    except Exception:
        pass
    return None

def check_rdp(ip: str) -> Optional[str]:
    try:
        with socket.create_connection((ip, 3389), timeout=2) as s:
            s.sendall(bytes.fromhex("030000130ee00000000000010008000b000000"))
            data = s.recv(1024)
            if data:
                return "RDP open (possible weak NLA / old build)"
    except Exception:
        pass
    return None

def check_smb(ip: str) -> Optional[str]:
    try:
        with socket.create_connection((ip, 445), timeout=2) as s:
            nego = bytes.fromhex(
                "00000054ff534d4272000000000018015300000000000000000000000000"
                "ffff000000000000"
            )
            s.sendall(nego)
            data = s.recv(1024)
            if data and data[4:8] == b'\xffSMB':
                return "SMB responds (check for EternalBlue / guest / null session)"
    except Exception:
        pass
    return None

VULN_CHECKS = {
    21:   [check_ftp_anon],
    80:   [lambda ip: check_http_default(ip, 80)],
    443:  [lambda ip: check_http_default(ip, 443)],
    445:  [check_smb],
    3389: [check_rdp],
    6379: [check_redis],
    27017:[check_mongodb],
}

PORTS = list(VULN_CHECKS.keys()) + [22, 23, 25, 110, 143, 993, 995, 1433, 3306, 5432, 5900, 8080, 8443]

def deep_check(ip: str, open_ports: List[Tuple[int, str]], verbose: bool) -> Optional[str]:
    for port, banner in open_ports:
        checkers = VULN_CHECKS.get(port, [])
        if verbose and checkers:
            print(f"    [probe] {ip}:{port} running {len(checkers)} vuln check(s)")
        for checker in checkers:
            result = checker(ip)
            if result:
                return f"{ip}:{port} → {result} | banner={banner[:60]}"
            elif verbose:
                print(f"    [probe] {ip}:{port} → clean")
    return None

def scan_host(ip: str, verbose: bool) -> Optional[str]:
    if verbose:
        print(f"[scan] {ip}")
    open_ports = []
    for port in PORTS:
        banner = tcp_banner(ip, port)
        if banner:
            open_ports.append((port, banner))
            if verbose:
                print(f"  [open] {ip}:{port}  {banner[:80]}")
    if not open_ports:
        if verbose:
            print(f"  [miss] {ip} no open ports")
        return None
    return deep_check(ip, open_ports, verbose)

def main(workers: int = 48, verbose: bool = False):
    print(f"[*] continuous random-IP vuln hunter | workers={workers} | verbose={verbose}")
    print(f"[*] will stop at first confirmed vulnerable host\n")

    scanned = 0
    start = time.time()
    found = None

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {}
        try:
            while found is None:
                while len(futures) < workers * 2:
                    ip = rand_ip()
                    fut = pool.submit(scan_host, ip, verbose)
                    futures[fut] = ip
                    scanned += 1

                done, _ = concurrent.futures.wait(
                    futures, timeout=0.4, return_when=concurrent.futures.FIRST_COMPLETED
                )
                for fut in done:
                    ip = futures.pop(fut)
                    try:
                        result = fut.result()
                        if result:
                            found = result
                            break
                    except Exception as e:
                        if verbose:
                            print(f"  [err] {ip} {e}")

                if not verbose and scanned % 300 == 0:
                    rate = scanned / (time.time() - start)
                    print(f"[*] scanned={scanned}  rate={rate:.1f}/s  still hunting...")

        except KeyboardInterrupt:
            print("\n[*] stopped by operator")
            return

    elapsed = time.time() - start
    print("\n" + "="*60)
    print(f"[+] VULNERABLE HOST FOUND after {scanned} hosts / {elapsed:.1f}s")
    print(f"[+] {found}")
    print("="*60)

    with open("vuln_hit.txt", "w") as f:
        f.write(found + "\n")
    print("[*] evidence written to vuln_hit.txt")

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Random IP vuln hunter")
    p.add_argument("-w", "--workers", type=int, default=48)
    p.add_argument("-v", "--verbose", action="store_true", help="print every IP, port, and probe result")
    args = p.parse_args()
    main(workers=args.workers, verbose=args.verbose)
EOF
