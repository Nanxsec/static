#!/usr/bin/env python3

import os
import socket
import struct
import subprocess
from concurrent.futures import ThreadPoolExecutor

TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING"
}

SCAN_TIMEOUT = 8
MAX_THREADS = 50


def hex_to_ip(hex_ip):
    return socket.inet_ntoa(struct.pack("<L", int(hex_ip, 16)))


def hex_to_port(hex_port):
    return int(hex_port, 16)


def clean_banner(banner):
    import re
    # pega só partes legíveis importantes
    match = re.search(r"([0-9]+\.[0-9]+\.[0-9]+[^\s]*)", banner)
    if match:
        return match.group(1)
    return "-"

def detect_service(port, banner):
    banner = banner.lower()

    if "ssh" in banner or port == 22:
        return "SSH"
    elif "http" in banner or port in [80, 8080, 8000]:
        return "HTTP"
    elif "smtp" in banner or port == 25:
        return "SMTP"
    elif "ftp" in banner or port == 21:
        return "FTP"
    elif "mysql" in banner or port == 3306:
        return "MySQL"
    elif "mongodb" in banner or port == 27017:
        return "MongoDB"
    elif port == 443:
        return "HTTPS"
    else:
        return "Unknown"


def get_inode_map():
    inode_map = {}

    for pid in filter(str.isdigit, os.listdir("/proc")):
        fd_path = f"/proc/{pid}/fd"

        if not os.path.exists(fd_path):
            continue

        try:
            for fd in os.listdir(fd_path):
                full_path = os.path.join(fd_path, fd)
                try:
                    link = os.readlink(full_path)
                    if "socket:[" in link:
                        inode = link.split("[")[1].strip("]")
                        inode_map[inode] = pid
                except:
                    continue
        except:
            continue

    return inode_map


def get_process_name(pid):
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            return f.read().strip()
    except:
        return "?"


def banner_grab(ip, port):
    try:
        s = socket.socket()
        s.settimeout(SCAN_TIMEOUT)
        s.connect((ip, port))

        try:
            s.sendall(b"\r\n")
        except:
            pass

        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()

        return clean_banner(banner) if banner else "-"
    except:
        return "-"


def parse_proc_net(file_path, proto, inode_map):
    results = []

    try:
        with open(file_path, "r") as f:
            next(f)

            tasks = []

            with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:

                for line in f:
                    parts = line.strip().split()

                    local_address = parts[1]
                    state_hex = parts[3]
                    inode = parts[9]

                    ip_hex, port_hex = local_address.split(":")
                    ip = hex_to_ip(ip_hex)
                    port = hex_to_port(port_hex)

                    state = TCP_STATES.get(state_hex, state_hex)

                    pid = inode_map.get(inode, "-")
                    process = get_process_name(pid) if pid != "-" else "-"

                    if state == "LISTEN" and proto == "TCP":
                        future = executor.submit(banner_grab, ip, port)
                        tasks.append((future, ip, port, state, pid, process))
                    else:
                        results.append({
                            "proto": proto,
                            "ip": ip,
                            "port": port,
                            "state": state,
                            "pid": pid,
                            "process": process,
                            "banner": "-",
                            "service": detect_service(port, "")
                        })

                for future, ip, port, state, pid, process in tasks:
                    banner = future.result()
                    service = detect_service(port, banner)

                    results.append({
                        "proto": proto,
                        "ip": ip,
                        "port": port,
                        "state": state,
                        "pid": pid,
                        "process": process,
                        "banner": banner,
                        "service": service
                    })

    except Exception as e:
        print(f"[!] Erro em {file_path}: {e}")

    return results


def show_results(connections):
    print("\nProto  IP              Port   State         PID    Process        Service   Banner")
    print("-" * 110)

    for c in connections:
        print(f"{c['proto']:5} {c['ip']:15} {c['port']:<6} {c['state']:<13} {c['pid']:<6} {c['process']:<14} {c['service']:<8} {c['banner']}")


def try_netstat():
    try:
        result = subprocess.run(
            ["netstat", "-tulnp"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if result.returncode == 0:
            print(result.stdout)
            return True
        return False

    except FileNotFoundError:
        return False


def main():
    if not try_netstat():
        print("[*] netstat não encontrado. Usando /proc...\n")

        inode_map = get_inode_map()

        connections = []
        connections += parse_proc_net("/proc/net/tcp", "TCP", inode_map)
        connections += parse_proc_net("/proc/net/udp", "UDP", inode_map)

        show_results(connections)


if __name__ == "__main__":
    main()
