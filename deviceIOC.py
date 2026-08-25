#Control Version 1.0

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

risk_Check = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4
}

ERROR        = '\033[91m [!!!]\033[0m'
WARNING      = '\033[93m [*]\033[0m'
NOTIFICATION = '\033[96m[+]\033[0m'
CRITICAL     = '\033[43m>>>\033[0m'
COLOUR_END   = '\033[0m'
UNDERLINE    = '\033[4m'

severityLabel = {
    "CRITICAL": '\033[1m\033[31m[CRITICAL]\033[0m',
    "HIGH":     '\033[1m\033[33m[HIGH]\033[0m',
    "MEDIUM":   '\033[1m\033[32m[MEDIUM]\033[0m',
    "LOW":      '\033[1m\033[36m[LOW]\033[0m',
    "INFO":     '\033[0m[INFO]\033[0m',
}

@dataclass
class IoC:
    severity:  str
    source:    str
    relInfo:   str
    timeStamp: str = ""


def _sev_key(ioc: "IoC") -> str:
    """Strip ANSI codes from severity and return the bare label (e.g. 'CRITICAL')."""
    clean = re.sub(r'\033\[[0-9;]*m', '', ioc.severity).strip()
    return clean.split()[-1] if clean else "INFO"


def tsharkField(pcap: Path, displayFilter: str, fields: list[str],
                extraArgs: Optional[list[str]] = None) -> list[list[str]]:
    if not pcap.exists():
        print(f"{WARNING} {pcap} unavailable: skipping checks for this capture.",
              file=sys.stderr)
        return []

    cmd = ["tshark", "-r", str(pcap), "-Y", displayFilter,
           "-T", "fields", "-E", "separator=|"]
    for f in fields:
        cmd += ["-e", f]
    if extraArgs:
        cmd += extraArgs

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        sys.exit(f"{ERROR} tshark unavailable.")
    except subprocess.TimeoutExpired:
        print(f"{ERROR} tshark service timed out on {pcap}", file=sys.stderr)
        return []

    rows = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line:
            rows.append(line.split("|"))
    return rows


def postFlows_Check(pcap: Path, target_ip: str) -> list[IoC]:
    iocs: list[IoC] = []
    rows = tsharkField(
        pcap,
        'http.request.method == "POST" && http.request.uri contains "/flows"',
        ["frame.time", "ip.src", "http.request.method", "http.request.uri"]
    )
    for row in rows:
        ts, src, method, uri = (row + [""] * 4)[:4]
        iocs.append(IoC(
            severity  = f"{CRITICAL} CRITICAL",
            source    = pcap.name,
            relInfo   = f"time={ts} src={src} method={method} uri={uri}",
            timeStamp = ts,
        ))
    return iocs


def getFlows_Check(pcap: Path, target_ip: str) -> list[IoC]:
    iocs: list[IoC] = []
    rows = tsharkField(
        pcap,
        'http.request.method == "GET" && http.request.uri contains "/flows"',
        ["frame.time", "ip.src", "http.request.uri"]
    )
    for row in rows:
        ts, src, uri = (row + [""] * 3)[:3]
        iocs.append(IoC(
            severity  = f"{NOTIFICATION} LOW",
            source    = pcap.name,
            relInfo   = f"time={ts} src={src} uri={uri}",
            timeStamp = ts,
        ))
    return iocs


def settingsCheck(pcap: Path, target_ip: str) -> list[IoC]:
    iocs: list[IoC] = []
    rows = tsharkField(
        pcap,
        'http.request.method == "GET" && http.request.uri contains "/settings"',
        ["frame.time", "ip.src"]
    )
    for row in rows:
        ts, src = (row + [""] * 2)[:2]
        iocs.append(IoC(
            severity  = f"{NOTIFICATION} LOW",
            source    = pcap.name,
            relInfo   = f"time={ts} src={src}",
            timeStamp = ts,
        ))
    return iocs


def HTTP1880_Check(pcap: Path, target_ip: str) -> list[IoC]:
    iocs: list[IoC] = []
    rows = tsharkField(
        pcap,
        f'tcp.port == 1880 && ip.src != {target_ip}',
        ["frame.time", "ip.src", "tcp.dstport"]
    )
    if rows:
        iocs.append(IoC(
            severity  = f"{NOTIFICATION} INFO",
            source    = pcap.name,
            relInfo   = (
                f"TCP port 1880 traffic from external host(s): "
                f"ZERO in baseline; {len(rows)} packet(s) found"
            ),
            timeStamp = rows[0][0] if rows else "",
        ))
    return iocs


def mqttEth0_check(pcap: Path, target_ip: str) -> list[IoC]:
    iocs: list[IoC] = []
    rows = tsharkField(
        pcap,
        f"mqtt && ip.src != {target_ip}",
        ["frame.time", "ip.src", "mqtt.msgtype"]
    )
    if rows:
        iocs.append(IoC(
            severity  = f"{NOTIFICATION} INFO",
            source    = pcap.name,
            relInfo   = f"First packet: time={rows[0][0]} src={rows[0][1]} msgtype={rows[0][2]}",
            timeStamp = rows[0][0] if rows else "",
        ))
    return iocs


def mqttConnect_Check(pcap: Path, target_ip: str) -> list[IoC]:
    iocs: list[IoC] = []
    rows = tsharkField(
        pcap,
        f"mqtt.msgtype == 1 && ip.src != {target_ip}",
        ["frame.time", "ip.src", "mqtt.clientid"]
    )
    for row in rows:
        ts, src, client_id = (row + [""] * 3)[:3]
        iocs.append(IoC(
            severity  = f"{NOTIFICATION} HIGH",
            source    = pcap.name,
            relInfo   = f"Anonymous MQTT connection from {src} | clientid: {client_id}",
            timeStamp = ts,
        ))
    return iocs  


def wildcardSub_check(pcap: Path, target_ip: str) -> list[IoC]:
    iocs: list[IoC] = []
    rows = tsharkField(
        pcap,
        'mqtt.msgtype == 8',
        ["frame.time", "ip.src", "mqtt.topic"]
    )
    for row in rows:
        ts, src, topic = (row + [""] * 3)[:3]
        severity = "HIGH" if src != target_ip or topic == "#" else "INFO"
        iocs.append(IoC(
            severity  = f"{NOTIFICATION} {severity}",
            source    = pcap.name,
            relInfo   = f"time={ts} src={src} topic={topic}",
            timeStamp = ts,
        ))
    return iocs


def mqttActuator_Check(pcap: Path, target_ip: str) -> list[IoC]:
    iocs: list[IoC] = []
    rows = tsharkField(
        pcap,
        "mqtt.msgtype == 3 && mqtt.topic contains \"actuators\"",
        ["frame.time", "ip.src", "mqtt.topic", "mqtt.msg"],
    )
    for row in rows:
        ts, src, topic, msg = (row + [""] * 4)[:4]
        iocs.append(IoC(
            severity  = f"{NOTIFICATION} HIGH",
            source    = pcap.name,
            relInfo   = f"time={ts} src={src} topic={topic} payload={msg}",
            timeStamp = ts,
        ))
    return iocs


def mqttBeacon_Check(pcap: Path, target_ip: str) -> list[IoC]:
    iocs: list[IoC] = []
    rows = tsharkField(
        pcap,
        f"mqtt.msgtype == 3 && ip.src == {target_ip if target_ip else '10.10.10.20'}",
        ["frame.time", "ip.src", "mqtt.topic"]
    )
    beacon_rows = [r for r in rows if 'actuators' not in (r[2] if len(r) > 2 else '')]
    if len(beacon_rows) >= 3:
        iocs.append(IoC(
            severity  = f"{NOTIFICATION} MEDIUM",
            source    = pcap.name,
            relInfo   = (
                f"First: time={beacon_rows[0][0]} | topic={beacon_rows[0][2]}"
                f" | Last: time={beacon_rows[-1][0]}"
            ),
            timeStamp = beacon_rows[0][0] if beacon_rows else "",
        ))
    return iocs


def auditdParse(auditd_file: Path) -> list[IoC]:
    iocs: list[IoC] = []

    if not auditd_file.exists():
        print(f"{WARNING} {auditd_file} unavailable or does not exist.")
        return iocs

    content = auditd_file.read_text(errors="replace")
    blocks = [b.strip() for b in re.split(r'^-{4,}$', content, flags=re.MULTILINE) if b.strip()]

    for block in blocks:
        lines = block.splitlines()

        ts = ""
        for ln in lines:
            m = re.search(r"time->(.+)", ln)
            if m:
                ts = m.group(1).strip()
                break

        keys_found = set(re.findall(r'key="([^"]+)"', block))

        execve_line = next((ln for ln in lines if "EXECVE" in ln), "")
        execve_cmd  = " ".join(re.findall(r'a\d+="([^"]+)"', execve_line))

        comm_match = re.search(r'comm="([^"]+)"', block)
        comm = comm_match.group(1) if comm_match else ""

        exe_match = re.search(r'exe="([^"]+)"', block)
        exe = exe_match.group(1) if exe_match else ""

        path_matches = re.findall(r'name="([^"]+)"', block)
        paths = [p for p in path_matches if not p.startswith("(")]

        if "proc_exec" in keys_found:
            iocs.append(IoC(
                severity  = f"{CRITICAL} CRITICAL",
                source    = auditd_file.name,
                relInfo   = (
                    f"time={ts} comm={comm} exe={exe}"
                    f"\n     execve: {execve_cmd}"
                ),
                timeStamp = ts,
            ))

        if "rce_marker" in keys_found:
            iocs.append(IoC(
                severity  = f"{CRITICAL} CRITICAL",
                source    = auditd_file.name,
                relInfo   = f"time={ts} RCE marker file written | comm={comm} exe={exe}",
                timeStamp = ts,
            ))

        if "data_impact" in keys_found:
            written = ", ".join(paths) if paths else "Unidentified file within target directory"
            iocs.append(IoC(
                severity  = f"{NOTIFICATION} MEDIUM",
                source    = auditd_file.name,
                relInfo   = f"time={ts} path={written} comm={comm}",
                timeStamp = ts,
            ))
    return iocs


def reportIoC(iocs: list[IoC], args: argparse.Namespace) -> str:
    lines = [
        "=" * 72,
        f"{NOTIFICATION} Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"{NOTIFICATION} Data: nodered={args.nodered_pcap} mqtt={args.mqtt_pcap} auditd={args.auditd}",
        f"{NOTIFICATION} IoC(s): {len(iocs)}",
        "=" * 72,
        "",
    ]

    counts = {
        s: sum(1 for i in iocs if _sev_key(i) == s)
        for s in risk_Check
    }

    lines += [
        "SUMMARY",
        "CRITICAL: {:>3}  (unauthenticated RCE + exec foothold)".format(counts.get("CRITICAL", 0)),
        "HIGH:     {:>3}  (anonymous access + actuator change)".format(counts.get("HIGH", 0)),
        "MEDIUM:   {:>3}  (Impact + Beacon)".format(counts.get("MEDIUM", 0)),
        "LOW:      {:>3}  (Enum + Fingerprinting)".format(counts.get("LOW", 0)),
        "INFO:     {:>3}  (Baseline Capture)".format(counts.get("INFO", 0)),
        "",
        "─" * 72,
        "INDICATORS OF COMPROMISE (Descending Severity)",
        "─" * 72,
        "",
    ]

    sorted_iocs = sorted(iocs, key=lambda i: (risk_Check.get(_sev_key(i), 99), i.timeStamp))

    for n, ioc in enumerate(sorted_iocs, 1):
        label = severityLabel.get(_sev_key(ioc), f"[{_sev_key(ioc)}]")
        lines += [
            f"[{n:02d}] {label}  |  source: {ioc.source}",
            f"     {ioc.relInfo}",
            "",
        ]

    return "\n".join(lines)

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Python program used to document the host's current state of compromise."
    )
    parser.add_argument("--nodered-pcap", default="nodered_rce.pcap")
    parser.add_argument("--mqtt-pcap",    default="mqtt_attack.pcap")
    parser.add_argument("--auditd",       default="auditd_events.txt")
    parser.add_argument("--output",       default=None)
    parser.add_argument("--attack-ip",    default="10.10.10.20")
    parser.add_argument("--target-ip",    default="10.10.10.40")
    args = parser.parse_args()

    nodered_pcap = Path(args.nodered_pcap)
    mqtt_pcap    = Path(args.mqtt_pcap)
    auditd_file  = Path(args.auditd)
    target_ip    = args.target_ip
    attacker_ip  = args.attack_ip

    print(f"{NOTIFICATION} Now checking for Indication of Compromise:\n")
    print(f"Nodered pcap:  {nodered_pcap}")
    print(f"MQTT pcap:     {mqtt_pcap}")
    print(f"Auditd file:   {auditd_file}")
    print(f"Target IP:     {target_ip} | Attacker IP: {attacker_ip}\n")

    all_iocs: list[IoC] = []

    print(f"{NOTIFICATION} Checking for RCE on Node-RED | {nodered_pcap.name}\n")
    all_iocs += postFlows_Check(nodered_pcap, target_ip)
    all_iocs += getFlows_Check(nodered_pcap, target_ip)
    all_iocs += settingsCheck(nodered_pcap, target_ip)
    all_iocs += HTTP1880_Check(nodered_pcap, target_ip)
    print(f"    {sum(1 for i in all_iocs if i.source == nodered_pcap.name)} IoC(s) discovered\n")

    print(f"{NOTIFICATION} Checking for MQTT attack | {mqtt_pcap.name}")
    mqtt_count_before = len(all_iocs)
    all_iocs += mqttEth0_check(mqtt_pcap, target_ip)
    all_iocs += mqttConnect_Check(mqtt_pcap, target_ip)
    all_iocs += wildcardSub_check(mqtt_pcap, target_ip)
    all_iocs += mqttActuator_Check(mqtt_pcap, target_ip)
    all_iocs += mqttBeacon_Check(mqtt_pcap, attacker_ip)
    print(f"    {len(all_iocs) - mqtt_count_before} IoC(s) found\n")

    print(f"{NOTIFICATION} Parsing auditd logs\n")
    auditd_count_before = len(all_iocs)
    all_iocs += auditdParse(auditd_file)
    print(f"    {len(all_iocs) - auditd_count_before} IoC(s) found\n")

    print(f"{NOTIFICATION} Total: {len(all_iocs)} IoC(s) across all sources\n")
    report = reportIoC(all_iocs, args)
    print(report)

    if args.output:
        Path(args.output).write_text(report)
        print(f"\n{NOTIFICATION} Report created | Check: {args.output}")


if __name__ == "__main__":
    main()