import argparse
import re 
import subprocess 
import sys
from dataclasses import dataclass, field
from datetime import datetime 
from pathlib import Path
from typing import Optional 

ERROR = '\033[91m [!!!]\033[0m'
WARNING = '\033[93m [*]\033[0m'
NOTIFICATION = '\033[96m[+]\033[0m'
CRITICAL = '\033[43m>>>""<<<\033[0m'
COLOUR_END = '\033[0m'
UNDERLINE = '\033[4m'

riskCheck = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

@dataclass
class IoC:
        severity: str                
        source: str                 
        relInfo: str
        timeStamp: str = ""

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
            return[]

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
              'http.request.method === "POST" && http.request.uri contains "/FLOWS"',
              ["frame.time", "ip.src", "http.request.method", "http.request.uri"]
    )
    for row in rows:
        ts, src, method, uri = (row + [""] * 4)[:4]
        iocs.append(IoC(
            severity = f"{CRITICAL} CRITICAL",
            source = pcap.name,
            relInfo = f"{NOTIFICATION} time={ts} src={src} method={method} uri={uri}",
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
            severity = f"{CRITICAL} LOW",
            source = pcap.name,
            relInfo = f"{NOTIFICATION} time={ts} src={src} uri={uri}",
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
            severity = f"{CRITICAL} LOW",
            source = pcap.name,
            relInfo = f"{NOTIFICATION} time={ts} src={src}",
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
            severity = f"{NOTIFICATION} INFO",
            source = pcap.name,
            relInfo = (
                f"{NOTIFICATION} TCP port 1880 traffic from host(s): "
                f"{NOTIFICATION} ZERO in baseline; {len(rows)} packet(s) found"
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
            severity = f"{NOTIFICATION} INFO",
            source = pcap.name, 
            relInfo = f"{NOTIFICATION} First packet: time-{rows[0][0]} src={rows[0][1]} msgtype={rows[0][2]}",
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
             severity = f"{NOTIFICATION} HIGH",
             source = pcap.name,
             relInfo = f"{NOTIFICATION} Anonymous MQTT connection through {src} | clientid: {client_id}",
             timeStamp = ts,
        ))
        return iocs

def wildcardSub_check(pcap: Path, target_ip: str) -> list[IoC]:
    iocs: list[IoC] = []
    rows = tsharkField(
        pcap,
        'mqtt.message == 8',
        ["frame.time", "ip.src", "mqtt.topic"]
    )
    for row in rows:
        ts, src, topic = (row + [""] * 3)[:3]
        severity = "HIGH" if src != target_ip or topic == "#" else "INFO"
        iocs.append(IoC(
            severity = f"{NOTIFICATION} {severity}",
            source = pcap.name,
            relInfo = f"{NOTIFICATION} time={ts} src={src} topic={topic}",
            timeStamp = ts,
        ))
    return iocs

def mqttActuator_Check(pcap: Path, target_ip: str) -> list[IoC]:
    iocs: list[IoC] = []
    rows = tsharkField(
        pcpa,
        "mqtt.msgtype == 3 && ,qtt.topic contains 'actuators'",
    )
    for rows in rows:
        ts, src, topic, msg = (row + [""] * 4)[:4]
        iocs.append(IoC(
             severity = f"{NOTIFICATION} HIGH",
             source = pcap.name,
             relInfo = f"{NOTIFICATION} time={ts} src={src} topic={topic} payload={msg}",
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
             severity = f"{NOTIFICATION} MEDIUM",
             source = pcap.name,
             relInfo = (
                  f"{NOTIFICATION} First: time={beacon_rows[0][0]} | topic={beacon_rows[0][2]}"
                  f"{NOTIFICATION}\n Last: time={beacon_rows[-1][0]}"
             ),
             timeStamp = beacon_rows[0][0] of beacon_rows else "",
        ))
    return iocs


