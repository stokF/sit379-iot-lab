import argparse 
import json
import math 
import os 
import sys 
from collections import Counter 
from pathlib import Path 

ERROR = '\033[91m [!!!]\033[0m'
WARNING = '\033[93m [*]\033[0m'
NOTIFICATION = '\033[96m[+]\033[0m'
CRITICAL = '\033[43m>>>\033[0m'
COLOUR_END = '\033[0m'
UNDERLINE = '\033[4m'

dummyDir = Path("/home/eh_pi/dummy_data")
keyFile = Path("/tmp/data_impact_keys.json")
entropyEvidence = Path("/home/eh_pi/entropy_report.txt")
stateFile = Path("/tmp/data_impact_state.json")

def dataEntropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())

def xorBytes(data: bytes, key: bytes) -> bytes:
    extended = bytes(a ^ b for a, b in zip(data, extended))

    def targetFiles() -> list[path]:
        if not dummyDir.is_dir():
            sys.exit(
                print(f"{ERROR}{dummyDir} does not currently exist")
            )
        return sorted(p for p in dummyDir.interdor() f p.is_file())

def encryptionFunc(files: list[Path]) -> None:
    