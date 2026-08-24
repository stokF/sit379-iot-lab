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

def targetFiles() -> list[Path]:
    if not dummyDir.is_dir():
        sys.exit(
            print(f"{ERROR}{dummyDir} does not currently exist")
        )
    return sorted(p for p in dummyDir.iterdir() if p.is_file())

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
        beforeDeploy = dataEntropy(plaintext)

        key = bytes.from_hex(keys[str(f)])
        cipherText = xor_bytes(plaintext, key)
        f.write_bytes(cipherText)
        postDeploy = dataEntropy(cipherText)

        line = f"{f.name:<20} before={beforeDeploy:.4f} after={postDeploy:.4f}" 
        reportEncryption.append(line)
        print(f"{CRITICAL} [enc] {line}")      

        reportEncryption.append("")
        entropyEvidence.write_text("\n".join(reportEncryption) + "\n")

        print(f"{NOTIFICATION} Encryption Completed: {len(files)} file(s) in {dummyDir}")
        print(f"{NOTIFICATION} Find Report: {entropyEvidence}")

def decrypt() -> None:
    if not keyFile.exists():
        sys.exit(
            f"{WARNING} Key file {keyFile} unavailable.\n"
            f"{WARNING} Try: Check for /tmp, or check for data location."
        )

    keys: dict[str, str] = json.loads(keyFile.read_text())
    restored = 0

    for pathStr, keyHex in keys.items():
        f = Path(pathStr)
        if not f.exists():
            print(f"{WARNING} File cannot be found.")
            print(f"{WARNING} Try: Check if files have been deleted or restored already.")
            continue
        ciphertext = f.read_bytes()
        key = bytes.fromhex(keyHex)
        plaintext = xorBytes(cipherText, key)
        f.write_bytes(plaintext)
        postDeploy = dataEntropy(plaintext)
        print(f"{NOTIFICATION} [dec] {f.name:<20} current entropy:{postDeploy:.4f} bits/bytes")
        restored += 1

        stateFile.write_text(json.dumps({"state": "restored"}))
        print(f"{NOTIFICATION} Files decrypted - {restored} file(s) restored.")

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
            "--restore", action="store_true",
        )
    parser.add_argument(
            "--dry-run", action="store_true",
        )
    args = parser.parse_args()

    files = targetFiles()
    if not files:
        sys.exit(f"{ERROR} {dummyDir} does not contain data.")

    if args.dry_run:
        print(f"{NOTIFICATION} Find: current of entropy files - {dummyDir}\n")
        for f in files:
            e = dataEntropy(f.read_bytes())
            print(f" {f.name:<20} {e:.4f} bits/bytes")
        return

    if args.restore:
        print(f"{NOTIFICATION} {len(files)} file(s) are being decrypted in {dummyDir}\n")
        restore()
        return

    if stateFile.exists():
        state = json.loads(stateFile.read_text()).get("state")
        if state == "encrypted":
            print(f"{WARNING} Files have already been encrypted.")
            sys.exit(1)

    print(f"{NOTIFICATION} Encrypting {len(files)} file(s) im {dummyDir}")
    encryptionFunc(files)

if __name__ == "__main__":
    main()

