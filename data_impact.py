#Control Version 1.2.1 - WIP 
#Last Update - Minor Bug fixes

import argparse
import json
import math
import os
import sys
from collections import Counter
from pathlib import Path
 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
 
ERROR        = '\033[91m [!!!]\033[0m'
WARNING      = '\033[93m [*]\033[0m'
NOTIFICATION = '\033[96m[+]\033[0m'
CRITICAL     = '\033[43m>>>\033[0m'
COLOUR_END   = '\033[0m'
UNDERLINE    = '\033[4m'
 
dummyDir        = Path("/home/eh_pi/dummy_data")
keyFile         = Path("/tmp/data_impact_keys.json")
entropyEvidence = Path("/home/eh_pi/entropy_report.txt")
stateFile       = Path("/tmp/data_impact_state.json")
 
nonceSize = 12
keySize = 32
 
def dataEntropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())
 
def maxEntropy(size: int) -> float:
    if size <= 0:
        return 0.0
    return math.log2(min(size, 256))
 
def encryptBytes(data: bytes, key: bytes) -> bytes:
    nonce = os.urandom(nonceSize)
    aesgcm = AESGCM(key)
    cipherText = aesgcm.encrypt(nonce, data, None)
    return nonce + cipherText
 
def decryptBytes(data: bytes, key: bytes) -> bytes:
    nonce = data[:nonceSize]
    cipherText = data[nonceSize:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, cipherText, None)
 
def targetFiles() -> list[Path]:
    if not dummyDir.is_dir():
        print(f"{ERROR} {dummyDir} currently does not exist")
        sys.exit(1)
    return sorted(p for p in dummyDir.iterdir() if p.is_file())
 
def encryptionFunc(files: list[Path]) -> None:
    keys: dict[str, str] = {}
    for f in files:
        key = os.urandom(keySize)
        keys[str(f)] = key.hex()
 
    keyFile.write_text(json.dumps(keys, indent=2))
    print(f"{NOTIFICATION} Key file: {keyFile} | {len(keys)} file(s)")
 
    reportEncryption = [
        "Encryption Report Generated",
        "Format: filename | before (bits/bytes) | after (bits/bytes)",
    ]
 
    for f in files:
        plaintext = f.read_bytes()
        beforeDeploy = dataEntropy(plaintext)
 
        key = bytes.fromhex(keys[str(f)])
        cipherText = encryptBytes(plaintext, key)
        f.write_bytes(cipherText)
        postDeploy = dataEntropy(cipherText)
 
        line = (f"\n{f.name: < 20} before = {beforeDeploy:.4f} after = {postDeploy:.4f} "
                f"max = {maxEntropy(len(plaintext)):.4f}")
        reportEncryption.append(line)
        print(f"{CRITICAL} [enc] | {line}")
 
    reportEncryption.append("")
    entropyEvidence.write_text("\n".join(reportEncryption) + "\n")
 
    stateFile.write_text(json.dumps({"state": "encrypted"}))
 
    print(f"\n {NOTIFICATION} encryption complete: {len(files)} file(s) in {dummyDir}")
    print(f"{NOTIFICATION} encryption logged: {entropyEvidence}")
 
def decrypt() -> None:
    if not keyFile.exists():
        sys.exit(
            f"\n{WARNING} key file ({keyFile}) unavailable."
            f"{WARNING} Try: Check for /tmp"
        )
 
    if stateFile.exists():
        state = json.loads(stateFile.read_text()).get("state")
        if state != "encrypted":
            print(f"\n{WARNING} Files are not currently encrypted (state: {state}).")
            sys.exit(1)
 
    keys: dict[str, str] = json.loads(keyFile.read_text())
    restored = 0
 
    for pathStr, keyHex in keys.items():
        f = Path(pathStr)
        if not f.exists():
            print(f"\n{WARNING} file cannot be found.")
            continue
        cipherText = f.read_bytes()
        key = bytes.fromhex(keyHex)
        try:
            plaintext = decryptBytes(cipherText, key)
        except Exception as e:
            print(f"\n{ERROR} decryption incomplete | {f.name}: {e} (fail) ")
            continue
        f.write_bytes(plaintext)
        postDeploy = dataEntropy(plaintext)
        print(f"\n{NOTIFICATION} [dec] {f.name:<20} current entropy: {postDeploy:.4f} bits/bytes")
        restored += 1
 
    stateFile.write_text(json.dumps({"state": "restored"}))
    print(f"\n{NOTIFICATION} files decrypted: {restored} file(s) decrypted")
 
def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--restore", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
 
    files = targetFiles()
    if not files:
        sys.exit(f"\n{ERROR} {dummyDir} does not contain data.")
 
    if args.dry_run:
        print(f"\n{NOTIFICATION} Current entropy of files in {dummyDir}:")
        for f in files:
            data = f.read_bytes()
            print(f"{f.name:<20} {dataEntropy(data):.4f} bits/byte"
                  f" (max {maxEntropy(len(data)):.4f})")
        return
 
    if args.restore:
        print(f"{NOTIFICATION} {len(files)} file(s) being decrypted in {dummyDir}\n")
        decrypt()
        return
 
    if stateFile.exists():
        state = json.loads(stateFile.read_text()).get("state")
        if state == "encrypted":
            print(f"{WARNING} file(s) already encrypted.")
            sys.exit(1)
 
    print(f"{NOTIFICATION} Encrypting {len(files)} file(s) in {dummyDir}")
    encryptionFunc(files)
 
if __name__ == "__main__":
    main()