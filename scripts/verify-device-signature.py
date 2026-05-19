#!/usr/bin/env python3
"""Verify the cross-signing chain on a Matrix device, end-to-end.

When `verify_status` returns `cross_signed: false` and you don't
trust the SDK's opinion (or you've just rotated the device id and
need to confirm the new device is properly signed before declaring
victory), run this script against the live Synapse postgres.

It does NOT trust any matrix-rust-sdk code path. It pulls the
device's published JSON, the user's published cross-signing
pubkeys, and the master→self_signing signature directly from
postgres, then performs the two ed25519 verifications that decide
whether peer Matrix clients will trust this device.

Usage:
    python3 verify-device-signature.py @user:server DEVICE_ID

You must have `kubectl` access to the cluster hosting Synapse and
read permission on the `synapse` database. Three SELECTs total, all
read-only. The script hard-codes the pod name + namespace conventions
the author uses (see POSTGRES_POD / POSTGRES_NS at the top of the
file); edit those for your deployment.

Requirements: PyNaCl, canonicaljson
    pip install --user PyNaCl canonicaljson
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys

try:
    import canonicaljson  # type: ignore[import-not-found]
    from nacl.exceptions import BadSignatureError  # type: ignore[import-not-found]
    from nacl.signing import VerifyKey  # type: ignore[import-not-found]
except ImportError as e:
    sys.exit(f"missing dep ({e}); install with: pip install PyNaCl canonicaljson")


POSTGRES_POD = "postgres-rescue-1"
POSTGRES_NS = "postgres"
POSTGRES_DB = "synapse"
POSTGRES_USER = "postgres"


def b64decode_unpadded(s: str) -> bytes:
    padding = (4 - len(s) % 4) % 4
    return base64.b64decode(s + "=" * padding)


def psql(sql: str) -> str:
    cmd = [
        "kubectl", "-n", POSTGRES_NS, "exec", POSTGRES_POD,
        "-c", "postgres", "--",
        "psql", "-U", POSTGRES_USER, "-d", POSTGRES_DB, "-tA", "-c", sql,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        sys.exit(f"psql failed:\nSTDOUT: {proc.stdout}\nSTDERR: {proc.stderr}")
    return proc.stdout.strip()


def fetch_device_keys(user_id: str, device_id: str) -> dict:
    sql = (
        "SELECT key_json FROM e2e_device_keys_json "
        f"WHERE user_id='{user_id}' AND device_id='{device_id}';"
    )
    out = psql(sql)
    if not out:
        sys.exit(f"device {device_id} for {user_id} not found on Synapse")
    return json.loads(out)


def fetch_cross_signing_keys(user_id: str) -> dict[str, dict]:
    sql = (
        "SELECT keytype, keydata FROM e2e_cross_signing_keys "
        f"WHERE user_id='{user_id}' ORDER BY stream_id DESC LIMIT 6;"
    )
    out = psql(sql)
    if not out:
        sys.exit(f"no cross-signing keys for {user_id}")
    by_type: dict[str, dict] = {}
    for line in out.splitlines():
        keytype, keydata = line.split("|", 1)
        if keytype not in by_type:
            by_type[keytype] = json.loads(keydata)
    return by_type


def canonical(obj: dict) -> bytes:
    stripped = {k: v for k, v in obj.items() if k != "signatures"}
    return canonicaljson.encode_canonical_json(stripped)


def pubkey_from_keys_dict(keys_dict: dict[str, str]) -> tuple[str, str]:
    """Return (key_id, pubkey_b64). Expects exactly one ed25519: entry."""
    eds = [(k, v) for k, v in keys_dict.items() if k.startswith("ed25519:")]
    if len(eds) != 1:
        sys.exit(f"expected exactly one ed25519 key, got {len(eds)}: {keys_dict}")
    return eds[0]


def verify(label: str, pubkey_b64: str, canonical_bytes: bytes, sig_b64: str) -> bool:
    vk = VerifyKey(b64decode_unpadded(pubkey_b64))
    try:
        vk.verify(canonical_bytes, b64decode_unpadded(sig_b64))
    except BadSignatureError:
        print(f"  FAIL: {label}")
        return False
    print(f"  OK:   {label}")
    return True


def main() -> int:
    if len(sys.argv) != 3:
        sys.exit(f"usage: {sys.argv[0]} @user:server DEVICE_ID")
    user_id, device_id = sys.argv[1], sys.argv[2]

    print(f"Verifying cross-signing chain for {user_id} / device {device_id}")
    print()

    print("===== Step 1: master signs self_signing =====")
    cs = fetch_cross_signing_keys(user_id)
    master = cs.get("master") or sys.exit("no master key published")
    self_signing = cs.get("self_signing") or sys.exit("no self_signing key published")
    master_kid, master_pub = pubkey_from_keys_dict(master["keys"])
    self_signing_kid, self_signing_pub = pubkey_from_keys_dict(self_signing["keys"])
    ss_sigs = self_signing.get("signatures", {}).get(user_id, {})
    ss_sig = ss_sigs.get(master_kid)
    if not ss_sig:
        sys.exit(f"self_signing key has no signature from master {master_kid}")
    step1_ok = verify(
        f"self_signing pubkey signed by master {master_kid}",
        master_pub,
        canonical(self_signing),
        ss_sig,
    )

    print()
    print("===== Step 2: self_signing signs the device =====")
    device = fetch_device_keys(user_id, device_id)
    device_sigs = device.get("signatures", {}).get(user_id, {})
    device_sig = device_sigs.get(self_signing_kid)
    if not device_sig:
        print(f"  no inline {self_signing_kid} signature in device_keys; "
              "checking e2e_cross_signing_signatures table...")
        sql = (
            "SELECT signature FROM e2e_cross_signing_signatures "
            f"WHERE target_user_id='{user_id}' AND target_device_id='{device_id}' "
            f"AND key_id='{self_signing_kid}';"
        )
        device_sig = psql(sql) or sys.exit(
            f"device {device_id} not signed by self_signing {self_signing_kid} "
            "(neither inline nor in the legacy signatures table)"
        )
    step2_ok = verify(
        f"device {device_id} signed by self_signing {self_signing_kid}",
        self_signing_pub,
        canonical(device),
        device_sig,
    )

    print()
    if step1_ok and step2_ok:
        print("VERDICT: device is properly cross-signed. Peer Matrix clients "
              "will trust it on /keys/query refresh.")
        return 0
    print("VERDICT: cross-signing chain is BROKEN. See doc:")
    print("  matrix-mcp/docs/cross-signing-recover-flow.md")
    return 1


if __name__ == "__main__":
    sys.exit(main())
