#!/usr/bin/env python3
"""
Générateur de licences Orchestrateur.
Usage : python3 generate_license.py --email client@example.com --tier pro --seats 1 --days 365
La clé privée doit être dans ~/.orchestrateur/license_private.pem
"""
import argparse
import base64
import json
import os
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone, timedelta


def b64url_encode(b: bytes) -> str:
    return base64.b64encode(b).decode().replace("+", "-").replace("/", "_").rstrip("=")


def generate_license(email: str, tier: str, seats: int, days: int) -> str:
    key_file = os.path.expanduser("~/.orchestrateur/license_private.pem")
    if not os.path.exists(key_file):
        sys.exit(f"Clé privée introuvable : {key_file}")

    with open(key_file, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    exp = int((datetime.now(timezone.utc) + timedelta(days=days)).timestamp())
    payload = json.dumps(
        {"email": email, "tier": tier, "seats": seats, "exp": exp},
        separators=(",", ":"),
    ).encode()
    payload_b64 = b64url_encode(payload)

    signature = private_key.sign(
        payload_b64.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    sig_b64 = b64url_encode(signature)

    return f"{payload_b64}.{sig_b64}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Générateur de licences Orchestrateur")
    parser.add_argument("--email",  required=True, help="Email du client")
    parser.add_argument("--tier",   default="pro", choices=["pro", "enterprise"], help="Tier de la licence")
    parser.add_argument("--seats",  type=int, default=1, help="Nombre de postes autorisés")
    parser.add_argument("--days",   type=int, default=365, help="Durée de validité en jours")
    args = parser.parse_args()

    key = generate_license(args.email, args.tier, args.seats, args.days)
    exp_date = datetime.now() + timedelta(days=args.days)

    seats_label = f"{args.seats} poste{'s' if args.seats > 1 else ''}"

    print(f"\n{'═'*60}")
    print(f"  LICENCE ORCHESTRATEUR — {args.tier.upper()}")
    print(f"{'═'*60}")
    print(f"  Email  : {args.email}")
    print(f"  Tier   : {args.tier}")
    print(f"  Postes : {seats_label}")
    print(f"  Expire : {exp_date.strftime('%d/%m/%Y')}")
    print(f"{'─'*60}")
    print(f"\n{key}\n")
    print(f"{'─'*60}")
    print(f"  Installation client :")
    print(f"    mkdir -p ~/.orchestrateur")
    print(f"    echo '<clé>' > ~/.orchestrateur/license.key")
    print(f"{'═'*60}\n")
