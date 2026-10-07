---
name: ctf-solver
description: Use when working TryHackMe (or similar) CTF rooms/challenges — OSINT, web, crypto, forensics, reverse engineering, detection engineering, and boot2root. Covers session/VPN setup, task-file retrieval, per-category solving playbooks, and troubleshooting a lab machine that's gone dark.
---

# CTF Solver

Playbook distilled from hands-on TryHackMe sessions (OSINT rooms, a reversing/network challenge,
a Detection-as-Code room, and a boot2root). The throughline: prefer **direct API/CLI access over
clicking through a slow UI**, verify claims against primary evidence instead of trusting a single
tool's first answer, and keep the environment clean (one machine running at a time).

## Session setup

**VPN over AttackBox.** If the user has an OpenVPN config, connect from the local attacker
machine instead of starting THM's AttackBox — it's faster and lets you use your own tool
versions. OpenVPN needs root:

```bash
sudo openvpn --config "<file>.ovpn" --disable-dco --daemon --log ~/thm-vpn.log --writepid ~/thm-vpn.pid
```

`--disable-dco` sidesteps a common `Cannot allocate DCO dev dynamically` failure in VM/container
environments. Verify with `ip -brief addr show tun0` and `ip route get <target-ip>` (should route
via `tun0`) before attacking anything.

**One lab machine at a time.** For every room that needs a target:
1. Expand the task, click **only** "Start Lab Machine" (never the AttackBox unless the challenge
   explicitly requires it, e.g. a Splunk/web-app-only challenge with no IP to attack).
2. Dismiss the "large screen recommended" modal via "Start lab machine anyway" if it appears.
3. Wait for the IP to reveal (often shows "Shown in Nmin Ns" — poll every ~20-30s rather than
   guessing a single sleep).
4. **Ping it from the terminal** before doing anything else — this is the user's preferred
   verification step, not optional. `ping -c3 <ip>`; a real remote host answers with `ttl=6x` and
   0% loss over the VPN's ~200ms RTT.
5. Work from the Kali terminal (curl/nmap/tshark/etc.), not the browser, whenever the target is a
   raw IP+port.
6. **Terminate the machine as soon as its flag is captured**, before starting the next task's
   machine. Use the room's "Active machines information" panel → Terminate → confirm. This is a
   standing user preference — don't wait to be asked each time.

## Retrieving task files fast

THM's "Download Task Files" button fires a presigned S3 URL that **expires in ~120 seconds**.
Two ways to grab it:
- Watch network requests right after clicking (`read_network_requests` filtered on
  `amazonaws|attachment`) and `curl` the URL immediately — it will time out if you wait.
- If using a real browser (not a sandboxed one), the file also lands in `~/Downloads/` — for
  large/slow files this is more reliable than racing the presigned URL. Poll
  `ls -lat ~/Downloads/*.crdownload` (Chrome's in-progress marker) until it disappears, or use
  `until ! ls ~/Downloads/*.crdownload >/dev/null 2>&1; do sleep 5; done` as a background wait —
  never chain raw `sleep` loops in the foreground (harness blocks it).

## Per-category playbooks

### OSINT
- **EXIF GPS ambiguity**: `GPSLatitude`/`GPSLongitude` without a `Ref` field are unsigned — a
  naive paste into Google Maps can land you in the wrong hemisphere entirely. Cross-check against
  any visible context clue (language on signage, security-company stickers, architecture) to pick
  the sign, or read the room's "answer format" — a working country name confirms it.
- **Newspaper/document dating**: triangulate a date from *multiple* independent stories on the
  same page (e.g. one event's date range intersected with another's) rather than trusting a
  blurry masthead.
- **Historical event research**: once you have a date + place, search primary archives (town
  history sites, rescue-society annals, newspaper archives) for the *exact* name/age asked for —
  summary blogs often round or omit details the flag needs.
- **Archive.org "WARC" hints**: a task mentioning "warc" points at a standalone Internet Archive
  *item* (Archive Team `warczone` collection), not a normal Wayback Machine capture — the CDX API
  and playback (`web.archive.org/web/...`) will show nothing for it. Search
  `archive.org/advancedsearch.php?q=...` for the item, then read its `Firstfiledate` metadata
  field for a "when did this first appear" answer. If archive.org itself is degraded/down,
  triangulate from external walkthroughs but *verify* by submitting — don't just trust one blog.
- **Browser-artifact chains** (Windows triage → password): a KAPE/triage bundle handing you SAM +
  SYSTEM + SECURITY hives, a DPAPI masterkey, and a browser profile is a *DPAPI decryption chain*:
  1. `impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL` → NT hashes **and**
     LSA secrets (`DefaultPassword` here is often the plaintext Windows password).
  2. `impacket-dpapi masterkey -file <masterkey-guid> -sid <user-SID> -password <pw>` → decrypted
     masterkey.
  3. Chrome `Local State` → `os_crypt.encrypted_key` is base64 with a 5-byte `DPAPI` prefix —
     strip it, then `impacket-dpapi unprotect -file <blob> -key 0x<masterkey>` → the browser's AES
     key.
  4. `Login Data` password blobs are `v10` + 12-byte nonce + AES-256-**GCM** ciphertext+tag —
     decrypt with `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.
  5. Also check `Web Data`'s `autofill` table — form data (not saved passwords) is stored in
     **plaintext** and is an easy way to leak a password/username that was typed once.
- **VeraCrypt containers**: a file that's an exact round size (e.g. 100.0 MB), `size % 512 == 0`,
  and ~8 bits/byte entropy is almost certainly VeraCrypt. If no `veracrypt` binary is installed
  and root/`cryptsetup` isn't available, a pure-Python decryptor is short: PBKDF2-HMAC-SHA512 (500k
  iters default) on the first 64-byte salt → AES-256-**XTS** decrypt bytes 64-512 of the header,
  check for `VERA` magic at offset 0 of the decrypted block → header fields (all big-endian, byte
  offsets *from the volume start*, so subtract 64 when indexing into the decrypted buffer):
  hidden-size@92, volume-size@100, **enc-area-start@108**, **enc-area-size@116**, flags@124,
  sector-size@128, master-keys@256 (64 bytes = key+tweak). Critical gotcha: the **data area's XTS
  unit numbers are absolute file-sector indices** (`byte_offset / 512`), *not* relative to where
  the data area starts — get this wrong and you'll decrypt 100% noise despite a perfect header
  match. Try the outer volume password on the hidden header too (offset 65536) in case of a hidden
  volume.
- **Visual geolocation**: crop and zoom aggressively (`convert -crop ... -resize 300%`) on
  street signs, storefront text, and flags/uniforms before guessing — a landmark's *neighboring*
  building is often the actual answer, not the landmark itself (read the question literally).

### Crypto
- Small/fixed-size keys (e.g. 4-byte XOR) + a known plaintext prefix (`THM{`, a file magic byte,
  etc.) → recover the key by XORing the first N ciphertext bytes against the known plaintext, then
  decrypt the rest with the repeating key. Don't reach for a brute-force cracker when a
  known-plaintext attack is one line of Python.

### Web
- A file-serving `?doc=` / `?file=` parameter with an extension whitelist ("only .pdf/.png") is
  frequently bypassed by a **stream wrapper** (`php://filter/convert.base64-encode/resource=...`)
  because whitelist checks are often written for plain filenames and never re-checked once a
  `://` wrapper is detected. First move: leak the app's own source through the same parameter
  (`resource=index.php`) to read the exact filter logic before guessing bypasses blind.
- Prefer reading the source over black-box guessing whenever any LFI/wrapper primitive exists —
  it turns "try 40 payloads" into "read the 3-line bug."

### Forensics (pcap / binaries)
- `tshark -q -z io,phs` for protocol hierarchy, `--export-objects http,<dir>` to carve
  transferred files straight out of a capture, `-z conv,tcp` to spot short/unusual TCP
  conversations (a C2 port, an exfil channel) `tshark -Y 'tcp.port==X && tcp.len>0' -T fields -e
  tcp.payload` gets exact application-layer bytes when `follow,tcp,hex` truncates or misparses.
- A large stripped Linux ELF (tens of MB) that came from network traffic is very likely
  **PyInstaller**-packed. `pip install --break-system-packages pyinstxtractor-ng` (works from
  PyPI, unlike the classic `pyinstxtractor.py` which security policy may block as a raw GitHub
  download-and-run) unpacks it; the entry-point `.pyc` in the extracted dir has the real logic.
- **Python bytecode version mismatch**: if the extracted `.pyc` is for a different Python version
  than the local interpreter, `marshal.loads()` and decompilers (`decompyle3`, `uncompyle6`) will
  fail ("bad marshal data" / "Unsupported Python version"). `pip install xdis` and use
  **`pydisasm`** instead — it disassembles bytecode from *any* supported version regardless of the
  host interpreter, and the constants table alone (hardcoded keys, IPs, ports) is often enough
  without a full decompile.
- **WMI repository forensics** (persistence hiding in `OBJECTS.DATA`/`INDEX.BTR`/`MAPPING*.MAP`,
  not Run keys/Scheduled Tasks/Startup): `pip install cim` (flare-wmi's `python-cim`), then
  `from cim import CIM, CIM_TYPE_WIN7; from cim.objects import Tree` and walk
  `Tree(CIM(CIM_TYPE_WIN7, repo_dir)).root` recursively via `.classes` / `.namespaces` /
  `ns.class_(name).instances`. Look in `root\subscription` for `__EventFilter` (the trigger query,
  e.g. a suspicious time-based `Win32_LocalTime` filter), `CommandLineEventConsumer` /
  `ActiveScriptEventConsumer` (the payload), and `__FilterToConsumerBinding` (ties them together).
  A custom/fake-legit-named class (e.g. `Win32_HardwareTelemetry`) is often where an
  attacker stashes a base64+compressed payload as an instance property, loaded by the consumer's
  command line.

### Reverse engineering
- .NET assemblies (Godot C# games, Windows tools): `dotnet tool install -g ilspycmd` — pin an
  older `--version` (e.g. `8.0.0.7246`) if the local `dotnet` SDK is older than the tool's default
  target, it'll auto-resolve to the nearest compatible build. Decompiled output usually reveals
  hardcoded HMAC/encryption keys and full client-server protocols directly.
- For a game/app that talks to a server: decompile the client, extract the exact protocol
  (endpoint order, HMAC message format, header rotation), then **replay the protocol from a
  script** rather than through the game UI — client code sometimes contains dead/unused branches
  (an unused "derive privileged role" method, say) that are the actual intended solution path the
  UI never exercises.

### Detection engineering (Detection-as-Code / Sigma / Splunk)
- These apps are usually React/vanilla-JS SPAs backed by a JSON API. Pull `app.js`, grep for
  `fetch(`/`apiGet(`/`apiSend(` and their endpoint templates — once you have
  `api/prs/{id}/rule` (PUT), `api/prs/{id}/checks/{syntax,convert,validate,redteam}` (POST),
  `api/prs/{id}/approve`, `api/prs/{id}/merge`, drive the **entire** tune → test → merge loop with
  `curl`, which is an order of magnitude faster than editing in a browser textarea and clicking
  through tabs for every iteration.
- Read the room's threat-intel/incident report and any "environment routines" (normal-ops)
  doc *before* touching a rule — the tuning almost always hinges on excluding one specific benign
  routine (a scheduled job, a designated service account, a legitimate remote-access tool used
  only on workstations) while still catching the technique everywhere else.
- Iterate: syntax → convert (read the generated query, sanity check field names against the PR's
  `supportedFields`) → validate (TP/FP/FN score against the answer key) → redteam (bypass tests —
  these usually demand tool-agnostic detection via a stable identifier like `OriginalFileName`
  rather than a specific binary name, and/or catching a technique variant the first pass missed).
  Only approve+merge once **all four** pass.
- Query the PR detail endpoint directly for ground truth instead of guessing field names from the
  vague rule description: `supportedFields`, `attackLog` (a sample raw event), and `issue` (the
  actual coverage-gap description) are usually all present in `GET api/prs/{id}`.

### Boot2root
- Standard recon first: `nmap -Pn -sV --top-ports 200`, then enumerate the web app's actual
  attack surface (WordPress: `wpscan --enumerate p,t,u`, but note default plugin/theme wordlists
  can miss anything custom — check `/wp-json/` for unexpected REST namespaces, directory listings
  under `wp-content/uploads/`, and exposed files before assuming "nothing's wrong here, must be a
  0-day").
- **Don't mass-fuzz a shared/rate-limited lab box** (13k-entry plugin wordlists, full wpscan
  aggressive mode) back-to-back — it can trip a WAF/fail2ban ban or just overload a small VM. If
  the target stops answering ICMP *and* every TCP port simultaneously right after heavy scanning,
  suspect you've knocked it over or gotten banned, not that "the box is fine but service X is
  down." Diagnose in this order: (1) is the VPN itself still up? (`pgrep openvpn`, `ip addr show
  tun0`) — if `tun0` is gone, that's the whole problem, reconnect the VPN, nothing wrong with the
  target; (2) if the VPN is confirmed healthy but the box is still unreachable after several
  minutes, check the room page — THM machines can simply **stop/expire** independent of anything
  you did; if it shows "Off", just start a fresh one (new IP) rather than assuming a ban; (3) only
  after ruling out both of those, treat it as a genuine ban and back off aggressive tooling once
  it's reachable again.

## Answer submission mechanics

- THM shows an "Answer format" placeholder like `***{***_*****_***}` — `*` counts characters,
  `_`/other literal chars are literal. Use it to sanity-check a recovered flag's shape (word
  lengths, punctuation) before submitting, and to disambiguate OCR/leet-speak ambiguity (e.g. is
  that character `0`/`O`, `1`/`l`, in a 3-character group implying a specific word).
- Prefer JS-level DOM manipulation (native `<input>` value setter + dispatch `input`/`change`
  events) over character-by-character typing when filling many answer boxes at once — it's far
  faster and works around React controlled-input quirks that plain `.value =` misses.
- Clicking a scrolled-to "Check" button can land on the wrong element if the page re-flows after
  focus/typing — re-screenshot or re-`find` the button immediately before clicking rather than
  reusing a coordinate from an earlier screenshot.

## General principles

- **Verify, don't just trust one source.** A single walkthrough, a single tool's decompiled
  output, or a single archive query can be wrong (site outages, version mismatches, stale blogs).
  Cross-check against a second source or, best of all, the platform's own "Correct Answer"
  confirmation.
- **Read the actual question wording** before spending time solving the wrong sub-problem (e.g.
  "the building to the *right* of the landmark," not the landmark itself).
- **When a GUI app has a JSON API underneath, use the API.** It's faster, scriptable, and
  produces reproducible artifacts (a `.py` exploit script) worth handing back to the user.
- **Respect the user's session hygiene preferences**: VPN-only (no AttackBox) when a raw IP
  target exists, ping-verify before attacking, terminate machines promptly, and don't run
  destructive/mass-scanning tooling against a shared lab box without a good reason.

## Collaborative CTF/Pentest Workflow

Use this protocol when working with a user as a team. The goal is deliberate progress with a
visible evidence chain, not a sequence of unexplained commands.

### 1. Name the current task before acting

- State the room task and phase explicitly: setup, discovery, service identification, exploitation,
  privilege escalation, or flag capture.
- State the task objective in one sentence and what evidence will prove it complete.
- Do not silently jump to the next room task just because a tool produced an interesting result.
- Before every command, explain what it tests and what result would change the next step.

### 2. Keep attacker and target roles distinct

- Say whether a command runs in Kali/AttackBox or on a shell obtained from the target.
- Assume local enumeration tools and wordlists run on the attacker machine unless a remote shell is
  explicitly established.
- Treat the lab host as the target, not as a place to install attacker tooling.

### 3. Use a narrow, evidence-first progression

Prefer this sequence unless the room gives a stronger local clue:

1. Verify the current IP, VPN interface, route, and reachability.
2. Discover open ports with the smallest useful scan; expand to all TCP ports when results conflict
   with the target's expected role.
3. Run version/default scripts only against confirmed ports.
4. Identify domain, hostname, service identities, and naming contexts before targeted enumeration.
5. Enumerate one protocol or attack surface at a time.
6. Verify each credential, hash, share, shell, and flag against the target before recording it as
   confirmed.

For each finding, record: command, raw output, interpretation, confidence, and next check. Keep
observed facts separate from hypotheses and candidate answers.

### 4. Handle changing lab state explicitly

- A restarted or expired machine may receive a new IP. Treat the old IP as invalid immediately.
- Update every subsequent command and the working notes when the IP changes.
- Re-run ping and route checks after an IP change; never assume a prior scan still applies.
- If a scan finds no ports but ping succeeds, discriminate among stale IP, missing VPN route,
  filtering, and transient service state before changing attack paths.

### 5. Treat answer formats as constraints, not evidence

- Read the exact room question and answer format before solving or submitting it.
- Use character counts and literal punctuation to reject impossible candidates, but do not infer an
  answer solely from its length.
- When a candidate came from a room-provided list, walkthrough, hint, or answer format rather than
  target output, label it as unverified and run the smallest check that can confirm it.
- Never present a guessed username, password, hash, or flag as confirmed. Say what source produced
  it and what remains to verify.
- When a tool and the room disagree, trust the room's accepted answer only after checking the exact
  question, format, and command semantics; record the correction so it is not repeated.

### 6. Prefer the room's intended artifacts

- If a room supplies a modified username or password list, download it and use it for the relevant
  task after inspecting its location and format.
- First enumerate broadly only when necessary to discover the protocol or domain. Then reduce to
  confirmed unique users/accounts for targeted checks such as AS-REP requests.
- Preserve raw artifacts before decoding or transforming them. Record the exact transformation,
  including removed delimiters, encoding alphabet, hash mode, or case normalization.

### 7. Close each phase cleanly

- Before proceeding, summarize what the current task proved, what it did not prove, and the next
  task objective.
- Submit answers only after the room's own confirmation or direct target evidence supports them.
- For flags, record account, path, raw value, transformation, final value, and submission state.
- If a flag was not captured in the transcript, document the retrieval command and say it was not
  captured. Never fill the gap from memory or a guessed walkthrough value.
- At completion, remove unnecessary secrets from public notes, terminate the lab machine, and keep
  only the minimum local credential evidence needed for reproducibility.
