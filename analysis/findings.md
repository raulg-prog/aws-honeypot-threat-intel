# Findings — AWS SSH Honeypot

Deeper analysis of the data collected by the honeypot over a 7-day window. Summary findings are in the main [README](../README.md); this document shows the supporting queries and reasoning.

**Dataset:** 205,620 events, one Cowrie SSH honeypot, ~7 days of collection.

---

## 1. Volume and concentration

Total events: **205,620**.

Source-IP distribution (top entries):

| Source IP | Events | Share of total |
|---|---|---|
| `118.179.155.139` | 102,451 | ~49.8% |
| `103.252.127.250` | 90,515 | ~44.0% |
| `43.133.186.13` | 10,699 | ~5.2% |
| `93.89.113.60` | 126 | <0.1% |
| `222.108.109.37` | 113 | <0.1% |
| all others | — | remainder |

**Two IPs generated ~94% of all activity.** This is the dataset's defining feature: the honeypot wasn't hit by broad, even scanning — it was hit by a small number of high-volume automated campaigns, with everything else as background noise.

The activity timeline shows this as two dominant spikes (Jun 19 and Jun 23), each corresponding to one of the two top IPs sustaining tens of thousands of events in a day.

---

## 2. These are complete intrusion sessions, not scans

Breakdown by event type:

| Event ID | Count |
|---|---|
| `cowrie.session.closed` | 25,922 |
| `cowrie.session.connect` | 25,922 |
| `cowrie.client.version` | 25,781 |
| `cowrie.client.kex` | 25,721 |
| `cowrie.command.input` | 25,568 |
| `cowrie.session.params` | 25,528 |
| `cowrie.log.closed` | 25,527 |
| `cowrie.login.success` | 25,522 |
| `cowrie.login.failed` | 68 |
| `cowrie.command.failed` | 35 |
| `cowrie.session.file_upload` | 12 |
| `cowrie.client.fingerprint` | 6 |
| `cowrie.session.file_download` | 1 |

The near-identical ~25,500 count across every stage of the SSH session lifecycle — connect, key exchange, version, login, command, close — shows these are **full sessions carried through to completion**, repeated ~25,000 times. The attackers weren't just knocking; they were connecting, authenticating, running commands, and disconnecting in a tight automated loop.

### On login success vs. failure

`cowrie.login.success` = 25,522 versus `cowrie.login.failed` = 68.

This is expected Cowrie behavior, not a security finding about the credentials themselves: Cowrie is a medium-interaction honeypot that **accepts most credentials by design** in order to observe post-authentication behavior. The analytical value is therefore not in *which passwords were tried* but in *what was executed after access was granted*.

This also means the "Top Usernames" panel should be read as **usernames present on successful logins** (dominated by `root`), not as brute-force attempt volume.

---

## 3. Post-access behavior — the captured playbook

Commands run, by source IP (`cowrie.command.input`):

| Source IP | Commands |
|---|---|
| `118.179.155.139` | 12,806 |
| `103.252.127.250` | 11,314 |
| `43.133.186.13` | 1,337 |
| all others | <120 combined |

The same handful of IPs that dominated connections also dominated command execution — **99.6% of commands came from three IPs.**

Top commands:

| Command | Count | Interpretation |
|---|---|---|
| `echo -e "\x6F\x6B"` | 25,457 | **Shell-confirmation handshake** |
| `uname -a` | 17 | OS / kernel fingerprint |
| `cat /proc/uptime 2 > /dev/null \| cut -d. -f1` | 8 | Uptime check |
| `m=0; while read k v r; do ... MemTotal ... /proc/meminfo ...` | 8 | **Memory check** |
| `uname -m 2 > /dev/null` | 8 | Architecture fingerprint |
| `uname -s -v -n -m 2 > /dev/null` | 8 | Detailed OS fingerprint |

### The "ok" handshake

`\x6F\x6B` is hexadecimal for the ASCII string **`ok`**. Automated SSH bots issue this immediately after obtaining a shell to verify that command execution actually works (that they're on a real, responsive shell and not a tarpit or broken session) before committing to deploying a payload. Its appearance 25,457 times — once per successful session — confirms a single automated toolkit was responsible for the bulk of the traffic.

### Hardware reconnaissance

The follow-up commands probe **CPU architecture, OS, uptime, and total memory** (`uname` variants, `/proc/uptime`, `/proc/meminfo` MemTotal). This is target-qualification: the bot profiles the host to decide whether it's worth infecting — sufficient memory and the right architecture make a box a viable target for crypto-mining or DDoS recruitment.

**Full captured sequence:** gain shell → confirm with `ok` → fingerprint hardware → (decide). The honeypot was disconnected before any second-stage payload was deployed at scale (only 12 `file_upload` and 1 `file_download` event recorded).

---

## 4. Geographic origin

GeoIP enrichment placed the bulk of traffic in a single dominant cluster (consistent with the two top IPs), with a long tail of lower-volume sources spread across multiple continents. The attack map visualizes this concentration: one large high-count cluster, surrounded by scattered single- and double-digit sources worldwide — the signature of "a few heavy automated actors plus the constant ambient background of internet-wide scanning."

---

## 5. Data integrity note

5 of the ~25,568 `cowrie.command.input` events originated from my own IP (`172.118.221.25`, geolocating to my home region) during honeypot setup verification — a test `wget http://example.com/test` and an `echo SHELL_TEST`, timestamped on day one of the deployment.

At **0.002%** of the dataset they have no effect on any aggregate finding, and they are left in the data rather than filtered, with this disclosure, for transparency. Their presence actually confirms the capture pipeline was working from day one.

---

## Takeaways

- The public internet subjects even an unannounced, never-advertised host to **immediate and sustained automated attack** — 205K events in a week from a box nobody was told about.
- The threat is overwhelmingly **automated and concentrated**: a small number of bots generate the vast majority of traffic.
- Modern SSH bots follow a **disciplined playbook**: confirm shell, fingerprint hardware, qualify the target — all before deploying anything.
- **Validating the data mattered more than building the charts.** The first-glance reading ("25,535 root brute-force attempts") was wrong; checking event types and source IPs revealed the real story (accepted logins + a single botnet handshake).
