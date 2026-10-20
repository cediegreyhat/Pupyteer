# Pupy parity

Pupyteer is the modernised successor to [Pupy](https://github.com/n1nj4sec/pupy).
This file is the authoritative worklist for reaching **full feature parity**:
every module upstream Pupy ships, classified by what it actually takes to land
it here.

Machine-readable twin: [`data/pupy_parity.json`](../data/pupy_parity.json).
Regenerate by re-running the inventory against `pupy/modules` + `pupy/commands`.

## Where we stand

| | Count |
|---|---|
| Upstream Pupy modules | **122** |
| Upstream Pupy console commands | **16** |
| Pupyteer registered modules | **41** |
| Already covered | 24 |
| Not yet ported | 98 |

Parity is the goal; this table is the honest distance to it.

## Classification

Each upstream module falls into one of four buckets. The bucket decides the
work, the risk, and which agent it can ever run on.

### PRESENT — 23
Pupyteer already provides the capability, possibly under a different name
(Pupy `ls` → Pupyteer `file_list`, Pupy `get_info` → `sysinfo`,
Pupy `clear_logs` → `log_clear`).

`cat`, `clear_logs`, `download`, `get_info`, `ip`, `ls`, `migrate`, `mimikatz`, `persistence`, `ps`, `screenshot`, `search`, `shell_exec`, `upload`

### AGENT_ACTION — 5
Needs a new action on the implant. This is the **highest-risk** bucket: an action
must be added to `agent/core/stub.py` **and** `agent/core/pe_template.c` **and**
the `CAPABILITIES` list, or the listener refuses the task as undeclared. Editing
one side without the other is the documented dominant failure mode.

These are all pure-logic actions — no third-party dependency — so once the agent
side lands they are straightforwardly testable.

`ad`, `become`, `call`, `exploit_suggester`, `mimishell`, `netstat`, `port_scan`, `privesc_checker`, `process_kill`, `pwd`, `sudo_alias`, `ttyrec`

### STDLIB — 14
**No third-party tree needed at all.** Audited by fetching each upstream module
and reading its non-framework imports: this batch has *zero* third-party
imports, so they were classified PY_DEP by category rather than by source. They
are portable now and only need writing.

`alive`, `date`, `display`, `drives`, `echo`, `getpid`, `getppid`, `getprivs`, `getuid`, `last`, `logs`, `msgbox`, `users`, `w`

### PY_DEP — 41
Needs Pupy's vendored Python dependency tree (`pupy/packages/*`: impacket,
paramiko, scapy, crypto) shipped inside the generated payload. **Reachable only
from the Python agent** — `pe_template.c` is a compiled C binary with no
interpreter, so a PE deployment cannot host these at all. Vendoring the tree into
a single generated script is the real work here.

`alive`, `apps`, `cd`, `check_vm`, `cloudinfo`, `contacts`, `cp`, `creddump`, `date`, `display`, `dns`, `drives`, `echo`, `edit`, `env`, `exit`, `forward`, `get_hwuuid`, `getdomain`, `getpid`, `getppid`, `getprivs`, `getuid`, `http`, `igd`, `interactive_shell`, `isearch`, `last`, `load_package`, `logs`, `mkdir`, `msgbox`, `mv`, `netcreds`, `pexec`, `portfwd`, `psexec`, `psh`, `pyexec`, `pyshell`, `reg`, `rm`, `rwmic`, `services`, `shares`, `smb`, `smbspider`, `socks5proxy`, `ssh`, `sshell`, `stat`, `tasks`, `users`, `w`, `wmic`, `write`, `x509`, `zip`

### NATIVE — 38
Needs a native payload (a binary, reflective DLL, or shellcode), not just Python.
These are the longest pole and the ones most dependent on the C agent path.

`beroot`, `bypassuac`, `credcap`, `duplicate`, `getsystem`, `gpstracker`, `hashmon`, `hide_process`, `impersonate`, `inveigh`, `keylogger`, `lazagne`, `linux_stealth`, `lock_screen`, `loot_memory`, `mapped`, `memory_exec`, `memstrings`, `mimipy`, `mouselogger`, `nbnsspoof`, `netmon`, `odbc`, `outlook`, `pipecatcher`, `powerview`, `pywerview`, `rdesktop`, `rdp`, `record_mic`, `rfs`, `scapy_shell`, `shellcode_exec`, `tcpdump`, `text_to_speach`, `usniper`, `vibrate`, `webcamsnap`

## Console commands

Upstream Pupy console commands, for parity tracking on the operator side
(Pupyteer's equivalent surface is the Textual TUI in `pupyteer/tui/`):

`config`, `connect`, `creds`, `dnscnc`, `exit`, `exposed`, `gen`, `help`, `jobs`, `listen`, `logging`, `python`, `restart`, `run`, `sessions`, `tag`

## Landed so far

| Module | Upstream source | Notes |
|---|---|---|
| `cat` | `pupy/modules/cat.py` | Wraps `fs_get`; no agent change |
| `search` | `pupy/modules/search.py`, `isearch.py` | Server-side BFS over `fs_list` |
| `stat` | `pupy/modules/stat.py` | Derived from `fs_list` of the parent; no agent change |
| `netstat` | `pupy/modules/netstat.py` | New action: declared in `capabilities.py`, **both** agents, and a module |
| `process_kill` | `pupy/modules/process_kill.py` | New action taking a pid arg; C side uses `taskkill /F /PID` |
| `pwd` | `pupy/modules/pwd.py` | New bare-verb action; the cwd was not exposed by anything else |
| `get_hwuuid` | `pupy/modules/get_hwuuid.py` | Misclassified as PY_DEP; the lookup is pure stdlib |
| `exploit_suggester` | `pupy/modules/exploit_suggester.py` | Server-side over `sysinfo`; bundled dataset, no phone-home |
| `env` | `pupy/modules/env.py` | First module under the native-reimplementation strategy; stdlib one-liner |

### Reclassified as already covered

Found during tranche 1: these were counted as missing but an existing module
already provides the capability. The manifest was over-counting the gap.

| Pupy module | Covered by |
|---|---|
| `port_scan` | `post_portscan` ("port scan a host from the target") |
| `privesc_checker` | `privesc` |
| `sudo_alias` | `post_sudo` |

## Suggested tranche order

1. **AGENT_ACTION, pure-logic subset** — `netstat`, `process_kill`, `pwd`,
   `stat`, `port_scan`. Extends the agent in both files; no dependencies.
2. **PY_DEP, operator-side only** — anything that can be done server-side over
   existing capabilities before vendoring the dep tree.
3. **Vendor the Python dependency tree** — the single largest unblock; turns the
   whole PY_DEP bucket from impossible to routine.
4. **NATIVE** — per-payload work, last.

Items 1 and 2 are verifiable from a Linux build host. Items 3 and 4 are not, and
should be planned as "implement here, verify on a live target".
