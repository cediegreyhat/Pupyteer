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
| Pupyteer registered modules | **101** |
| Already covered (PRESENT) | 79 |
| Portable, not yet written (STDLIB) | 5 |
| Needs a native payload (NATIVE) | 38 |

Parity is the goal; this table is the honest distance to it.

## Classification

Each upstream module falls into one of three buckets. The bucket decides the
work, the risk, and which agent it can ever run on.

### PRESENT — 79
Pupyteer already provides the capability, possibly under a different name
(Pupy `ls` → Pupyteer `file_list`, Pupy `get_info` → `sysinfo`,
Pupy `clear_logs` → `log_clear`). This bucket has grown as modules landed and
as the manifest was corrected — see *Reclassified as already covered* below.

`ad`, `apps`, `become`, `call`, `cat`, `cd`, `check_vm`, `clear_logs`, `cloudinfo`, `contacts`, `cp`, `creddump`, `display`, `dns`, `download`, `drives`, `echo`, `edit`, `env`, `exit`, `exploit_suggester`, `forward`, `get_hwuuid`, `get_info`, `getdomain`, `getprivs`, `http`, `igd`, `interactive_shell`, `ip`, `isearch`, `last`, `load_package`, `logs`, `ls`, `migrate`, `mimikatz`, `mimishell`, `mkdir`, `msgbox`, `mv`, `netcreds`, `netstat`, `persistence`, `pexec`, `port_scan`, `portfwd`, `privesc_checker`, `process_kill`, `ps`, `psexec`, `psh`, `pwd`, `pyexec`, `pyshell`, `reg`, `rm`, `rwmic`, `screenshot`, `search`, `services`, `shares`, `shell_exec`, `smb`, `smbspider`, `socks5proxy`, `ssh`, `sshell`, `stat`, `sudo_alias`, `tasks`, `ttyrec`, `upload`, `users`, `w`, `wmic`, `write`, `x509`, `zip`

### STDLIB — 5
**No third-party tree needed at all.** These are pure stdlib and are portable
now; they only need writing.

`alive`, `date`, `getpid`, `getppid`, `getuid`

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
| `cp` | `pupy/modules/cp.py` | Server-side over fs_get+fs_put; chunked, no agent change |
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

1. **STDLIB** — `alive`, `date`, `getpid`, `getppid`, `getuid`. Pure stdlib, no
   dependency and no agent change, so it is the cheapest measurable progress.
2. **PY_DEP, operator-side only** — anything that can be done server-side over
   existing capabilities before vendoring the dependency tree.
3. **Vendor the Python dependency tree** — the single largest unblock; turns the
   whole third-party bucket from impossible to routine.
4. **NATIVE** — per-payload work, last.

Items 1 and 2 are verifiable from a Linux build host. Items 3 and 4 are not, and
should be planned as "implement here, verify on a live target".
