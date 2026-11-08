# ADR-0020: Inventory engines run fixed queries the database can only select

**Status:** accepted · **Date:** 2026-11-09 · **Amends:** PRD-006 D5 · **Context:** PRD-019, host inventory (internal product documentation)

## Context

PRD-006 D5 said: *no signature can run a command; capabilities are read-only primitives (read registry values,
list a certificate store, find files by name, read matching lines of a text file, list packages, list installed
programs)*. The reason was sound: the signature database is data the server hands out inside the script, and
data must not be able to make a machine execute anything.

Under that rule the scripts could not see what matters most to a migration: what the installed OpenSSL and
OpenSSH *can* do (ML-KEM, ML-DSA), the SSH server's *effective* policy, the suites Windows *actually*
negotiates with, which process listens on which port with which library loaded, TPM, BitLocker, LUKS and FIPS
state, or the versions and TLS backends of the runtimes and servers on the machine. Those facts exist only as
the output of system tools and cmdlets. Reading files alone gets a third of the picture.

## Decision

1. Each engine carries a **fixed table of queries**, each an id and a read-only command line (or cmdlet
   script block) written in the engine source: `QUERIES` / `query_def` in the shell engine, `$Queries` in the
   PowerShell engine. Every query has a timeout (`timeout -k 5 20` on Linux) and its tool is checked before it
   runs; a missing tool is a `skip` line with the tool's name.
2. A signature's `query` capability names an **id**, never a command. An id outside the table is skipped and
   said so in the facts file (`skip <signature> query <id> is not in this engine`). The Go validator refuses a
   database whose query ids are not in `signatures.Queries`, and a test checks that list against both engines'
   tables, so the three cannot drift.
3. The Windows engine starts no program other than Windows' own `certutil.exe`, `netsh.exe` and `ssh.exe`,
   called by full path under `System32`, each with the fixed arguments in the table; everything else is an
   in-process cmdlet. The shell engine already ran `dpkg-query`, `rpm`, `apk`, `find`, `awk` and `sha256sum`; its
   queries add version and capability listings, `sshd -T`, `ss`, `lsblk` and `testparm`, nothing that writes.
4. `listeners` is a capability of its own, not a query, because its output is structured and because it reads
   `/proc/<pid>/maps` (or a process's module list): the engine keeps only the *names* of mapped libraries that
   match a fixed pattern.
5. The scripts' headers and the Inventory page say exactly this, so a person reading the script before running
   it finds the table and the promise in the same place.

## Consequences

- The database can grow (138 signatures at this writing, from 16) without touching the engines, and still cannot
  make them run anything new. Adding a query is an engine change, reviewed as code, in both engines and the Go
  list at once.
- Facts format version 3 adds the `query` and `listener` record kinds; the server reads versions 1 to 3.
- The wording "runs no other program" in earlier material is replaced by the exact statement in point 3.
