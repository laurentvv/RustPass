# AGENTS.md — RustPass

> Instructions for any AI coding agent working in this repository.
> Structure: **common block** (delimited, resyncable) + **project-specific part** (free).

<!-- BEGIN:agents-common v3.2 — block shared across repositories (agents-kit). Do not edit by hand: resync with scripts/sync_agents.py -->
<!-- The script only replaces what lies between the BEGIN/END markers; all repository-specific content is preserved -->

> **Priority on conflict**: explicit user instruction > this repo's §7 > this common block. The §5 prohibitions are lifted only on a formal explicit request. This block is overwritten on every sync: add nothing here (lessons → §7, see §6).

## §1 Environment

- Default machine: **Windows 11**, shell **Git Bash** — any deviation (PowerShell 7, WSL, Linux…) is declared in §7; use ONLY the declared shell's commands.
- Python: **`uv` only** — never `pip install`, never `requirements.txt` (`uv add` / `uv run`).
- Machine paths: never hardcoded — go through the project configuration (config.py / .env / dedicated section).
- Code search: on large repositories (> 5k files, or a `.tgrep/` index folder present), prefer the fast indexed `tgrep` CLI from the PATH over recursive `grep`/`find` scans — `tgrep -- "pattern" .`, `tgrep -t <type> -- "pattern" .` (first use: `tgrep index .`; keep `.tgrep/` git-ignored). Below ~2k files, plain `git grep` is already instant.
- Text files: **UTF-8 without BOM**, line endings per `.gitattributes`. Never markdown exported or pasted from a rich editor (Notion, Word…): it arrives escaped and becomes unreadable for the agent.
- Language: **English** for everything written in the repository (code, comments, docs, commit messages, ledger); **French** for chat replies to the user. Any deviation is declared in §7.
- Long context (architecture, detailed lessons, ecosystem): see the repo's `PROJECT_MEMORY.md` or `docs/` — AGENTS.md stays deliberately short.

## §2 On-disk state = source of truth

Never rely on the context window alone: it degrades, gets compressed, gets erased. Work state lives in **one DuckDB database**, `.agent/state.duckdb`, managed only through the `agent-state` skill CLI (shipped by the kit; another path is declared in §7):

```bash
uv run --no-project .agents/skills/agent-state/scripts/state_agents.py [--repo PATH] <command>
```

## §3 Execution loop

1. **Bootstrap** — `bootstrap` (§2); a feature suite starting on an empty ledger opens its sprint there (features, contract frozen BEFORE the first line of code).
2. **Action** — log the task before running it (§2).
3. **Gate** — a failing static check **forbids** syncing the ledger (compiler/linter green first — never claim "check OK" without running it). Verification tools pinned to a version, identical locally and in CI.
4. **Sync** — after each write or test, update the ledger (§2).
5. **Errors** — on exception or interruption, `bootstrap` again (§2).
6. **Closure** — features marked completed, sprint `step reset`, `done` log entry; report to the user: done · verified (how) · not verified.

## §4 Git & delivery

- **Never work or push directly on the default branch** (`main`/`master`): `feat/…` or `fix/…` branch before any change.
- **PRs stay small and deterministic**: one PR, one self-contained change — declared scope, no drive-by edits, green tests; the whole diff is reviewable in one pass and rebuildable from the branch alone.
- **Never a destructive git command on live work**: `reset --hard`, `clean -fd`, `checkout -- .` / `restore .`, `push --force` on a shared branch.
- Push only on the user's explicit request.
- **Pre-commit checklist**: tests/linters green · no secret in the diff · maintained docs up to date · ledger synced.

## §5 Security & integrity

- **No secrets** in code, commits, logs or on screen (user paths, e-mails, tokens) → env vars / dummy placeholders.
- **Never delete** state files, databases, archives or business data. Any ambiguous deletion: **restate the list** to the user and get confirmation BEFORE executing.

## §6 Truth & validation

- "Verified" = **actually executed** (exit 0) or **visually inspected** (screenshot/render looked at) — never inferred from code, intentions or logs.
- Every factual claim (number, color, presence of an asset) is backed by a measurement or a screenshot kept as evidence.
- **Never disable, skip or weaken a test** to get green; an unresolved failure or a skipped step is reported as is.

<!-- END:agents-common -->

---

## §7 Project-specific

### Mission / scope
**RustPass** — Clean-room, memory-safe password manager suite in pure Rust (`egui`/`eframe` desktop GUI `rustpass`, KeePassXC-compatible CLI `rustpass-cli`, and browser Native Messaging host `rustpass-proxy`) with full binary interoperability for KeePass **KDBX v4.0 / v4.1** (Argon2id/Argon2d/AES-KDF, ChaCha20/AES-256-CBC, HMAC-SHA-256 block stream, inner stream protection) and **KDBX v3.1**, RFC 6238 TOTP / Steam Guard + QR codes, CSPRNG & Diceware password generation, Security Health Audit, and bilingual FR/EN UI.

### Declared locations
- Machine / shell: Windows 11 + PowerShell 7 / Git Bash.
- Language: English in repository, French in chat replies.

### Key commands
```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

### Business invariants (never break)
- **Zero plaintext master keys or passwords leaked**: wrap composite keys, master passwords, and protected entry values in `zeroize::Zeroizing` in memory; never log secrets or write unencrypted vault secrets to settings files.
- **Atomic vault writes**: always write `.kdbx` saves to a sibling `.kdbx.tmp` file and atomically rename over the destination path so an interrupted write never corrupts an existing vault.
- **Zip-Slip / Path Traversal defense**: attachment exports validate destination paths before writing to disk.
- **No GitHub Actions**: validation runs locally; never create `.github/workflows/`.

### References
- REAP Inventory & Coverage Matrix: `docs/inventory.md`
- Porting Notes & Specification Mapping: `PORTING.md`
