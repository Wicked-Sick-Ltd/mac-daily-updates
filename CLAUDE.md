<!-- PORTFOLIO_STATE:START company=Wicked Sick hash=e8c78c23 last_sync=2026-11-19T10:05Z -->
## Portfolio context (auto-generated — do not edit between the markers)

Repo company: **Wicked Sick**. Full inventory at `wicked-repo-inventory/PORTFOLIO_STATE.md` (canonical in Notion → Engineering Inventory).

**Secrets:** API credentials live in 1Password (Wicked Sick account), never in committed files. Map env vars to `op://vault/item/field` references in a committed `.env.op` (paths only, no secret values) and run via `op run --env-file=.env.op -- <cmd>` so secrets exist only for that process. Don't hardcode keys or commit real values.

**Reusable drop-ins** (use these before building from scratch):
- `acsendr-billing` — Provider-agnostic subscription billing with idempotent webhooks, a two-sided revenue-share ledger, payouts, and a reconciliation invariant that proves every penny is allocated.
- `acsendr-conformance-suite` — A language-neutral behavioural contract with a thin runner, so a rewrite in another stack can be held to the same assertions instead of hand-translating them and letting them drift.
- `acsendr-connector-economics` — A registry of third-party data connectors recording what each one actually costs to ship — verification regime, lead time, money, and blockers.
- `acsendr-elicitation` — Elicit a person's decision-making identity — behavioural-event questionnaire, public-domain Big Five, and reconciliation against their own written record.
- `acsendr-intake-contract` — One normalised document shape every ingest source produces, plus a deterministic quality gate that runs before anything is paid for.
- `acsendr-mailbox-import` — Mailbox and transcript ingestion with sent-vs-received voice attribution — mbox, .eml, IMAP and VTT/SRT, no OAuth app and no vendor review.

**Other Wicked Sick repos:**
- `HubSpot Order Management` — Bi-directional sync between HubSpot and order systems — scoped, not yet built.
- `pfSense P2P Link` — Point-to-point ISP link with routed /26 block (188.213.95.128/26 over 100.66.66.0/30 transit).
- `Self-hosted UniFi Controller` — UniFi Network Controller running on Proxmox instead of cloud.
- `wicked-amiga/amiga-projects` — —
- `wicked-amiga/battle-isle-remake` — —
- `wicked-amiga/deuteros-app` — Deuteros mobile port (Godot 4) — strategy & licensing stage
- `wicked-amiga/deuteros-parallel` — Parallel Godot port of Deuteros (1991), companion to Deuteros Resurrected
- `wicked-amiga/supremacy-remake` — Source-derived Supremacy reconstruction, extraction tools, and original-CPU validation evidence
- _... +122 more — see /Github/PORTFOLIO_STATE.md_
<!-- PORTFOLIO_STATE:END -->

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A single-file bash script (`daily-update.sh`) that automates daily macOS maintenance — updating Homebrew, npm, pip3, Ruby gems, Mac App Store apps, VS Code, and system software. Designed to run unattended via launchd or cron. There is no build step, test suite, or linter.

## Running

```bash
./daily-update.sh            # Run all updates
./daily-update.sh --dry-run  # Preview without making changes
```

## Architecture

**`daily-update.sh`** uses `set -euo pipefail` and runs 9 update sections sequentially:
1. macOS Software Updates (flags only, no auto-install)
2. Mac App Store via `mas`
3. Homebrew formulae
4. Homebrew casks
5. Homebrew cleanup + `brew doctor`
6. npm global packages (includes MCP filesystem server)
7. pip3 core tools
8. Ruby gems (update system, update gems, cleanup old versions)
9. VS Code + extensions

**Key design patterns:**
- **Fail-soft execution** — `run_step()` wraps `eval` with error capture; failures log `✗` but don't halt the script.
- **No sudo** — the script runs entirely as the current user. npm, pip3, and gem are configured to use user-writable directories (see Environment Setup below).
- **Platform detection** — auto-detects Apple Silicon (`/opt/homebrew`) vs Intel (`/usr/local`) Homebrew paths.
- **Graceful degradation** — missing tools (npm, pip3, gem, VS Code, mas) are skipped with a log message.
- **Dry-run mode** — `--dry-run` flag causes `run_step()` to log commands without executing them.
- **Logging** — all output goes to `~/.local/log/daily-update-YYYY-MM-DD.log` via `log()` (tee to stdout + file). `add_summary()` collects results printed at the end.

**`com.craigfletcher.daily-update.plist`** is a macOS LaunchAgent config that schedules the script daily at 6 AM. Note: the plist hardcodes the script path as `$HOME/mac-daily-updates/daily-update.sh`.

## Environment Setup (lines 55–77)

The script configures its own PATH before running any updates — this is critical for unattended execution where the user's shell profile isn't loaded:

- **Homebrew** — sources `brew shellenv` from the detected prefix
- **pyenv** — prepends `~/.pyenv/shims` to PATH so `pip3` resolves to pyenv's Python, avoiding Homebrew's externally-managed Python
- **npm** — prepends `~/.npm-global/bin` to PATH (npm's global prefix is set to `~/.npm-global` to avoid `/usr/local` permission issues)
- **Ruby gems** — sets `GEM_HOME=~/.gem/ruby/<version>` so `gem install/update` writes to a user-owned directory instead of `/Library/Ruby/Gems`

When adding a new update section that depends on a tool installed in a non-standard location, add the PATH setup in this block.

## Shell Conventions

- Use `log()` for all user-facing output (not raw `echo`)
- Use `section()` for new update categories
- Use `run_step "description" "command"` to wrap commands with error handling and dry-run support
- Use `add_summary()` to register results for the end-of-run summary
- Check tool availability with `command -v` before use

## Shared repository guidance

Read [AGENTS.md](AGENTS.md) for the shared contributor and agent instructions.
Keep the project-specific constraints above in effect.
