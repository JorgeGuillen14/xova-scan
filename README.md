# xova-scan

**See every AI tool on your computer, what it can reach, and what it has been doing. One command, nothing leaves your machine.**

AI assistants and agents now run commands, edit files, open browsers and connect to your databases and accounts, often through MCP servers you added once and forgot about. xova-scan answers:

- **What AI is here?** Apps, command-line agents, MCP servers, AI libraries in your code, AI keys.
- **What can it reach?** Your files, databases, code repositories, web browser, whole desktop, or any command.
- **What did it actually do?** Commands run, risky commands, files changed, websites reached, tools used, in the last 30 days.
- **What should I fix first?** The top three problems, in plain language.

It works on **macOS, Windows and Linux**, needs only **Python 3.11+**, and has **no dependencies**.

---

## Quick start

```sh
python3 -m pip install git+https://github.com/JorgeGuillen14/xova-scan
python3 -m xova_scan.cli
```

That scans your home folder. Time depends on how much code and agent history you have: seconds on a small machine, a minute or more with years of agent logs. To scan one folder only:

```sh
python3 -m xova_scan.cli ~/code
```

Using pipx instead: `pipx run --spec git+https://github.com/JorgeGuillen14/xova-scan xova-scan`

---

## What you'll see

This is the scanner's real output on a demo machine built by [`examples/demo_machine.py`](examples/demo_machine.py) (a small fake home folder with Claude, Cursor, Codex and a few MCP servers; no real person's data). Run `python3 examples/demo_machine.py` to reproduce it exactly. A test keeps this block identical to what the scanner prints.

<!-- demo-output-start -->
```
xova-scan 0.4.0: 9 AI items on this machine, 5 problems

What your AI can reach
  - databases: supabase
  - files on this machine: filesystem
  - run any command: Codex
  - web browser: playwright

What your AI did in the last 30 days (1 agent session)
  - ran 4 shell commands (most: git 2, npm 2, rm 1)
  - risky commands: delete files (rm -rf) x1, force push x1
  - changed 2 files (mostly in ~/code/shop)
  - reached 1 web host: platform.openai.com
  - used tools through MCP: supabase 1

Fix first
  1. Codex: This AI agent runs commands and changes files without asking first. One bad prompt or poisoned web page can act with your full access. Turn approvals back on.
  2. supabase: This MCP server's config holds a secret in plain text (env, header, URL or argument). Use an environment variable reference.
  3. OPENAI_API_KEY: An AI key is stored in plain text inside a git repository. Confirm it can never be committed: git check-ignore -v "$HOME"/code/shop/.env must print a rule, and git ls-files must not list it. Better: use a secrets manager.

MCP servers (3)
  - filesystem  Claude Desktop (~/Library/Application Support/Claude/claude_desktop_config.json)
  - playwright  Claude Desktop (~/Library/Application Support/Claude/claude_desktop_config.json)
  - supabase  Cursor (~/.cursor/mcp.json)

AI apps (2)
  - Claude  ~/Applications/Claude.app
  - Cursor  ~/Applications/Cursor.app

AI libraries in code (2)
  - anthropic  ~/code/api/requirements.txt
  - openai  ~/code/shop/package.json

AI keys (names only) (2)
  - OPENAI_API_KEY  in ~/code/shop/.env
  - SUPABASE_ACCESS_TOKEN  in Cursor config for MCP server 'supabase' (~/.cursor/mcp.json)

All rule findings (5)
  ! agent-runs-without-asking: Codex  This AI agent runs commands and changes files without asking first. One bad prompt or poisoned web page can act with your full access. Turn approvals back on.
      in ~/.codex/config.toml
  ! no-secrets-in-mcp-config: supabase  This MCP server's config holds a secret in plain text (env, header, URL or argument). Use an environment variable reference.
      in Cursor (~/.cursor/mcp.json)
  ! plaintext-ai-key-in-repo: OPENAI_API_KEY  An AI key is stored in plain text inside a git repository. Confirm it can never be committed: git check-ignore -v "$HOME"/code/shop/.env must print a rule, and git ls-files must not list it. Better: use a secrets manager.
      in ~/code/shop/.env
  ! unpinned-mcp-server (2): playwright, supabase
      This MCP server downloads its latest code every time it starts. Pin an exact version so new code can't arrive unreviewed.

Local scan only. Nothing left this machine. Secret values were never read into the report. Finding nothing does not prove there is no AI here.
```
<!-- demo-output-end -->



### The sections

| Section | What it tells you |
|---|---|
| **What your AI can reach** | Each MCP server and agent sorted by what it can touch. "Your whole desktop" and "run any command" are the most powerful. |
| **What your AI did** | Read from the agents' own local logs (Claude Code, Codex, Claude Desktop): counts only, never your prompts or file contents. |
| **Fix first** | The three most serious problems, worst first. |
| **Inventory** | MCP servers, AI apps, AI command-line tools, AI libraries in your projects, AI keys (names only), cloud accounts set up here. |
| **All rule findings** | Every problem, grouped by rule, with where it is. |

### The rules it checks

| Rule | What it means | How to fix it |
|---|---|---|
| `agent-runs-without-asking` | An agent (Claude Code bypass mode, Codex full-auto) runs commands and edits files with approvals off. A poisoned web page or file can act with your full access. | Turn approvals back on, or limit it to a sandbox. |
| `secret-in-ai-logs` | Real-looking keys or tokens were pasted into or printed in AI chats and kept in the agent's local logs. | Rotate those keys and clear old logs. |
| `no-secrets-in-mcp-config` | A key is pasted directly into an MCP server's config (env, header, URL or argument). | Use an environment variable reference instead. |
| `plaintext-ai-key-in-repo` | An AI key sits in a `.env` file inside a git repository. | Check it's git-ignored and never committed (the finding gives the exact command), or use a secrets manager. |
| `unpinned-mcp-server` | An MCP server downloads its newest code every time it starts (`npx pkg`, `uvx pkg`). | Pin an exact version (`pkg@1.2.3`, `pkg==1.2.3`). |
| `approved-tools-only` | Something isn't on your approved list (only when you give it one). | Approve it, or remove it. |

---

## Getting the most out of it

**1. Set your approved list.** Write the AI tools you allow into a file:

```json
{"approved": ["Claude", "Cursor", "github", "openai", "anthropic"]}
```

```sh
python3 -m xova_scan.cli --rules approved.json
```

Everything else is flagged as not approved: the fastest way to spot AI that crept in.

**2. Re-run it regularly.** New MCP servers, agents and keys appear quietly. Run it weekly, or after installing any AI tool. Compare runs with `--json`:

```sh
python3 -m xova_scan.cli --json > scan-$(date +%F).json
```

The JSON is deterministic: the same machine state produces identical output, so a `diff` between two runs shows exactly what changed.

**3. Look further back or skip the logs.**

```sh
python3 -m xova_scan.cli --days 90        # read 90 days of agent activity
python3 -m xova_scan.cli --no-activity    # skip agent logs entirely (faster)
```

**4. Scan a whole team's machines.** Each person runs it and shares the `--json` file (or the XOVA export below). Look for the same findings across machines: that's where a team policy is missing. To bring every machine into XOVA as one list, see `merge` below.

**5. Fix in order.** Do "Fix first" top to bottom. The first item is usually the one that would hurt most.

---

## What it promises (and tests)

- **Nothing leaves your machine.** It never opens a network connection.
- **It never runs other programs**, not even git.
- **Secret values are never read into the report.** Only the names of the variables that hold them. Anything shaped like a key is redacted, even inside names and paths.
- **It never says a key file is safe.** Git ignore rules are too subtle to judge reliably, so it gives you the command to check instead.
- **It won't crash or hang on odd files** (huge, binary, malformed, special files).
- **Same machine state in, identical report out.**

Each promise is covered by the test suite (`python3 -m unittest discover -s tests`), which runs on macOS, Windows and Linux.

## What it doesn't do

- It can't see AI that runs only in the cloud or in a browser tab without a local trace (for example ChatGPT on the web). It notices AWS, Azure and Google Cloud are set up on the machine, but never reads inside them.
- Agent activity covers Claude Code, Codex and Claude Desktop logs today. Other agents' activity isn't read yet.
- Finding nothing does not prove there's no AI on the machine.

---

## For organizations: XOVA

xova-scan shows one machine. **XOVA** is an AI governance platform in development. Today it keeps an organization's AI inventory, assesses each system against a built-in rules library (EU AI Act, NIST AI RMF and its Generative AI profile, OMB M-25-21 and M-25-22, Texas TRAIGA, Colorado's AI law, NYC Local Law 144), and records every change in an audit trail. Its determinations come from rules code, not AI. Connections to Microsoft 365, Google Workspace and cloud AI services are planned, not yet available.

Send a scan to XOVA:

```sh
python3 -m xova_scan.cli --export-xova ./xova-import --team <your XOVA department ID>
```

This writes XOVA inventory import files (25 systems per file). Everything arrives as Detected and Not reviewed. Nothing is approved and no owner is guessed.

Send a whole team: each person runs the export above and shares their folder. Then one person combines them:

```sh
python3 -m xova_scan.cli merge --out ./team-import ./alice-export ./bob-export
```

Each AI system becomes one entry that says how many machines it was found on (counted by machine name), not one entry per machine. If the same AI system is listed under different departments, `merge` stops and asks for `--team`. It never picks one for you. Pass `--team` to put every entry under one department. Run `merge` again later with new exports: the entries keep the same IDs, so XOVA updates them instead of adding duplicates. Use either single-machine exports or `merge` for an organization, not both, or the same system shows up twice.

---

## Questions

**Does it need admin rights?** No. It reads your own files only.

**Will it slow my computer?** It reads files once, then stops. Nothing keeps running.

**Is my data shared with XOVA?** No. Nothing is sent anywhere. The export only writes files on your machine; sharing them is your choice.

**Why does "Could not read" appear?** Some folders can't be read with your account's permissions. The scan lists them so you know they weren't checked.

License: Apache-2.0.
