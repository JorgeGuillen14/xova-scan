# xova-scan

**See every AI tool on your computer, what it can reach, and what it has been doing. One command, nothing leaves your machine.**

AI assistants and agents now run commands, edit files, open browsers and connect to your databases and accounts, often through MCP servers you added once and forgot about. Normal security tools see "Cursor is installed" and stop there. xova-scan answers the questions that matter:

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

That scans your home folder (about a minute on a busy machine). To scan one folder only:

```sh
python3 -m xova_scan.cli ~/code
```

Using pipx instead: `pipx run --spec git+https://github.com/JorgeGuillen14/xova-scan xova-scan`

---

## What you'll see

```
xova-scan 0.3.0: 64 AI items on this machine, 18 problems

What your AI can reach
  - databases: supabase
  - run any command: Codex
  - web browser: playwright
  - your whole desktop: computer-use
  ...

What your AI did in the last 30 days (210 agent sessions)
  - ran 9120 shell commands (most: git 2210, npm 1340, python3 990, ...)
  - risky commands: delete files (rm -rf) x37, force push x1
  - changed 412 files (mostly in ~/code/app, ~/code/api)
  - reached 48 web hosts: github.com, api.openai.com, ...
  - 6 unique keys or tokens sit in its chat logs

Fix first
  1. Codex: This AI agent runs commands and changes files without asking first...
  2. 6 unique keys or tokens in 9 AI log files: ...
  3. supabase: This MCP server's config holds a secret in plain text...
```

(Illustrative example; your numbers will differ.)

Then the full inventory and every finding, grouped.

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

**4. Scan a whole team's machines.** Each person runs it and shares the `--json` file (or the XOVA export below). Look for the same findings across machines: that's where a team policy is missing.

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

xova-scan shows one machine. **XOVA** keeps an organization's whole AI inventory current across every machine, Microsoft 365, Google Workspace and cloud accounts, checks it against the rules that apply to you (EU AI Act, NIST AI RMF, OMB M-25-21, state AI laws and your own policies), and produces audit-ready evidence. Every determination is deterministic and can be re-run.

Send a scan to XOVA:

```sh
python3 -m xova_scan.cli --export-xova ./xova-import --team <your XOVA department ID>
```

This writes XOVA inventory import files (25 systems per file). Everything arrives as Detected and Not reviewed. Nothing is approved and no owner is guessed.

---

## Questions

**Does it need admin rights?** No. It reads your own files only.

**Will it slow my computer?** It reads files for about a minute, then stops. Nothing keeps running.

**Is my data shared with XOVA?** No. Nothing is sent anywhere. The export writes local files you choose to share.

**Why does "Could not read" appear?** Some folders are protected by your system. The scan lists them so you know they weren't checked.

License: Apache-2.0.
