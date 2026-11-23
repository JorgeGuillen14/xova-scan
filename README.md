# xova-scan

Find every AI tool on your machine and check it against your rules, in one command.

```sh
pipx run xova-scan            # or: pip install xova-scan && xova-scan
xova-scan ~/code --rules rules.json
xova-scan --json > ai-inventory.json
```

**What it finds**
- MCP servers set up in Claude Desktop, Claude Code, Cursor, Windsurf, VS Code and Gemini CLI
- AI apps installed (ChatGPT, Claude, Cursor, Ollama, LM Studio and more)
- AI libraries in your code (OpenAI, Anthropic, LangChain, MCP SDKs and more), across every project
- AI API keys, by **name only**

**What your AI can reach and what it did** (from the agents' own local logs, last 30 days)
- What each AI tool can touch: your files, databases, code repositories, web browser, whole desktop, any command
- Agents set to act without asking (Claude Code bypass mode, Codex full-auto)
- What the agents actually did: shell commands run, risky commands (rm -rf, force push, piping downloads to a shell, sudo, dropping tables), files changed and where, web hosts reached, MCP tools used, sub-agents started
- Keys and tokens that ended up in AI chat logs (counted, never shown)
- Only counts, program names, web hosts and folders are reported. Prompts, command arguments and file contents never are. Skip it with `--no-activity`.

**Starter rules**
- `plaintext-ai-key-in-repo`: an AI key stored in plain text inside a git repository (with the command to confirm it can never be committed)
- `no-secrets-in-mcp-config`: a secret pasted straight into an MCP server's config
- `agent-runs-without-asking`: an AI agent that runs commands and edits files with approvals turned off
- `secret-in-ai-logs`: real-looking keys or tokens sitting in AI agents' chat logs
- `unpinned-mcp-server`: an MCP server that downloads its latest code on every start
- `approved-tools-only`: anything not on your list, e.g. `{"approved": ["Claude", "openai", "github"]}`

**Safe by design**
- Runs only on your machine. It never opens a network connection and never runs another program, not even git (tested).
- It never reads a secret's value into the report, only the variable name (tested).
- Everything starts as "Not reviewed". Finding nothing doesn't prove there's no AI.

Want this kept current across a whole team, mapped to the EU AI Act, NIST AI RMF and state AI laws, with audit-ready evidence? That's XOVA.

Apache-2.0.
