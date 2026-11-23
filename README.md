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

**Starter rules**
- `plaintext-ai-key-in-repo`: an AI key stored in plain text inside a git repository (with the command to confirm it can never be committed)
- `no-secrets-in-mcp-config`: a secret pasted straight into an MCP server's config
- `approved-tools-only`: anything not on your list, e.g. `{"approved": ["Claude", "openai", "github"]}`

**Safe by design**
- Runs only on your machine. It never opens a network connection and never runs another program, not even git (tested).
- It never reads a secret's value into the report, only the variable name (tested).
- Everything starts as "Not reviewed". Finding nothing doesn't prove there's no AI.

Want this kept current across a whole team, mapped to the EU AI Act, NIST AI RMF and state AI laws, with audit-ready evidence? That's XOVA.

Apache-2.0.
