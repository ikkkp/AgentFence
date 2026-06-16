# Audit Export

AgentFence stores audit events locally in SQLite and can export them as JSON or CSV.

Shell events use action `shell.exec`. MCP proxy events use `mcp.tool`, `mcp.resource`, or `mcp.prompt` and include server, kind, name, arguments, and the final decision in metadata.

## CLI

```bash
agentfence audit export --format json --output audit.json
agentfence audit export --format csv --output audit.csv
```

Use `--limit` to cap the number of recent rows:

```bash
agentfence audit export --format csv --limit 500
```

## Daemon

```bash
curl "http://127.0.0.1:37421/audit/export?format=json&limit=1000"
curl "http://127.0.0.1:37421/audit/export?format=csv&limit=1000"
```

Exported subjects, reasons, and metadata strings have already passed through the audit redactor before being stored.
