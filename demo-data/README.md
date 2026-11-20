# Demo data for the gateway

- `finance/` is the only folder the `files` upstream (official MCP filesystem server) can see.
- `finance/vendors/vendor_onboarding_note.txt` contains a **planted prompt injection**. When an agent
  reads it through the gateway, the run is marked as tainted and later payments or exports from the
  same session are blocked.
- `bank_state.json` is created by `cmd/demo-bank-mcp` on first run. Delete it to reset balances.
