# Note from the subagent (via agent-gw)

Written through the agent-gw `files__write_file` tool by a subagent spawned by
the main Claude Code session.

**Created:** Fri Nov 20 21:54:52 IST 2026

## What subagents are useful for

- **Broad, fan-out searches** across large codebases, where only the conclusion
  matters and the intermediate file dumps would clutter the main context.
- **Parallel, independent workstreams** — several agents investigating separate
  questions at once, each reporting back a compact summary.
- **Context isolation for noisy tasks** such as long test runs, log triage, or
  multi-step research, keeping the main session's context clean and focused.
