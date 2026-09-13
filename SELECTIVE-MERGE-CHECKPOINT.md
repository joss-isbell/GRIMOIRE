# Selective merge checkpoint — 2026-09-12

## Durable starting point

- Recovered candidate: `vi/selective-v093-ready` at `fcaa73a6478fbceb067ebd0dd22dfe4cf1738c2c`.
- Main observed at `4cc20de8c9cbd95a554c27ffc84f3f20fb9ba4e1`.
- Original source: `grim-16-incident-recorder`; leave that branch unchanged.

## Requested scope

Include upstream integration through **prime-agent v0.9.3**, Python kernel startup/environment repair, and disposable test environments. Exclude shell/subagent message queuing changes and incident-recorder/diagnostic changes. Do not substitute v0.9.4.

## Remaining at this checkpoint

1. Read the recovered candidate's existing notes/history; do not rebuild the work from scratch.
2. Check only the requested scope boundaries and preservation of main-only changes. Make and commit any concrete correction separately.
3. Land the candidate on main without force-pushing, then record the final commit and only the local execution steps still needed.

This recovery checkpoint does not claim the candidate has been fully verified. Avoid broad test/audit passes, GitHub Actions changes, and artifact-export workflows. Commit each completed piece and explain the next remaining operation in its commit message.
