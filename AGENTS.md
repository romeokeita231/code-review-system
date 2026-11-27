## Agent skills

### Gates

`npm run gate:all` is enforced by CI (`.github/workflows/gates.yml`): it replays each
known incident through the check that catches it. Keep it green.
When a child process fails to start, or its output comes back empty, run
`npm run env:probe` before debugging — piped stdio is `spawn EPERM` in this sandbox
and `scripts/capture.ts` is the working path. See `docs/agents/gates.md`.

### Issue tracker

Issues and specs live as GitHub issues on `romeokeita231/code-review-system`, driven by the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical triage roles map 1:1 to `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `GLOSSARY.md` at the repo root plus ADRs under `docs/adr/`. See `docs/agents/domain.md`.
