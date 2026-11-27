## Agent skills

### Gates

`npm run gate:all` is enforced by CI (`.github/workflows/gates.yml`): it replays each
known incident through the check that catches it. Keep it green.
When a child process fails to start, or its output comes back empty, run
`npm run env:probe` before debugging — piped stdio is `spawn EPERM` in this sandbox
and `scripts/capture.ts` is the working path. See `docs/agents/gates.md`.

### Issues

Specs and issues live as GitHub issues on `romeokeita231/code-review-system`, driven
by the `gh` CLI. Labelling and the five triage roles: `docs/agents/triage-labels.md`;
how a spec becomes work: `docs/agents/issue-tracker.md`.

### Domain docs

Single-context: `GLOSSARY.md` at the repo root plus ADRs under `docs/adr/`. See `docs/agents/domain.md`.
