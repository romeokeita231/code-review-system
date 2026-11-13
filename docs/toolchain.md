# Toolchain pins

Every measuring tool is pinned by the identity the *artefact* records, not by whatever is
installed. `ReviewRow.instrument` carries the observed `{semgrep, ocr, aor_model}` and
`evaluate` refuses a row whose identity is missing, declared, mixed, or different from the
frozen pin in `artifacts/preregistration.json` (which `--stage check` also compares with
`configs/b4.json`, so an edit to the config cannot move the pin).

## ocr (open-code-review) — `04deca6`

| | |
| --- | --- |
| config pin | `sources.aor.versionCommit = "04deca6"` in `configs/*.json` |
| full commit | `04deca6721ec4fe2f74a6a0eb069d2a01b3d31cb` (`feat(session): inspect saved sessions by ID`, 2026-11-09) |
| `ocr --version` | `open-code-review v1.13.6 (04deca6) windows/amd64` |
| binary sha256 | `7230310d964929787e77b9a0e5a563b7b44271315df61f2570330dbcf08bcaa9` |
| source tree | `%LOCALAPPDATA%\crs\ocr-src` |
| installed at | `C:\nvm4w\nodejs\node_modules\@alibaba-group\open-code-review\node_modules\@alibaba-group\ocr-win32-x64\bin\opencodereview.exe` (the path the `ocr` launcher resolves: it looks up the platform package first) |

**`04deca6` is not a release tag.** `v1.13.7` was tagged at `b1dcffb` and `v1.13.8` at
`4236c87`, so the pin is only reproducible by building the commit:

```powershell
git clone --filter=blob:none https://github.com/alibaba/open-code-review "$env:LOCALAPPDATA\crs\ocr-src"
git -C "$env:LOCALAPPDATA\crs\ocr-src" checkout 04deca6721ec4fe2f74a6a0eb069d2a01b3d31cb
# go.mod declares go 1.26.10; GOTOOLCHAIN=auto fetches it
cd "$env:LOCALAPPDATA\crs\ocr-src"
$env:CGO_ENABLED = "0"
go build -ldflags "-s -w -X main.Version=v1.13.6 -X main.GitCommit=04deca6 -X main.BuildDate=<utc>" `
  -o opencodereview.exe ./cmd/opencodereview
```

That is `make build` with `GIT_TAG=v1.13.6` (the tag `git describe --tags --abbrev=0`
returns at this commit), `GIT_COMMIT=04deca6`, `CGO_ENABLED=0`.

### No self-update

`ocr` spawns `scripts/update.js` on every invocation, which runs
`npm i -g @alibaba-group/open-code-review@latest`. That is how the binary moved from
`04deca6` to `4236c87` between two sessions while the config still claimed the pin.

Two independent brakes:

1. `TOOL_ENV = { OCR_NO_UPDATE: "1" }` in `src/config/index.ts`, passed to every tool the
   system spawns (`src/l3/semgrep.ts` runner, the instrument probe, the drill's preflight
   and DSH child processes).
2. `OCR_NO_UPDATE=1` in the user environment, so a manual `ocr` run does not update either.

Both are needed: (1) covers the automated paths, (2) covers a human typing `ocr` between
sessions. The `ocr pin` gate in `--stage check` is the backstop, and it is one of the gates
that `--allow-degraded` cannot waive.

It also happened once *after* the pin was restored: `update.js` is spawned detached, so an
update check triggered by an earlier invocation can finish minutes later and replace the
binary. The gate caught it (`ocr v1.13.8 (4236c87)` while the config pinned `04deca6`) and
the file was re-copied from `%LOCALAPPDATA%\crs\bin`. Treat "pinned" as a property that has
to be re-observed before every run, not as a state that was achieved once.

## The AOR model — `deepseek-flash` (served)

The binary is only half of the instrument. What `ocr` reports is decided by the model it
calls, and that model is neither compiled in nor pinned by the binary:

| | |
| --- | --- |
| provider | `deepseek` (`Source: provider:deepseek`) |
| endpoint | `https://api.deepseek.com` |
| requested | `deepseek-chat` — `~/.opencodereview/config.json` → `providers.deepseek.model` |
| served | `deepseek-flash` — the id the service answers with (`ocr llm test` prints `resp.Model`) |
| recorded as | `ReviewRow.instrument.aor_model = { provider, id, params: { url, configured } }` |

`id` is the served model and the ruler; `params.configured` is what the client asked for.
The frozen pin in `artifacts/preregistration.json` carries both, and `evaluate` refuses a
row whose `id`, `provider`, `url` or `configured` differs from it — the same refusal the
`ocr` commit gets, one level deeper.

The probe is `ocr llm test`, which sends a real request with a tool and replays the turn
after the tool call. That covers the failure this gate exists for: a configured key with no
quota, or an endpoint that accepts a chat but rejects a tool-call round trip, passes every
local check and then degrades every AOR row of the one run. Cost is a few thousand tokens
per process; it is cached per process and also runs once in `--stage check` / `prepare`.

If a future build compiles a model in, record it as `bundled@<commit>`. "Fixed" is a
statement too, and an empty field cannot be told apart from an unrecorded one.

## Node / platform

`node` and `platform` are recorded in `toolchain` only. They are not part of the frozen
instrument set: the measured artefact is the plugin bundle, and the bundle is checked by
`plugin bundle` (mtime this round, a source-tree hash in the follow-up).

## semgrep — `1.184.0`

Not self-updating; the pin is the version string `semgrep --version` prints, recorded in
`configs/*.json` (`sources.semgrep.version`) and in `ReviewRow.instrument.semgrep.version`.

## code-review-graph — `2.3.9`

The crg source is advisory (triage only) and its results never enter a line's denominator,
so it is recorded in `toolchain` but not part of the frozen instrument pair.
