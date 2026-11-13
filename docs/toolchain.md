# Toolchain pins

Every measuring tool is pinned by the identity the *artefact* records, not by whatever is
installed. `ReviewRow.instrument` carries the observed `{name, version, commit}` and
`evaluate` refuses a row whose identity is missing, declared, mixed or different from
`configs/b4.json`.

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
sessions. The `ocr pin` gate in `--stage check` is the backstop, and it is one of the three
gates that `--allow-degraded` cannot waive.

## semgrep — `1.184.0`

Not self-updating; the pin is the version string `semgrep --version` prints, recorded in
`configs/*.json` (`sources.semgrep.version`) and in `ReviewRow.instrument.semgrep.version`.

## code-review-graph — `2.3.9`

The crg source is advisory (triage only) and its results never enter a line's denominator,
so it is recorded in `toolchain` but not part of the frozen instrument pair.
