# Git: branches, remotes, and the three exempt zones

## Branches

| branch | role | contents |
| --- | --- | --- |
| `feat/v1-spec` | active, default | the line that gets pushed; everything below is history |
| `research/wayfinder` | archive | research notes only (4 files) |
| `t15-step0-ts-block`, `t15-step1-inventory`, `t15-d1-d2`, `t15-p0-denominator`, `t15-p1-aacr`, `t15-live-acceptance` | archive | one branch per #41 step, so each step's state can be read without replaying the commits |

None of the archives is a default branch, and none takes new commits: they record how a step was reached, not where the line goes next. All eight were pushed on 2026-11-15; the seven archives had never left this machine before that.

## Remote

`origin`'s fetch URL is the read-only mirror `https://gh-proxy.com/https://github.com/...`, applied by a global `url.<mirror>.insteadOf` rule rather than by the clone's own config. The reason is measured, not assumed: direct HTTPS to `github.com` from here is intermittent (2026-11-15, 3 × `git ls-remote`: 1 connected in 1.3 s, 2 timed out after 21 s).

Push must not go through the mirror - an unauthenticated third-party write is refused, and a host that serves the fetch is a host that can serve a different tree. `remote.origin.pushurl` therefore names the direct host with an explicit `:443`:

```
git remote get-url --push origin   # https://github.com:443/romeokeita231/code-review-system.git
```

The port spelling is what keeps the global `insteadOf` from rewriting the push URL: the rule matches the literal prefix `https://github.com/`, which `https://github.com:443/` is not. A `pushInsteadOf` rule does not help here - it is matched against the original URL, which is already `github.com`, so a mirror-to-direct mapping never fires.

`git push origin <branch>` authenticates from the Windows credential store; there is no `gh-proxy.com` entry there, so there was nothing to rotate. A push can still fail with `Connection was reset`: retry, the connection is what is intermittent, not the credentials.

## The three exempt zones

`datasets/`, `research/` and `artifacts/acceptance/` are exempt from secret scanning (`.github/secret_scanning.yml`) because they hold external bytes verbatim - rewriting them would change `content_sha256` and break every archived run that cites the hash.

Two rules keep the exemption from becoming a hole:

- `npm run check:secrets` (also a preflight gate, so a drill cannot start without it): any provider shape *outside* the zones fails; a shape *inside* them must be registered in `artifacts/acceptance/PROVENANCE.md` with a source repository and a commit, or the gate fails.
- `research/` stays external-bytes-only. A note of our own belongs in `docs/` - the exemption is for copies, not for anything we write.
