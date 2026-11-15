# Git: branches, remotes, and the three exempt zones

## Branches

| branch | role | contents |
| --- | --- | --- |
| `feat/v1-spec` | active, default | the line that gets pushed; everything below is history |
| `research/wayfinder` | archive | research notes only (4 files) |
| `t15-step0-ts-block`, `t15-step1-inventory`, `t15-d1-d2`, `t15-p0-denominator`, `t15-p1-aacr`, `t15-live-acceptance` | archive | one branch per #41 step, so each step's state can be read without replaying the commits |

None of the archives is a default branch, and none takes new commits: they record how a step was reached, not where the line goes next. All eight were pushed on 2026-11-15; the seven archives had never left this machine before that.

## Remote

`origin`'s fetch URL is the read-only mirror `https://gh-proxy.com/https://github.com/...`, applied by a global `url.<mirror>.insteadOf` rule rather than by the clone's own config.

Direct-connection measurements, both labelled with their route because the route is the thing that gets miscounted: a `git ls-remote https://github.com/...` run with the global config still loaded is a measurement of *the mirror*, since `insteadOf` rewrites the URL before git dials. The numbers below were taken with `GIT_CONFIG_GLOBAL` pointed at an absolute path that does not exist, which is the only way to dial `github.com` itself:

| when (+08) | route | result |
| --- | --- | --- |
| 2026-11-15 00:30-00:45 | `github.com:443`, no global config | 1 of 3 `git ls-remote` connected (1.3 s); the other two timed out after 21 s. The archive-branch push loop in the same window needed 19 probe rounds before one connection landed |
| 2026-11-15 15:34-15:40 | `github.com:443`, no global config | 6 of 6 connected, 0.9-1.1 s each, 8 branch refs returned |

So there are two observations of the same route two hours apart, pointing opposite ways: at 15:34 direct was fine six times in a row, at 00:30 it failed twenty times in a row. That is jitter observed - it is not an availability figure, and neither window says what the next hour does. The mirror stays on the fetch path and the push stays direct, because a push that needs 19 retries at the wrong hour is not a route to depend on.

Budget the push retry loop at **20 probe rounds**. The archive-branch push at 00:30 needed 19 before one connection landed; a loop capped lower would have reported a network outage that was not there.

Push must not go through the mirror - an unauthenticated third-party write is refused, and a host that serves the fetch is a host that can serve a different tree. `remote.origin.pushurl` therefore names the direct host with an explicit `:443`:

```
git remote get-url --push origin   # https://github.com:443/romeokeita231/code-review-system.git
```

The port spelling is what keeps the global `insteadOf` from rewriting the push URL: the rule matches the literal prefix `https://github.com/`, which `https://github.com:443/` is not. A `pushInsteadOf` rule does not help here - it is matched against the original URL, which is already `github.com`, so a mirror-to-direct mapping never fires.

**Self-check, run it after any remote surgery** (rebuilding the remote, switching machines, upgrading git):

```
git remote get-url --push origin | Select-String gh-proxy   # must print nothing
```

The ways this breaks silently, in order of likelihood: a rebuilt remote drops the `:443` and the push falls back through the mirror; a git version normalises the URL before matching and the port stops shielding anything; a new `insteadOf`/`pushInsteadOf` rule starts matching the port form. In every case the symptom is the same `Authentication failed ... gh-proxy.com`, which reads like a credential problem and is not one.

`git push origin <branch>` authenticates from the Windows credential store; there is no `gh-proxy.com` entry there, so there was nothing to rotate. A push can still fail with `Connection was reset`: retry, the connection is what is intermittent, not the credentials.

### When the port form cannot authenticate (observed 2026-11-16)

The `:443` spelling keeps the rewrite away but it also changes the credential-store lookup, and on this machine that lookup came back empty:

```
fatal: unable to access 'https://github.com:443/...': schannel: AcquireCredentialsHandle failed: SEC_E_NO_CREDENTIALS
fatal: could not read Username for 'https://github.com:443': No such file or directory
```

`git credential fill` returns an entry for `host=github.com` and none for `host=github.com:443`, which is the whole failure. The port is not a credential problem and not a connectivity problem (`Test-NetConnection github.com -Port 443` was true throughout).

Working recipe, used once and repeatable - it never edits the user's `~/.gitconfig`, it points git at a copy with only the mirror rule removed:

```powershell
$cfg = "$PWD/.tmp/gitconfig-direct"
(Get-Content $HOME/.gitconfig) | Where-Object { $_ -notmatch 'insteadOf|gh-proxy' } | Set-Content $cfg
$env:GIT_CONFIG_GLOBAL = (Resolve-Path $cfg).Path
git push https://github.com/romeokeita231/code-review-system.git feat/v1-spec
```

With the rewrite gone, the plain `github.com` URL is dialled as written, and the credential helper finds the `github.com` entry. Verify the result with `git ls-remote` under the same `GIT_CONFIG_GLOBAL`, not with `git log` on the local branch: a local commit says nothing about the remote.

The `:443` pushurl stays as the default attempt because it is still the only spelling that survives the rewrite; when it fails with the two messages above, switch to the recipe rather than rotating a token that is present and valid.

## The three exempt zones

`datasets/`, `research/` and `artifacts/acceptance/` are exempt from secret scanning (`.github/secret_scanning.yml`) because they hold external bytes verbatim - rewriting them would change `content_sha256` and break every archived run that cites the hash.

Three rules keep the exemption from becoming a hole:

- `npm run check:secrets` (also a preflight gate, so a drill cannot start without it): any provider shape *outside* the zones fails; a shape *inside* them must be registered in `artifacts/acceptance/PROVENANCE.md` with who introduced it, where its bytes came from, and an anchor the gate recomputes, or the gate fails.
- The registry is inside an exempt zone and is the gate's own input, so it must not contain a shape itself. Writing the complete AWS example key in a note made the registry a hit that needed registering; the fix is to write `AKIA...EXAMPLE`. The `sha256:` anchor is the second half of the same defence: it is recomputed against the file, so the table cannot clear itself by being edited.
- `research/` stays external-bytes-only. A note of our own belongs in `docs/` - the exemption is for copies, not for anything we write.
