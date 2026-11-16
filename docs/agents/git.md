# Git: branches, remotes, and the three exempt zones

## Branches

| branch | role | contents |
| --- | --- | --- |
| `feat/v1-spec` | active, default | the line that gets pushed; everything below is history |
| `research/wayfinder` | archive | research notes only (4 files) |
| `t15-step0-ts-block`, `t15-step1-inventory`, `t15-d1-d2`, `t15-p0-denominator`, `t15-p1-aacr`, `t15-live-acceptance` | archive | one branch per #41 step, so each step's state can be read without replaying the commits |

None of the archives is a default branch, and none takes new commits: they record how a step was reached, not where the line goes next. All eight were pushed on 2026-11-15; the seven archives had never left this machine before that.

## Remote

Two URLs, two jobs, both written literally in this clone's config:

| direction | URL | why this spelling |
| --- | --- | --- |
| fetch | `https://gh-proxy.com/https://github.com/romeokeita231/code-review-system.git` | read-only mirror. The URL is the mirror literal, so it does not depend on the global `url.<mirror>.insteadOf` rule; that rule stays because other repositories on this machine still fetch through it |
| push | `git@github.com:romeokeita231/code-review-system.git` | SSH, key-based. `insteadOf` rewrites `https://` URLs only, so there is no prefix to defeat and no credential-store lookup to satisfy |

`gh` (issues, PRs, API) has its own auth over HTTPS and is unaffected by either URL.

### Why the push is not HTTPS any more

Three HTTPS spellings were tried, and each traded one failure for another:

| push URL | what happens |
| --- | --- |
| `https://github.com/…` | the global `insteadOf` rewrites it to the mirror before git dials, and the mirror refuses the write |
| `https://github.com:443/…` | the port breaks the rewrite prefix, but it also changes the credential-store key. The store has an entry for `github.com` and none for `github.com:443`, so git prompts: `schannel: AcquireCredentialsHandle failed: SEC_E_NO_CREDENTIALS`, then `could not read Username for 'https://github.com:443'` |
| the same, after `git credential approve` for `host=github.com:443` | the entry cannot be created non-interactively here: the helper shells out for a TTY (`bash: line 1: /dev/tty: No such device or address`), so the prompt path fails and `git credential fill` still returns nothing for that key |

Earlier notes listed three other ways the `:443` spelling could break: a rebuilt remote dropping the port, git normalising the URL before matching, or a new rule matching the port form. None of those is what happened. The test for a workaround is not "how could this break" but "can it be checked automatically" - and the old check could not: `git remote get-url --push origin` printed the expected URL while authentication was already dead. A URL is not a route.

### Measurements, each labelled with its route

`git ls-remote https://github.com/…` with the global config still loaded is a measurement of *the mirror*, because `insteadOf` rewrites the URL before git dials. The HTTPS rows below were taken with `GIT_CONFIG_GLOBAL` pointed at an absolute path that does not exist, which is the only way to dial `github.com` itself. The SSH rows use the key at `~/.ssh/id_rsa` with `BatchMode=yes`.

| when (+08) | route | result |
| --- | --- | --- |
| 2026-11-15 00:30-00:45 | `github.com:443`, no global config | 1 of 3 `git ls-remote` connected (1.3 s); the other two timed out after 21 s. The archive-branch push loop in the same window needed 19 probe rounds before one connection landed |
| 2026-11-15 15:34-15:40 | `github.com:443`, no global config | 6 of 6 connected, 0.9-1.1 s each, 8 branch refs returned |
| 2026-11-16 16:52 | `git@github.com` | `ssh -T` under `BatchMode=yes` authenticated (`Hi romeokeita231!`); `git push --dry-run origin HEAD` exit 0 |
| 2026-11-16 17:27 | `git@github.com` | `git ls-remote`: attempt 1 exit 128 after 21.2 s with 0 refs; attempt 2 exit 0 in 3.8 s with 8 refs. `git push --dry-run origin HEAD` exit 0 in 5.6 s |

That is four observation windows across two direct routes, and the HTTPS pair points opposite ways two hours apart: at 15:34 direct was fine six times in a row, at 00:30 it failed twenty times in a row. The SSH pair is the same shape at a smaller scale. This is jitter observed; it is not an availability figure, and neither window says what the next hour does. The mirror stays on the fetch path and the push stays direct, because a push that needs 19 retries at the wrong hour is not a route to depend on.

Budget the push retry loop at **20 probe rounds**. The archive-branch push at 00:30 needed 19 before one connection landed; a loop capped lower would have reported a network outage that was not there.

**Self-check, and it must be end-to-end.** Run it after any remote surgery (rebuilding the remote, switching machines, upgrading git):

```
git push --dry-run origin HEAD
```

Exit 0 with `Everything up-to-date` means the URL resolves, the transport connects and authentication succeeds. Anything else means the route is broken now, whatever the URL says. The previous check (print the push URL, reject `gh-proxy` in it) passed while authentication was already failing, which is why it is gone.

### Running the push from this harness

Both direct transports need facilities the confined sandbox denies:

| transport | error under the sandbox | what it needs |
| --- | --- | --- |
| SSH | `ssh (…): fatal error - couldn't create signal pipe, Win32 error 5` | Git for Windows' MSYS ssh needs a named pipe |
| HTTPS | `failed to execute prompt script (exit code 66)` | the credential helper shells out for a prompt |

So `git push` has to run with full sandbox access here; the error text above is how you tell a sandbox denial from a network failure. `Test-NetConnection github.com -Port 443` was true throughout, which rules out connectivity.

`git push origin <branch>` authenticates from the SSH key, so there is no credential to rotate. A push can still fail with `Connection was reset` or a 21 s timeout: retry, the connection is what is intermittent, not the credentials.

## The three exempt zones

`datasets/`, `research/` and `artifacts/acceptance/` are exempt from secret scanning (`.github/secret_scanning.yml`) because they hold external bytes verbatim - rewriting them would change `content_sha256` and break every archived run that cites the hash. Every path whose bytes are hashed is also pinned `-text` in `.gitattributes` (`datasets/**`, `artifacts/acceptance/**`, `artifacts/*.json`): with `core.autocrlf=true`, a fresh checkout would rewrite them as CRLF and the anchors would stop recomputing.

Three rules keep the exemption from becoming a hole:

- `npm run check:secrets` (also a preflight gate, so a drill cannot start without it): any provider shape *outside* the zones fails; a shape *inside* them must be registered in `artifacts/acceptance/PROVENANCE.md` with who introduced it, where its bytes came from, and an anchor the gate recomputes, or the gate fails.
- The registry is inside an exempt zone and is the gate's own input, so it must not contain a shape itself. Writing the complete AWS example key in a note made the registry a hit that needed registering; the fix is to write `AKIA...EXAMPLE`. The `sha256:` anchor is the second half of the same defence: it is recomputed against the file, so the table cannot clear itself by being edited.
- `research/` stays external-bytes-only. A note of our own belongs in `docs/` - the exemption is for copies, not for anything we write.
