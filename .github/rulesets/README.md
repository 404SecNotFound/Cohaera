# Branch rulesets

`main.json` is the branch protection for `main`, kept here so the configuration
is reviewable in a diff rather than living only in the web UI.

**GitHub does not read this file.** Nothing applies it automatically. It is a
payload you apply deliberately, and the repository is unprotected until somebody
does. That is worth stating plainly, because a protection config sitting in a
repo looks like protection and is not — the same failure mode as a Sigma rule
that validates but can never match.

## Applying it

Needs **admin** on the repository. A GitHub App token scoped to contents and
pull requests is not enough; the Cohaera automation token has `admin: false` and
gets `403 Resource not accessible by integration`.

```bash
gh api -X POST repos/404SecNotFound/Cohaera/rulesets \
  --input .github/rulesets/main.json
```

Updating an existing ruleset needs its numeric id:

```bash
gh api repos/404SecNotFound/Cohaera/rulesets --jq '.[] | "\(.id)\t\(.name)"'
gh api -X PUT repos/404SecNotFound/Cohaera/rulesets/<id> \
  --input .github/rulesets/main.json
```

Equivalent UI path: **Settings → Rules → Rulesets → New branch ruleset**.

## What it enforces

| Rule | Effect |
|---|---|
| `deletion` | `main` cannot be deleted |
| `non_fast_forward` | no force pushes |
| `pull_request` | changes arrive through a PR; **squash is the only merge method**; stale reviews dismissed on push; review threads must be resolved |
| `required_status_checks` | all nine CI checks must pass, and the branch must be up to date with `main` first |

## Why squash is the only merge method

`allowed_merge_methods` is `["squash"]`, and that is a signing control rather than
a style preference.

GitHub signs commits it creates server-side with its own key. A squash merge is
one such commit, so it lands **Verified** whether or not the contributor could
sign anything locally. A merge commit is also GitHub-signed — but it *preserves
the branch commits underneath it*, exactly as they were.

This repository learned the difference the hard way. PR #3 was merged with a
merge commit, and four locally-created unsigned commits survived beneath a
Verified merge commit. `main` went from one unverified commit to five, and
clearing them cost a history rewrite, a force push, and taking this ruleset down
and putting it back up.

With squash the branch commits are discarded at merge and only the GitHub-signed
commit reaches `main`. Contributors who cannot sign locally can still land work
that verifies.

It also keeps `main` linear, which matters here for a second reason: the
evaluation card in `eval/` is byte-reproducible per revision, and a linear
history means `git log -p eval/EVALUATION-CARD.md` reads as a straight record of
how the detector's measured behaviour changed.

## Two judgement calls, stated so they can be overridden

**`required_approving_review_count: 0`.** This is a single-maintainer repository.
Setting it to 1 would mean the owner can never merge their own pull request
without a second account — protection that blocks only the person it is meant to
serve. Zero still forces every change through a PR with green CI, which is the
gate that actually catches things. **Raise this to 1 the moment there is a second
contributor**; at that point it starts doing work instead of just being friction.

**No `bypass_actors`.** Nobody is exempt, including the owner. The argument the
other way is real: a broken runner or a GitHub incident will block all merges
with no escape hatch. If that becomes a problem, add the repository admin as a
bypass actor rather than weakening the checks — an escape hatch somebody has to
consciously use is better than a gate that is quietly not gating.

`strict_required_status_checks_policy: true` requires a branch to be up to date
with `main` before merging. Without it a PR can pass CI against a stale base and
merge something that was never tested against what it actually lands on.

## Keeping the check names honest

The nine `context` values must match the job names GitHub reports, which come
from `name:` in **every** file under `.github/workflows/` with the matrix
expanded. Today that is `ci.yml` alone; the loop reads the whole directory
rather than one file, so a second workflow's gate cannot go unrequired.

There were ten. `codeql (python)` was removed together with
`.github/workflows/codeql.yml`, and the pairing matters more than the removal:
CodeQL's analysis ran clean but could never UPLOAD its results, because this is
a private repository on a personal account and code scanning there requires
GitHub Code Security. Keeping it as a required check would have blocked every
pull request forever — a required check that can never report success is the
failure this section is about, arriving from the other direction. Keeping it as
a non-required check would have left a permanently red tick, which is how people
learn to ignore red. `tests/test_ci_config.py` now asserts the two halves are
absent together or present together, and carries the restore procedure.

A required check that no job ever reports does not error. It blocks merges
forever, and the reason is invisible unless you already know to look here. So
rename a CI job and this file goes stale silently, in the direction that hurts.

`tests/test_ci_config.py` asserts the two agree and runs in the normal suite.
It is the same idea as `tests/test_content.py`, which asserts every field the
Sigma pack names exists in a real verdict record: committed configuration that
refers to something by name should be checked against the thing it names.

That file now also asserts the supply-chain properties the workflows claim:
every `uses:` is pinned to a 40-character commit SHA, every pin carries a
readable version comment, `.github/dependabot.yml` covers `github-actions` so
the pins can move, any restored `codeql.yml` triggers on `pull_request` (a
required check that does not report on a PR blocks it forever) and is required
by the ruleset in the same commit, and every workflow declares least-privilege
top-level `permissions`.

## Repository settings that cannot be committed

The same gap as the ruleset itself, one level worse: these have no file to hold
them, so nothing in a diff can show whether they are on. Check them, and re-check
them after any repository transfer or fork.

| Setting | Where | Why |
|---|---|---|
| **Secret scanning** | Settings → Code security | The `sbom` and `build` jobs upload artefacts; a credential committed by accident is otherwise found by whoever downloads one |
| **Push protection** | Settings → Code security | Blocks the commit rather than reporting it afterwards. The one that actually prevents the incident |
| **Private vulnerability reporting** | Settings → Code security | `SECURITY.md` tells reporters to use it. If it is off, that instruction is a dead end |
| **Dependabot alerts and security updates** | Settings → Code security | `.github/dependabot.yml` schedules version updates; alerts are the separate switch for known-vulnerable versions |
| **Actions: allow only actions pinned by this repository** | Settings → Actions → General | Defence in depth behind the SHA pins |
| **Workflow permissions: read-only by default** | Settings → Actions → General | Every workflow here declares `contents: read`, but the default governs anything added later that forgets to |

The automation token used by this project's agent has `admin: false`, so it
cannot read or change any of these. They are the owner's to set, and this table
exists so the list is at least written down where the rest of the configuration
lives.

```bash
# What can be checked without admin: nothing here. With admin:
gh api repos/404SecNotFound/Cohaera --jq \
  '{secret_scanning: .security_and_analysis.secret_scanning.status,
    push_protection: .security_and_analysis.secret_scanning_push_protection.status,
    dependabot: .security_and_analysis.dependabot_security_updates.status}'
```
