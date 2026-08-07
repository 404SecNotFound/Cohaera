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
from `name:` in `.github/workflows/ci.yml` with the matrix expanded.

A required check that no job ever reports does not error. It blocks merges
forever, and the reason is invisible unless you already know to look here. So
rename a CI job and this file goes stale silently, in the direction that hurts.

`tests/test_ci_config.py` asserts the two agree and runs in the normal suite.
It is the same idea as `tests/test_content.py`, which asserts every field the
Sigma pack names exists in a real verdict record: committed configuration that
refers to something by name should be checked against the thing it names.
