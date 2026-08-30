<!--
  Copyright 2026 Imran Hafeez
  SPDX-License-Identifier: Apache-2.0
-->

# What is outstanding

**The question this answers:** everything is merged and green — so what is
actually left, who owns it, and what should be done first?

Five sources feed this page: an external security review, three role reviews,
the roadmap, work blocked on repository access, and decisions deliberately
parked. They are listed separately because they have different owners and very
different sizes.

**The numbers here are derived.** 19 free evasions, 9 roadmap items, 8 role
review findings, 3,309 lines in `checks.py` — every one of those is read out of
the file it describes by [`tools/readme_facts.py`](../tools/readme_facts.py) and
checked in CI. Status *within this page* is a checkbox rather than a total,
because a checklist cannot disagree with itself the way "6 of 10 remain" can.
This page is about a backlog, and a backlog page full of hand-typed counts is
the defect this repository has now shipped eleven times.

---

## A. External security review

Conducted against `5cca159`. Four findings were P0; all four are merged.

- [x] **1. A fake hash-chain shape controlled event ordering.** `chained` asked
      whether `prev` and `chain` were *present*, so two arbitrary hex strings
      suppressed a critical CH04 finding. Ordering now requires a signature that
      verified, on both sides. *(#32)*
- [x] **2. Approval timing was producer-controlled.** Same root cause in
      `Session._observed_before`. *(#32)*
- [x] **3. CH07 manufactured a critical finding from an unauthenticated
      receipt.** Receipt trust is now tiered and unauthenticated tops out below
      critical. *(#33)*
- [ ] **4. Approval binding remains incomplete.** Approval does not bind the
      tool definition, and approvals lack issuer authentication, mandatory
      nonces and cross-run consumption. **E25 and E26 are free,
      default-deployment evasions.** Needs: tool-schema digest, server identity
      and version, tenant/resource, call nonce, expiration, and an authoritative
      single-use approval ledger. **Large.**
- [ ] **5. Work the free evasions rather than growing the catalogue.** 19 are
      tier T0 — no attacker capability required — of which 11 work outright and
      the rest are half closed. Remaining, cheapest first: ship memory-tool
      manifest entries, detect hidden delegation turns.
      **Medium, and the best security-per-hour on this page.**

      *E09 is half closed.* The local injection scan is built, and the shape it
      took is worth knowing before starting the next one. This page and
      `EVASION.md` both said "scan locally"; finding F-16 had refused exactly
      that, in a code comment and a passing test, on the grounds that a detector
      generating its own taint evidence grades its own work. **Two documents
      here gave opposite instructions for two revisions and nothing noticed** —
      the drift was in the reasoning, not in a count, and counts are the only
      thing anything recomputes. The resolution was to tier the evidence the way
      CH07's receipts are tiered: `cohaera.content_scan` reports on the
      *scanner*, can only lower a confidence, and can never build a finding. The
      ceiling E09 names is untouched and the entry says so.

      *E24 is half closed.* `CH04_undeclared_control_cited` asks the question no
      check asked — did this control exist? — where the manifest declares its
      controls. The half that remains is the one worth watching: an attacker who
      reads the manifest cites a control that IS declared, and nothing signs a
      policy event. Closing it needs a per-event policy signature schema;
      `cohaera.policy_signature:1` attests a file. **The new check is unscored
      by the evaluation card**, so it ships at `hunt` saying so, which is the
      same treatment CH05 gets and for the same reason.

      *E26 is half closed.* Signature, window and nonce ledger are all built.
      `cohaera.approval:1` gained a `nonce` and a detached issuer signature, the
      trust store gained an `approval` role, and `--seen-approvals` remembers
      spent nonces across runs. **The default is unchanged and that is
      deliberate** — requiring signed approvals in a deployment that has issued
      no keys makes every authorised action look like a bypass, so the operator
      turns it on. The ledger inherits E22 whole: unsigned by necessity, local,
      per-host.
- [ ] **6. Obtain external efficacy evidence that means something.** The one
      external run evaluated no checks. Needs an independently authored,
      properly instrumented corpus with agent, tool-family, task and
      organisation holdouts — and the detector frozen before adaptive testing.
      **Large.**

      **The internal corpus has no content channel, found while building E09's
      scan and worth more than that entry.** Its 216 injection-marked records
      carry no `tool_result` at all, and all 7,156 captured results in it are
      the literal string `ok`. So the corpus cannot exercise anything that reads
      content: it returned zero false positives *and* zero true positives from
      the local scan, and neither number means anything. **CH03's content story
      is untested by the evaluation that gates this repository's claims.**
- [ ] **7. Build the Exabeam proof, not another architecture document.** One
      captured pipeline end to end: off-host collector, signed evidence, Cohaera
      verdict, Exabeam parser, timeline, risk enrichment, case. Measure ingest
      loss, latency and analyst usefulness. **Large.**
- [ ] **8. Require independent review.** No pull request in this repository has
      a recorded GitHub review, and the ruleset requires zero approvals, no
      code-owner review and no last-push approval. **Owner: repository admin —
      see section D.** **Small.**
- [ ] **9. Split the trust kernel before adding to it.** `checks.py` is 3,309
      lines and `evidence.py` is 3,306. The decision not to split was taken when
      they totalled about 4,700, and the ordering defect above crossed those
      module boundaries. Characterization tests first, then separate integrity
      admission, ordering, approvals, receipts, ledger handling and the check
      families. **Large.**
- [x] **10. Factual drift in the manager-facing documents.** `EXABEAM-STACK.md`
      understated the evasion catalogue and claimed no external validation after
      the run had happened; `REVIEW-RESPONSE.md` undercounted the Sigma pack.
      All corrected and derived. *(#34)*

---

## B. Three role reviews

8 findings from [REVIEWS-2026-08.md](REVIEWS-2026-08.md) remain Open or
Recorded. None is a defect; several are positioning decisions that should be
made deliberately rather than as a side effect.

- [ ] **This is closer to a data-quality product than a detection product.** The
      buyer is the detection-engineering or security-data-platform team, not the
      SOC. Deferred deliberately: a repositioning of this size should be a
      decision, not a review side-effect.
- [ ] **`not_evaluated` is a product primitive**, not an implementation detail —
      an API contract a SIEM can surface to an analyst.
- [ ] **Name the release gate as a trust mechanism.** CI fails when published
      numbers drift from measured ones, in a market where every competitor
      claims high accuracy and none shows a denominator.
- [ ] **No operator tuning path exists.** Thresholds and suppressions require
      editing Python, so in practice the pack gets disabled rather than tuned.
      The plumbing already exists — `trust_config_digest` binds configuration
      into verdict identity, so exposing thresholds as config would give both
      tuning and a tamper-evident record of what was tuned.
- [ ] **Omitted ATT&CK tags** mean the pack lands in a SIEM with no technique
      coverage and appears in no coverage dashboard. Correctly reasoned, real
      cost, honestly incurred.
- [ ] **Coverage and correlation confidence per session is an automated
      telemetry gap assessment** — the exercise most programmes do annually in a
      spreadsheet — and is undersold.
- [ ] **Next year's success metric is adoption, not accuracy:** how many
      collectors emit the sidecar, and how many corpora the detector has run
      against that its author did not write.
- [ ] **Escalated risk: the eval gates claims, not correctness.** Rounds of real
      defects have been fixed without the evaluation card moving — including the
      two P0 trust-kernel fixes above. Nothing currently distinguishes "protects
      against publishing something false" from "release QA", and the card itself
      should say so.

---

## C. Roadmap

9 unchecked items in the README's roadmap.

- [ ] AgentDojo corpus under observra instrumentation, 25 attempts per scenario
- [ ] CH02 semantic matching — currently lexical, and its weakest point
- [ ] Praxen Worker Remit compiler, remit sections to runtime predicates
- [ ] Static analysis (CodeQL) — configured and clean, but code scanning needs
      GitHub Code Security on a private personal-account repository. **Free the
      moment this repository is public.**
- [ ] Signed releases with an SBOM attested to the released artefact rather than
      a 90-day CI artefact
- [ ] Cohaera schema 1.0 plus a tested Exabeam exporter and parser package
- [ ] Streaming state with watermarks, replacing batch load
- [ ] Validate content against a live SIEM
- [ ] Build AIE-COHAERA-001 natively and compare against the Cohaera-fed version

---

## D. Blocked on repository access

Both need the repository owner; neither can be done from an automation session.
A8 below is now closed as far as one maintainer can close it, and the entry
states what it still does not buy.

- [ ] **Tag and publish v0.3.0.** Artefacts are built, committed and internally
      consistent — `tools/release_gate.py` passes. The tag push and the release
      API both return 403 through the egress proxy. Run `git tag -a v0.3.0` and
      push from a machine with direct access.
- [x] **Require independent approvals** (item A8). `.github/rulesets/main.json`
      now sets `required_approving_review_count: 1`, `require_code_owner_review`
      and `require_last_push_approval`, pinned by `tests/test_ci_config.py`.
      **Applied live and verified on 2026-08-22**, against ruleset `20557863`.
      Applying it needs admin — the automation token gets 403 — so the
      committed file is the source of truth and a maintainer syncs it by the
      procedure below.

      **This entry previously said "two minutes of repository settings", and
      that was wrong in the direction that bites.** `.github/CODEOWNERS` names
      one owner, GitHub forbids approving your own pull request, and the live
      ruleset had an empty bypass list. Setting the three fields alone would
      not have produced independent review — it would have made `main`
      permanently unmergeable.

      So the repository admin is a **declared bypass actor**. A solo merge is
      recorded as a bypass in the ruleset audit log instead of passing as a
      review that happened. That is a real weakening of A8 and it is written
      down rather than left in the audit log to be discovered: the whole
      argument of this project is that a stated gap and a silent one are
      different objects.

      **A8 is closed as far as one maintainer can close it. What would finish
      it is a second person with write access** — then the bypass goes and
      `test_the_bypass_is_declared_rather_than_silent` can be deleted.

      **Applying it: disable first, verify the bypass, then enable.** The
      approval rules and the bypass are separate fields, and the bypass can
      fail to take while the approval requirement succeeds — which locks
      `main` for everybody. Do not apply and hope:

      ```bash
      # 1. Load the rules with the ruleset switched off. Nothing is gated yet.
      gh api -X PUT /repos/404SecNotFound/Cohaera/rulesets/20557863 \
          --input .github/rulesets/main.json
      gh api -X PUT /repos/404SecNotFound/Cohaera/rulesets/20557863 \
          -f enforcement=disabled

      # 2. Ask GitHub whether YOU can bypass. This is the check that matters:
      #    it is computed from bypass_actors and is authoritative, where
      #    reading back an actor_id only tells you what was stored.
      gh api /repos/404SecNotFound/Cohaera/rulesets/20557863 \
          --jq .current_user_can_bypass
      #    "never"  -> STOP. Enabling now makes main unmergeable.
      #    anything else -> the bypass resolved; go on.

      # 3. Turn it on.
      gh api -X PUT /repos/404SecNotFound/Cohaera/rulesets/20557863 \
          -f enforcement=active
      ```

      `enforcement=disabled` is the unlock if it goes wrong; `evaluate` is
      **not** available — it returns 422 on anything below Enterprise, so it
      is not a rollback on this repository's plan.

      **What the first application settled, and what it did not.** These were
      open questions when the ruleset was written and are recorded here as
      answers rather than left to be re-derived:

      | question | answer |
      |---|---|
      | Is `actor_id: 5` / `RepositoryRole` the repository admin? | **Yes.** `current_user_can_bypass` returned `always` for the owner. It was a guess when committed and is now measured. |
      | Does an invalid field abort the whole PUT? | **Yes.** The `evaluate` attempt returned 422 and changed nothing, so a bad apply fails closed rather than half-applying. |
      | Does a one-field PUT wipe the others? | **No.** `-f enforcement=…` on its own preserved every rule. |
      | Can the bypass be confirmed from an automation session? | **No.** GitHub omits `bypass_actors` for callers without admin, and `current_user_can_bypass` answers for the *calling* token — it reads `never` for the automation token and `always` for the owner. **Only a maintainer can verify this field.** |
      | Does `current_user_can_bypass: always` mean the owner can merge? | **No — and this page said otherwise until a merge was actually attempted.** See below. |

      **THE BYPASS IS PATH-DEPENDENT, AND THE FIELD DOES NOT SAY SO.** With the
      ruleset active, one approval required and zero reviews on the pull
      request, `PUT /repos/{owner}/{repo}/pulls/{n}/merge` returns
      **`405 Pull Request is not mergeable`** for an owner whose
      `current_user_can_bypass` reads `always`. The API reported the same
      request as `"mergeable": true` with `"mergeable_state": "blocked"` — no
      git conflict, held purely by the approval rule.

      So `current_user_can_bypass` states an actor's *eligibility*, not that
      the bypass is honoured on the path being used. The REST merge endpoint
      enforces the rule and offers no override parameter. Merge through the web
      UI ("Merge without waiting for requirements") or `gh pr merge --admin`,
      which take a different path.

      This was found by trying it. The procedure above had been written, run,
      and its verification step passed — and it still did not predict that the
      first gated merge would be refused, because the field it checks answers a
      narrower question than the one that matters. **A control verified through
      the interface that reports on it, rather than through the action it
      governs, is verified in the weakest available sense.** That is this
      project's own argument, and it took two attempts on its own repository
      to notice it applied here.

      That last row is the one to remember. An automation session can read
      `enforcement`, the rules and the required checks, and cannot read the
      bypass at all — so "CI confirmed the ruleset" will never cover the half
      of it that decides whether `main` is mergeable.

      **A live application is not proved by a successful merge.** Merging with
      `--admin` while `enforcement` is `disabled` succeeds for the wrong
      reason: the flag is a no-op and nothing was gated. Read `enforcement`
      and `updated_at` back, and check the timestamp actually moved — a
      re-enable that silently never reached GitHub looks identical to one that
      worked, and this happened once already.

---

## E. Decisions parked

Not defects. Each was raised, considered, and left because the answer is a
judgement call rather than a fix.

- [ ] **CH04's manifest `policies` escape hatch.** A manifest declaring a
      `policies` section keeps CH04 `evaluated` on a quiet session. It is the
      only way to separate "governed, and nothing tripped" from "no policy
      instrumentation at all" — and it is operator-assertable.
- [ ] **The `doc map word count` claim is churny.** It moves on almost every
      documentation edit. Correct, derived, and noisy.
- [ ] **Whether `docs/REVIEWS-2026-08.md` belongs in the repository at all.**
      Role reviews of the project, rather than of the code.
- [ ] **Renaming `inadmissible`.** Accurate, and reads as stronger than it is.
- [ ] **CH05: quarantine or delete.** Zero target precision on `0 of 0` own
      labels. The check may be right and the corpus may simply be missing its
      attack, which is a different and fixable problem.

---

## What to do first

Three things, in this order, and the reasoning is about leverage rather than
severity:

1. ~~**A8, require independent review.**~~ **Done, with a stated limit.** The
   ruleset requires an approval, code-owner review and last-push approval, and
   the admin bypass that keeps a single-maintainer repository mergeable is
   declared in §D rather than implied. It is not two-person review until there
   is a second person.
2. **A5, the free evasions.** 19 attacks that need no attacker capability, most
   with cheap remedies. Best security-per-hour on this page.
3. **A9, split the trust kernel.** Before it grows again. The ordering defect
   crossed exactly the module boundaries this would draw.

**A6 and A7 are the ones that change what this project can claim** — external
efficacy evidence and a real pipeline. They are also the two nobody can finish
in an afternoon, and neither should be started as a side quest.
