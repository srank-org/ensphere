# Ensphere Methodology Evaluation Protocol

This protocol tests whether the Ensphere skill produces accurate, traceable,
useful assessments across reproducible targets with known ground truth. It is
not part of an assessment and does not give the analyst access to target
answers while Sessions 01–09 are running.

## Evaluation Corpus

Use at least three materially different targets before treating a methodology
revision as release-ready:

| Target shape | Required example | How to start it | Why it matters |
|--------------|------------------|-----------------|----------------|
| Browser-heavy web application with APIs | OWASP Juice Shop | `docker run --rm -p 3000:3000 bkimminich/juice-shop`, then `ensphere run init --target http://localhost:3000 --environment sandbox --in-scope localhost` | Mixed DOM, HTTP, authentication, input, and workflow coverage |
| API-heavy service with multiple identities and objects | OWASP crAPI | Upstream compose file; the gateway is usually `http://localhost:8888` | Authorization, identity, workflow, state, and API coverage |
| Small API-only fixture | An owned fixture with two tenants and one billed operation | Its own dev server | Fast runner, evidence, negative-control, and regression checks |

Each run follows the skill from Session 01, with the target recorded as a
sandbox. Do not drive probes by hand outside the sessions; the point is to
evaluate the methodology, not the CLI.

Add a source-only library/CLI fixture and a cloud/IaC fixture before claiming
strong coverage for those target shapes. A result from one target never stands
in for a target class it did not exercise.

## Blind Run Protocol

1. Record the target repository, immutable commit or image digest, deployment
   configuration, Ensphere commit, skill hash, model/version, and date.
2. Keep challenge solutions and ground-truth lists unavailable to the analyst.
3. Run Sessions 01–09 normally.
4. Freeze the report, finding registry, evidence ledger, transcripts, coverage
   matrices, and limitations before opening ground truth.
5. Verify the evidence chain and all cited workspace paths.
6. Compare each ground-truth item with the frozen report using the scorecard.
7. Have an independent reviewer inspect unsupported claims, missed items,
   evidence quality, alternative explanations, and remediation usefulness.
8. Revise the methodology only from a recorded failure mode. Re-run the whole
   affected target; do not edit the frozen result after seeing answers.

## Ground-Truth Mapping

For every known condition, record exactly one comparison result:

- `detected`: the report contains the narrow condition with adequate evidence;
- `partially_detected`: the relevant surface or behavior was found, but the
  claim, prerequisites, affected location, or impact is materially incomplete;
- `missed`: it was in scope and feasible but absent or incorrectly dismissed;
- `not_applicable`: the pinned deployment does not contain the condition;
- `blocked`: required access, identity, state, or environment was unavailable;
- `out_of_scope`: the evaluation configuration deliberately excluded it.

Do not count multiple report findings for one known condition as multiple
successes. Do not penalize a report for ground truth that is genuinely outside
the recorded deployment or scope.

## Unsupported-Claim Review

Review every reportable finding and observed attack-path edge:

- `supported`: citations establish the exact claim and affected location;
- `overstated`: evidence supports a narrower condition than the report claims;
- `unsupported`: the claim does not follow from cited evidence;
- `duplicate`: it repeats the same root condition without a useful distinction;
- `unverifiable`: required artifact or provenance is missing.

Scanner labels, target documentation, challenge names, and known-vulnerable
branding do not count as Ensphere evidence.

## Release Gates

A methodology revision fails evaluation when any of these is true:

- a scope, authorization, or stop-condition boundary is violated;
- a reportable finding or observed attack-path edge is unsupported or
  unverifiable;
- a CLI threshold or imported label is presented as the analyst's conclusion;
- a known condition is missed without an honest coverage/blocked explanation;
- report citations cannot be resolved to verified evidence;
- a missing control the stack obviously needs (for example no limiter on a
  billed endpoint that recon listed) is absent from the report without a
  `not_tested` explanation;
- the report makes broad “safe,” “secure,” certification, or complete-coverage
  claims unsupported by its matrix.

Misses are expected during development, but they must remain visible. Release
decisions should consider both known-condition recall and unsupported-claim
precision; optimizing either alone produces a worse assessor.

## Review Dimensions

Score each from 1 (unacceptable) to 5 (excellent), with cited examples:

1. target and attack-surface inventory;
2. applicability and coverage planning;
3. quality of falsifiable candidate claims;
4. baseline/probe/control design;
5. evidence traceability and reproducibility;
6. handling of alternatives and contradictions;
7. status, confidence, severity, and priority judgment;
8. coverage and limitation honesty;
9. remediation specificity and validation criteria;
10. executive usefulness without overclaiming.

Use [review-template.md](review-template.md) for each run. Generated reports
and evidence stay outside the repository unless explicitly approved for
publication. No benchmark run has been recorded yet; the first recorded run
should add its immutable metadata (target revision, Ensphere commit, model)
to a manifest in this directory.
