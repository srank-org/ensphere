# Session 05: Cross-Site Scripting

## Objective

Resolve whether controlled input reaches a script-capable rendering context
without the required context-specific encoding or sanitization.

## Preflight and Coverage

Build a matrix of input/source × storage path × renderer × output context ×
browser/runtime × identity/role. Include reflected, stored, and DOM flows plus
HTML/attribute/URL/JavaScript/CSS/markdown/email/PDF contexts only where they
exist.

Record the intended encoder/sanitizer, CSP and Trusted Types facts, template
auto-escaping, client framework behavior, and who can create and view the
content. Use synthetic markers and owned test content.

## Candidate Generation

Source review traces input to the exact render context and all transformations.
A sink-pattern match is a lead until reachability and attacker control are
established.

Live-target discovery starts with unique inert markers to locate reflection or
storage and determine the context. Reflection alone is not XSS.

## Controlled Validation

1. Capture a normal render baseline.
2. Submit a unique inert marker and inspect the exact DOM/source context.
3. Apply one context-appropriate benign witness that proves script execution
   without reading data, credentials, or DOM content and without performing a
   user action.
4. Use an encoded/sanitized variant or non-executable context as a control.
5. For stored flows, verify only through authorized viewer accounts and remove
   the test content afterward.

Do not perform open-ended filter/WAF/CSP bypasses. Additional encodings or
syntax variants must test a named normalization, parser-transition, or context
hypothesis. Do not steal cookies/tokens, read sensitive page content, trigger
business actions, persist beyond the controlled fixture, or contact an
unapproved external service.

CSP absence is not XSS; CSP presence is a defense fact and may affect impact,
but it does not cure an unsafe render flow. Record the actual policy and tested
browser behavior.

## Interpretation and Stop Rules

Classify the narrow render flow using the shared evidence model. Distinguish raw
HTTP reflection, inert DOM text, sanitizer mutation, browser execution, and
extension/devtool artifacts. Stop once the context is shown safe for the tested
input or benign execution is observed. Do not escalate to cookie theft,
session use, or any real-user impact for proof.

## Report

Write `05-xss/report.md` with the render-context rows from `coverage.yaml`, source/data
flows, safe witness and cleanup, browser and policy context, resolved findings,
tested defenses, unresolved contexts, remediation and validation criteria, and
evidence citations.
