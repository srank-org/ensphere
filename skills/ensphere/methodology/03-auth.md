# Session 03: Authentication

## Objective

Assess identity establishment and session lifecycle controls using supplied
accounts and bounded, reversible checks.

## Candidate Generation

Candidates cover the applicable login, logout, registration, verification,
password reset/change, MFA enrollment/challenge/recovery, OAuth/OIDC/SSO, API
key, session cookie, refresh/access token, device/session management, and
account recovery flows. For each flow record endpoint, identity/role, tenant,
credential type, state transition, expected control, and the test account it
needs.

Open the checklists the plan assigned to this session first; they name the
auth provider's specific settings (for example `supabase-rls.md` covers
Supabase Auth configuration, `nextjs-app-router.md` covers middleware
matchers and Server Actions). Rate limiting on login, signup, reset, and OTP
is measured in Session 08.5; record the endpoints here and hand them over.

Use owned test accounts only. If a role, MFA device, IdP tenant, mail channel,
or recovery factor is unavailable, the specific flow's row is `blocked` with
that prerequisite.

Source review traces credential verification, token validation, session
issuance/rotation/revocation, reset-token generation/storage/use, OAuth
state/nonce/PKCE handling, MFA enforcement, and error handling. Cite
reachable source and configuration.

Live-target candidates come from observed flow behavior, not assumptions about
framework defaults.

Do not estimate token entropy from a small sample, infer password strength from
UI text alone, or treat cookie flags as proof of session compromise.

## Controlled Validation

Use the shared baseline/probe/control cycle with owned accounts. `ensphere
verify auth` and `ensphere verify jwt` cover the token shapes they name;
send any other flow step with `ensphere verify request` and label its role
with `--result`.

- compare valid, invalid, expired, revoked, replayed, and context-mismatched
  tokens only where each case is safely constructible;
- verify session identifier rotation across login, privilege change, password
  change, and logout using the same test account;
- test reset and verification tokens for single use, intended account binding,
  expiry, and invalidation without taking over another account;
- compare authentication error behavior using a small authorized set of known
  test identities and matched controls;
- exercise OAuth/OIDC state, nonce, redirect URI, issuer, audience, and PKCE
  controls only in a configured test integration;
- validate MFA enforcement and recovery transitions with supplied factors.

Do not use generic default-credential lists, online password guessing,
credential stuffing, lockout triggering, CAPTCHA/rate-limit evasion, token
forgery against real users, or acquisition of another user's session.

For timing claims, use randomized/interleaved repeated observations and report
the distribution and noise. There is no universal millisecond threshold.

Positive controls are required where a negative result could mean the test was
misconfigured: demonstrate that the valid test token/account works before
interpreting a rejected variant.

## Interpretation and Stop Rules

Separate authentication failure, authorization failure, upstream rejection,
invalid test state, and environmental instability. Stop when the specific
control is demonstrated or contradicted, the account/request limit is reached,
or further work would require guessing, unrelated identities, or greater
impact.

The session report records token and session lifecycle facts alongside the
findings. Never include live tokens, passwords, reset links, or personal data
in it.
