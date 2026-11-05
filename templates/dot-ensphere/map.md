# System map: <system name>

<!-- Written and reconciled by Ensphere Session 01. For the next reader,
     human or model. Keep it current; the surfaces file beside it is the
     machine-read inventory and ensphere map validate checks it. -->

## What it is for

<Two or three sentences in plain words: who uses it, what they do, where the
money and the data are.>

## Roles

| Role | Filled by | Where |
|------|-----------|-------|
| Entry point | <framework router> | <path> |
| Identity | <auth provider> | <path> |
| Authorization decision | <row policies, handler checks> | <path> |
| Data store | <database> | <path> |
| Object storage | <bucket> | <path> |
| Expensive or billed operation | <mail, SMS, AI, payments> | <path> |
| Limiter | <middleware and its store> | <path> |
| Platform configuration | <hosting, edge> | <path> |

## Trust boundaries

<Which components trust which. Where tenant isolation is enforced. What is
public by design.>

## Driving the sandbox

- Start: <command>
- Seed: <command>
- Reset: <command>
- Identities: `[TENANT_A_USER]` is <how to obtain>; `[TENANT_B_USER]` is <how to obtain>; `[ADMIN]` is <how to obtain>
- Reaching a surface: <login path, headers, fixtures that must exist first>

## Gotchas

- <The thing that cost an hour last run, with the fix.>
