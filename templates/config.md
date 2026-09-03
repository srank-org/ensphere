# Assessment Configuration

## Target
- URL: https://staging.example.invalid
- (Leave URL empty for a source-only assessment. A disposable local instance is the preferred live target.)
- Source path: ./
- Target type: auto | web_app | api_backend | static_site | mobile_client_remote_backend | mobile_client_offline | desktop_or_extension_client | cloud_only | library_or_cli
- Cloud / platform: none | aws | gcp | azure | kubernetes | cloudflare | supabase | (comma-separated if multiple)
- Environment: sandbox | staging | none (sandbox is a local disposable instance with synthetic data; production is never a live target)

## Authentication
- Login URL: /login
- Username: testuser
- Password: testpass123
- (Add additional accounts and a second tenant for authorization and rate-limit key testing)

## Scope
- In scope: staging.example.invalid
- Out of scope: third-party services, production systems
- Rules to avoid: no load testing, no data destruction
- Approved rate-limit bursts: (endpoint → burst count / window, agreed with the operator before Session 08.5)
- Approved upload sizes: (bytes, for Session 08.5 upload-size measurement against a staging bucket)
- Areas to focus: (e.g. payment flow, upload pipeline, edge functions)

## Assessment
- Assessed by: (model or person performing the assessment, e.g. Claude Fable 5.1 via Claude Code)
- Operator: (person who authorizes the assessment and signs the statement)

## Authorization
This assessment is authorized against the environment named above by its owner.
It does not authorize exploitation, data extraction, or testing of any other system.
