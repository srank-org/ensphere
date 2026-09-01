# Cloudflare R2 Checklist

Load this checklist when recon records `wrangler.toml` or `wrangler.jsonc` with an `r2_buckets` binding, the `@aws-sdk/client-s3` or `aws4fetch` client pointed at `<account>.r2.cloudflarestorage.com`, or an `r2.dev` or custom R2 domain in configuration. R2 has no egress fee but charges per Class A (write, list) and Class B (read) operation and per GB stored, so abuse shows up as bill growth, not bandwidth. Worker code that fronts the bucket is covered in `cloudflare-workers.md`; shared abuse patterns are in `abuse-and-cost.md`.

## Prerequisites

Facts come from read-only Wrangler commands and source. If `wrangler` is missing or `wrangler whoami` fails, tell the operator to run `npm i -g wrangler` and `wrangler login`, and record live items as `blocked` until then. Never run `wrangler r2 object put|delete` against a bucket you were not given as a fixture.

Read-only inventory commands: `wrangler r2 bucket list`, `wrangler r2 bucket info <bucket>`, `wrangler r2 bucket cors list <bucket>`, `wrangler r2 bucket lifecycle list <bucket>`, `wrangler r2 bucket domain list <bucket>`.

## Public access

- [ ] **Bucket exposed on r2.dev or a custom domain unintentionally** — public access makes every object readable by anyone who knows or guesses a key.
  - Look for: `wrangler r2 bucket domain list` output; dashboard "Public access" state; whether object keys are predictable (sequential IDs, user emails).
  - Measure: `ensphere verify auth --technique no_token --url https://<public-host>/<known-fixture-key> --token <app-session-token> --in-scope <public-host>`.
  - Fix: disable public access; serve through a Worker that checks authorization, or use signed URLs.

- [ ] **Public domain without cache or WAF rules** — a public custom domain with no Cache Rule lets every request count as a Class B operation, and hotlinking from other sites bills you.
  - Look for: Cache Rules and WAF custom rules on the zone; `Cache-Control` metadata on objects; hotlink protection.
  - Measure: `manual: GET a public object twice and record cf-cache-status on each response`.
  - Fix: Cache Rule with edge TTL for the domain; hotlink protection or a Referer or signed-token check in a Worker.

- [ ] **Listing exposed to clients** — `list()` through a Worker or the S3 API with an empty prefix enumerates the whole bucket and costs Class A operations per call.
  - Look for: `env.BUCKET.list(` in Worker source; `ListObjectsV2` from client-facing code; prefix derived from user input.
  - Measure: `manual: call the listing endpoint with an empty or other-tenant prefix using a test user and record the keys returned`.
  - Fix: constrain prefix to the caller's namespace server-side; paginate with a hard cap.

## Presigned URLs

- [ ] **Presigned PUT without size, type, or key constraints** — a presigned URL that allows any key, any size, or any content type is an open upload slot for its lifetime.
  - Look for: presign code (`getSignedUrl`, `aws4fetch` sign) and whether it sets a fixed key, `ContentLength`, and `ContentType`; note that R2 does not support POST policies with `content-length-range`, so size must be enforced by a fixed `Content-Length` in the signature or by a Worker.
  - Measure: `ensphere verify fileupload --url <presigned-put-url> --method PUT --filename test.html --mime-type text/html --technique content_type_mismatch --in-scope <r2-host>` using a URL the operator generated for a fixture key.
  - Fix: server-generated keys, signed `Content-Type` and `Content-Length`, short expiry.

- [ ] **Presigned URL lifetime too long** — leaked links keep working until expiry.
  - Look for: `expiresIn` values in presign calls; defaults in wrapper libraries.
  - Measure: `manual: record every expiresIn value in source with file and line`.
  - Fix: minutes for uploads, short and per-request for downloads.

- [ ] **Unbounded uploads per user** — nothing stops one account from requesting presigned URLs in a loop and filling the bucket.
  - Look for: per-user quota checks before presigning; a limiter on the presign endpoint; lifecycle rules for abandoned multipart uploads.
  - Measure: `manual: read the presign handler and record whether it counts existing objects or bytes per user`; with approval `ensphere verify ratelimit --url <origin>/api/upload-url --method POST --token <user-token> --burst-count <approved> --window-sec 10 --in-scope <host>`.
  - Fix: quota table checked in the presign handler; rate limit on the endpoint; lifecycle rule `AbortIncompleteMultipartUpload`.

## Bucket configuration

- [ ] **CORS allows any origin with credentials** — browser reads from other sites.
  - Look for: `wrangler r2 bucket cors list <bucket>` output with `*` origins and `PUT`/`DELETE` methods.
  - Measure: `ensphere verify cors --url https://<bucket-host>/<fixture-key> --in-scope <bucket-host>`.
  - Fix: exact origins; only the methods the app uses.

- [ ] **No lifecycle rules** — abandoned multipart uploads and stale objects accumulate storage cost.
  - Look for: `wrangler r2 bucket lifecycle list <bucket>` output.
  - Measure: `manual: record rules present`.
  - Fix: expire incomplete multipart uploads after one day; expiration or transition rules for temporary objects.

- [ ] **API token scope too broad** — an R2 token with admin read/write across all buckets used from one service.
  - Look for: token permissions in the dashboard; which environments share the token; token in client bundles or mobile apps.
  - Measure: `manual: list tokens and their bucket scope and permission level`.
  - Fix: per-bucket, object-read-only or object-write-only tokens; rotate any token found in a client.

## Encryption and metadata

- [ ] **Customer-provided keys reused across tenants** — SSE-C keys stored in one place or shared defeat tenant separation.
  - Look for: `x-amz-server-side-encryption-customer-key` handling; key derivation per tenant.
  - Measure: `manual: review key storage and derivation with file and line references`.
  - Fix: per-tenant keys from a KMS; never log the key.
