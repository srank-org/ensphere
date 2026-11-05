# AWS S3 Checklist

Load this checklist when recon records `aws_s3_bucket` resources in Terraform or CloudFormation, the `@aws-sdk/client-s3` or `boto3` S3 client, or an `aws` CLI profile in scope. Unlike R2, S3 bills egress per GB, so a public or hotlinked bucket is a direct cost exposure as well as a data exposure. Shared abuse patterns are in `abuse-and-cost.md`.

## Prerequisites

`ensphere cloud storage` shells out to the `aws` CLI. If `aws sts get-caller-identity` fails, tell the operator to configure a read-only profile (`aws configure` or SSO login) for the staging account and record live items as `blocked` until then. Terraform review proceeds without credentials: `ensphere scan ./infra --category iac_terraform --absence-check`.

All live measurements below use `ensphere cloud storage --provider aws --bucket <bucket> --in-scope "aws://<account_id>"`, which records public-access block, ACL, policy, encryption, versioning, and logging as raw provider output. Interpret the output; the command does not.

## Public access

- [ ] **Block Public Access disabled** — without the account and bucket level block, a single ACL or policy change can expose the bucket.
  - Look for: `aws_s3_bucket_public_access_block` per bucket with all four flags true; account-level block.
  - Measure: `ensphere cloud storage` output field for public access block.
  - Fix: enable all four settings at the account level and per bucket.

- [ ] **Wildcard principal in bucket policy** — `"Principal": "*"` without a restricting condition is public regardless of ACLs.
  - Look for: `aws_s3_bucket_policy` documents; `Principal` `*` or `{"AWS":"*"}`; conditions such as `aws:PrincipalOrgID`, `aws:SourceVpce`.
  - Measure: `ensphere cloud storage` policy output.
  - Fix: explicit principals; CloudFront origin access control for public content.

- [ ] **Legacy ACL grants** — `AllUsers` or `AuthenticatedUsers` grantees on the bucket or objects.
  - Look for: `acl = "public-read"`; object ACLs set at upload time; Object Ownership not set to bucket owner enforced.
  - Measure: `ensphere cloud storage` ACL output.
  - Fix: `BucketOwnerEnforced` ownership, which disables ACLs entirely.

- [ ] **Cross-account grants without conditions** — external account ARNs allowed `GetObject` or `PutObject`.
  - Look for: foreign account IDs in policy principals; missing `aws:PrincipalOrgID` condition.
  - Measure: `ensphere cloud storage` policy output.
  - Fix: condition keys on every cross-account statement.

## Uploads and presigned URLs

- [ ] **Presigned POST or PUT without constraints** — no `content-length-range`, fixed key, or content type lets a leaked URL upload anything.
  - Look for: `createPresignedPost` conditions; `getSignedUrl` with `ContentType` and `ContentLength`; expiry values.
  - Measure: `ensphere verify fileupload --url <presigned-url> --method PUT --filename test.html --mime-type text/html --technique content_type_mismatch --in-scope <bucket-host>` using an operator-generated fixture URL.
  - Fix: `content-length-range` in POST policies, signed type and length for PUT, minutes-long expiry.

- [ ] **No per-user upload quota or limiter on the presign endpoint** — one account can fill the bucket.
  - Look for: quota checks before presigning; a limiter on the endpoint; lifecycle rule aborting incomplete multipart uploads.
  - Measure: `manual: read the presign handler and record whether it enforces a quota`; with approval `ensphere verify ratelimit --url <origin>/api/upload-url --method POST --token <user-token> --burst-count <approved> --window-sec 10 --in-scope <host>`.
  - Fix: quota table, endpoint limiter, `AbortIncompleteMultipartUpload` rule.

## Cost exposure

- [ ] **Public objects served directly from S3 without CloudFront** — every download bills egress from S3 at the highest rate and cannot be cached or rate limited.
  - Look for: application URLs pointing at `s3.amazonaws.com` or a bucket website endpoint.
  - Measure: `manual: record which public asset URLs resolve to S3 directly`.
  - Fix: CloudFront distribution with OAC, WAF rate rules, and signed URLs or cookies for private content.

- [ ] **Requester Pays and lifecycle not considered** — large shared datasets without Requester Pays, and buckets without lifecycle rules, grow cost without bound.
  - Look for: `request_payer` setting; `aws_s3_bucket_lifecycle_configuration`.
  - Measure: `manual: aws s3api get-bucket-lifecycle-configuration --bucket <bucket>` and `aws s3api get-bucket-request-payment --bucket <bucket>`.
  - Fix: lifecycle transitions and expirations; Requester Pays for public datasets.

## Data protection

- [ ] **Default encryption missing** — objects at rest unencrypted, or SSE-KMS without a key policy.
  - Look for: `aws_s3_bucket_server_side_encryption_configuration`.
  - Measure: `ensphere cloud storage` encryption output.
  - Fix: SSE-S3 at minimum; SSE-KMS with a scoped key for sensitive data.

- [ ] **Versioning, Object Lock, and MFA Delete** — deletion or overwrite is unrecoverable for buckets that hold records.
  - Look for: `versioning`, `object_lock_configuration`, MFA delete status.
  - Measure: `ensphere cloud storage` versioning output; `manual: aws s3api get-object-lock-configuration --bucket <bucket>`.
  - Fix: versioning on data buckets; Object Lock for compliance retention.

- [ ] **Access logging or CloudTrail data events disabled** — abuse and exfiltration cannot be investigated.
  - Look for: `aws_s3_bucket_logging`; CloudTrail data event selectors for the bucket.
  - Measure: `ensphere cloud storage` logging output; `ensphere cloud logging --provider aws --in-scope "aws://<account_id>"`.
  - Fix: server access logging to a separate bucket; data events in CloudTrail for sensitive buckets.

- [ ] **CORS allows any origin** — browser reads and writes from other sites.
  - Look for: `aws_s3_bucket_cors_configuration` with `*` origins.
  - Measure: `ensphere verify cors --url https://<bucket-host>/<fixture-key> --in-scope <bucket-host>`.
  - Fix: exact origins and methods.
