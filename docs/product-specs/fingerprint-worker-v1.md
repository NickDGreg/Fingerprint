# Fingerprint Worker V1

## Goal

Given a claimed website job, the worker must produce structured fingerprints that let operators understand what was fetched, what matched, what failed, and why.

## Inputs

Job payloads must provide:
- `networkArtifactId`
- `websiteHost`
- `websiteUrl`
- optional `runId`

## Outputs

For each processed job, the worker writes:
- HTTP fingerprint payload
- HTML fingerprint payload
- asset fingerprint payload
- analytics fingerprint payload
- favicon fingerprint payload
- TLS fingerprint payload
- final run result
- zero or more run issue records

## Acceptance

The worker is acceptable when:
- file-backed fixture jobs can run end to end with deterministic outputs
- stage failures still produce a final run result
- unreachable sites are reported explicitly
- TLS can be disabled for local deterministic tests
- the Convex/file adapter choice is controlled by environment variables without code changes
