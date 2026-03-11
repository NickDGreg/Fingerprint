# Convex Contract Notes

This repository does not own a local relational database schema.

The storage contract is instead:
- Convex job claims for due work
- Convex mutations for per-stage fingerprint payloads
- Convex mutations for run issue records
- Convex mutation for final run result

Raw HTML, favicon bytes, and local assets are intentionally not stored in Convex today. Stage payloads carry `storageTodo` markers instead.
