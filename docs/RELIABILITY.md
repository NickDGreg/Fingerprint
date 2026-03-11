# Reliability

Reliability requirements for this service:

- At-least-once processing is expected.
- Fingerprinting writes must remain idempotent.
- Timeouts and partial failures are normal.
- Per-stage failure must not erase successful earlier stage writes.
- The worker must be restart-safe.
- Local smoke and unit tests must continue to prove the worker can process deterministic jobs end to end.

Operational rules:
- keep bounded polling and batch sizes
- keep detailed run issue records
- keep final run outcomes explicit even when intermediate stages fail
