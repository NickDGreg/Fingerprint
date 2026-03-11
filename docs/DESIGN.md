# Design

The worker is optimized for clarity, determinism, and recovery.

Key design choices:
- Convex is the system of record for jobs, run state, and fingerprints.
- The worker stays stateless outside in-flight execution.
- Fingerprinting is bounded by explicit byte caps, timeouts, and per-stage limits.
- Stages write human-interpretable structured payloads instead of opaque blobs.
- Local file-backed adapters exist so the runtime can be exercised without Convex.

When changing the design, prefer explicit flow and debug visibility over abstraction.
