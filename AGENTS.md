# Fingerprinting Worker – Agent Instructions

This repository contains a Python fingerprinting worker for scam domains.  
The agent developing this system must follow the principles below.

---

## Core Goal

Build a **reliable, observable, idempotent fingerprinting worker** that:

- Pulls domains/jobs from Convex
- Fingerprints scam websites safely and deterministically
- Writes structured results back to Convex
- Can run locally and on a single VM with no code changes
- Uses the Convex Python SDK for backend calls

This system prioritises **correctness, debuggability, and incremental evolution** over sophistication.

---

## Non-Goals (for now)

- High-throughput distributed systems
- Multi-region workers
- Perfect real-time guarantees
- Complex external queues or orchestration frameworks
- Premature optimisation

If a design choice adds infrastructure or complexity without clear necessity, reject it.

---

## Architectural Invariants

These must always hold:

1. **Convex is the source of truth**
   - Job state, fingerprints, and run history live in Convex.
   - The worker is stateless beyond in-flight execution.

2. **At-least-once processing**
   - Jobs may be retried.
   - Fingerprinting and writes must be idempotent.

3. **Explicit state transitions**
   - Jobs move through clear states (e.g. queued → running → done/failed).
   - No implicit or “hidden” transitions.

4. **Failure is expected**
   - Timeouts, network errors, malformed sites, dead domains are normal.
   - The system must degrade gracefully and retry intelligently.

5. **One worker is enough**
   - The system must work correctly with a single worker.
   - Concurrency is bounded and explicit.

---

## Execution Model

- The worker **pulls** work from Convex (never pushed).
- Jobs are claimed via **leases/locks with expiry**.
- If a worker crashes, work must eventually be reclaimed.
- Long-running tasks must respect strict timeouts.

---

## Fingerprinting Philosophy

Fingerprinting should be:

- **Deterministic**: same input → same output (as much as possible)
- **Incremental**: start shallow, add depth later
- **Explainable**: stored data should be interpretable by humans
- **Non-invasive**: avoid unnecessary interaction with target sites

Avoid:
- Overfitting to one site
- Fragile heuristics
- Relying on a single signal

Prefer **many weak signals** over one “clever” one.

---

## Observability Requirements

The system must make it easy to answer:

- What domains were processed today?
- Which jobs failed and why?
- Is the worker alive?
- How long does fingerprinting take?
- What changed between runs?

Logs, run records, and timestamps are first-class outputs.

---

## Configuration & Secrets

- All configuration comes from environment variables.
- No secrets are committed to the repository.
- The same container must run locally and in production.
- Behaviour differences are controlled via explicit config flags.
- Keep dependencies minimal; prefer the Python standard library and `uv` for local envs.

---

## Development Ethos

- Build the end-to-end skeleton first.
- Ship small, working increments.
- Prefer boring, explicit code over abstraction.
- If unsure, choose the design that is easiest to debug at 3am.
- Break down the code following software engineering best practices, we do not want one single file that does everything, we need compartmentalised, testable, debuggable code

The agent should always optimise for **clarity over cleverness**.

---

## Verification Commands

After making code changes, you must verify code quality.

Run these from the repo root and ensure all are clear:

- `uv run ruff check .` (lint)
- `uv run ruff format .` (format)
- `uv run ty check .` (typecheck)
