# Tech Debt Tracker

- Runtime orchestration still concentrates most control flow in `src/fingerprint_worker/runtime/worker.py`.
- Service payloads are still dictionary-shaped rather than fully modeled dataclasses or `TypedDict`s.
- Compatibility wrappers under `src/*.py` should eventually be retired after external callers move to package imports.
- Object-storage integration remains a planned follow-up; large artifacts are still represented only by TODO markers.
