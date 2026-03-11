# ExecPlans

Use an ExecPlan for any substantial change.

An ExecPlan in this repository must:
- be self-contained enough for a new engineer or agent to implement from the file alone
- describe the user-visible or operator-visible outcome, not just code edits
- name exact files, modules, and commands
- include `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective`
- live under `docs/exec-plans/active/` while in progress and move to `docs/exec-plans/completed/` when done

Every ExecPlan should also include:
- the purpose of the change
- current repository context
- the implementation path in prose
- exact validation commands
- acceptance criteria a human can observe

Keep ExecPlans updated as work progresses. They are living documents, not one-time design notes.
