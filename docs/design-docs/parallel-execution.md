# Parallel Execution

When multiple agents or engineers work in parallel:

- use worktrees or isolated branches
- update the active ExecPlan with ownership and discoveries
- avoid large cross-cutting refactors without first stabilizing the package layout
- regenerate diagram hashes whenever architecture or package flow changes
- merge structure changes before large feature work when possible, so future diffs stay small and conflict-resistant
