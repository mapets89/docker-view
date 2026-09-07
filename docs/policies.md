# Policies

Policies contain enabled, human-readable allow/deny rules for one action. V1's UI focuses on `container.exec` and supports bounded container-name globs (`api-*`) and exact labels (`team=payments`). Bracket expressions and slashes are rejected to keep matching understandable and avoid pathname edge cases.

Explicit deny always wins. Explicit allow still requires the user's role to grant the action. With no matching rule, the role permission applies to non-system containers. System policy is not editable.
