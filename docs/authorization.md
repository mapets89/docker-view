# Authorization

Permissions are a backend code-defined catalog. Routes check permissions server-side; UI visibility is convenience only. Viewer receives read/inspect/stats/logs, Developer adds exec, and Admin receives the complete catalog. Built-in role names cannot be changed or deleted, though their permission assignments can be edited.

Policies answer where a granted action applies. Evaluation order is: immutable system deny, explicit deny, explicit allow, role permission, default deny. An allow rule never grants a missing role permission. Current resources are scoped as `host/local` in role bindings.

Containers labeled `dockerview.system=true` cannot be exec'd or restarted, even by Admin and even if a policy allows them. Both Server and Gateway enforce this against Docker's authoritative inspect response.
