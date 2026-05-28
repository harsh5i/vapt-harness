# IDOR Differential Authorization

Reportable shape:

- Same protected object identifier is used across authorized and unauthorized
  principals.
- Authorized principal receives the expected object.
- Unauthorized principal is able to read or modify the same object, or a
  patched/negative control shows the expected denial.
- Root cause is an authorization invariant failure, not only a missing UI check.

Minimum evidence:

- Principal A request/response.
- Principal B request/response.
- Object ownership or tenant boundary.
- Permission check location and omitted invariant.
