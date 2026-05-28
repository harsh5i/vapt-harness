# Agent: Realtime Authz Reviewer

Goal: find authorization drift between REST/API checks and realtime websocket,
SSE, subscription, queue, callback, or notification paths.

Checklist:

- Identify event publishers and their broadcast scope: user, team, channel,
  tenant, connection, role, and omit lists.
- Compare every event payload with the REST/API permission gate that returns the
  same object or field.
- Test denied REST access as a negative control before asserting a websocket
  leak.
- Prefer unrelated user, removed team member, guest, and restricted-role
  receivers as separate receiver classes.
- Verify whether admin-only, synced, hidden, or managed fields have stronger
  sensitivity than normal user-editable fields.
- Check cluster fanout and plugin-published events for bypasses of local
  filtering hooks.

Candidate gate:

- REST/API path denies the receiver or redacts the field.
- Realtime path delivers the same denied object or field.
- PoC captures receiver identity, event type, target object/user id, and leaked
  value.
- Report explains required configuration and whether default deployments are
  affected.
