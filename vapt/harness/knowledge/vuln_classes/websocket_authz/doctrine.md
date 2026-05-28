# WebSocket Authorization Drift

Thesis shape:

- A user is blocked from reading an object through the canonical REST/API path.
- A realtime event or websocket subscription still delivers the object, metadata,
  or update signal.
- The leak crosses a real permission, membership, guest, tenant, or visibility
  boundary.

Required proof:

- Positive actor can trigger or update the protected object.
- Denied actor receives the realtime event.
- Denied actor cannot read the same data through the guarded REST/API path.
- Event payload contains security-relevant content or enough metadata to create
  concrete confidentiality impact.

Common sinks:

- Event publish helpers.
- Channel/team/user fanout helpers.
- `ShouldSendEvent`-style filters.
- WebSocket subscription routing.

Negative controls:

- Denied REST/API read.
- Unsubscribed/unauthorized user does not receive unrelated events.
- Patched or fixed behavior when available.
