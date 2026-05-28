"""Watch and discovery substrate (Phase 5 Move 4).

Phase 4 wired per-target watch sources (`watch-add`, `watch-tick`,
`watch-daemon`). This package extends the substrate with target-level
discovery: sweep external advisory feeds, propose new targets the
harness is not yet watching, and surface them for operator promotion.

Modules:
- discovery: cross-target advisory sweep and proposal logic.

Per the substrate doctrine, no auto-discovered target enters a campaign
without an explicit operator claim.
"""
