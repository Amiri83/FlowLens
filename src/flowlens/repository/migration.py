"""Identity migration *contract* (ADR 0007). Documented and tested; NOT executed.

Phase 1 does not activate the ``tf:<cfg>::<address>`` identity scheme in the
production scanner, so no database is touched. When a later phase activates
it, the one-time migration must follow this contract exactly:

1. Gate: meta key :data:`IDENTITY_SCHEME_META_KEY` in the existing ``meta``
   table. Missing key = legacy scheme 1; the new value is
   :data:`CURRENT_IDENTITY_SCHEME`.
2. Scope: only nodes matching :func:`is_legacy_terraform_node_id`
   (``tf:`` prefix and no ``::``) plus every edge touching them. Cloud-id nodes
   (``<type>:<cloud_id>``, including state-derived nodes merged with AWS) and
   scheme-2 ``tf:<cfg>::<address>`` nodes are never touched.
3. One-time and transactional: purge, re-insert and the scheme stamp happen in
   one SQLite transaction together with the save (which must itself become
   atomic). No alias map, no id-equality merge between old and new ids.
4. No general stale-node subsystem: stale nodes *within* scheme 2 remain a
   documented known limitation.
5. The RepositoryModel schema version
   (:data:`~flowlens.repository.model.CURRENT_REPOSITORY_MODEL_VERSION`) is
   separate: bumping it replaces only a persisted model blob, never nodes.
"""
from __future__ import annotations

IDENTITY_SCHEME_META_KEY = "terraform_identity_scheme"
LEGACY_IDENTITY_SCHEME = "1"
CURRENT_IDENTITY_SCHEME = "2"


def is_legacy_terraform_node_id(node_id: str) -> bool:
    """Exact legacy predicate: scheme-1 config-only Terraform node ids."""
    return node_id.startswith("tf:") and "::" not in node_id


def migration_required(stored_scheme: str | None, node_ids: list[str] | tuple[str, ...]) -> bool:
    """Whether a Terraform-writing command would have to run the one-time purge."""
    return stored_scheme != CURRENT_IDENTITY_SCHEME and any(is_legacy_terraform_node_id(n) for n in node_ids)
