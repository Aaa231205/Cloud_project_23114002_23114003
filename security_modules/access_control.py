"""
Access Control Module.

Enforces data access restrictions across storage nodes after detecting
suspicious activities. Supports three restriction types:
- node_block:   Block a user from accessing a specific storage node
- file_block:   Block a user from accessing a specific file
- temp_suspend: Temporarily suspend all access for a user

Restrictions are time-limited and automatically expire.
"""

from datetime import datetime, timedelta


def check_access_restriction(username: str, node_id: str, file_id: int, db) -> dict:
    """
    Check if a user has any active access restrictions that would prevent
    them from accessing a given node or file.

    Args:
        username: The user's username.
        node_id: The storage node being accessed (can be None).
        file_id: The file ID being accessed (can be None).
        db: Active database session.

    Returns:
        Dict with 'blocked' boolean and 'reason' string.
        If not blocked, returns {'blocked': False, 'reason': ''}.
    """
    from application_server_models import AccessRestriction

    now = datetime.utcnow()

    # Check temporary full suspension
    suspension = db.query(AccessRestriction).filter(
        AccessRestriction.username == username,
        AccessRestriction.restriction_type == "temp_suspend",
        AccessRestriction.restricted_until > now
    ).first()

    if suspension:
        remaining = (suspension.restricted_until - now).seconds // 60
        return {
            "blocked": True,
            "reason": f"Account temporarily suspended. Reason: {suspension.reason}. "
                      f"Try again in {remaining} minutes."
        }

    # Check node-level block
    if node_id:
        node_block = db.query(AccessRestriction).filter(
            AccessRestriction.username == username,
            AccessRestriction.restriction_type == "node_block",
            AccessRestriction.target == node_id,
            AccessRestriction.restricted_until > now
        ).first()

        if node_block:
            remaining = (node_block.restricted_until - now).seconds // 60
            return {
                "blocked": True,
                "reason": f"Access to node '{node_id}' is restricted. Reason: {node_block.reason}. "
                          f"Try again in {remaining} minutes."
            }

    # Check file-level block
    if file_id:
        file_block = db.query(AccessRestriction).filter(
            AccessRestriction.username == username,
            AccessRestriction.restriction_type == "file_block",
            AccessRestriction.target == str(file_id),
            AccessRestriction.restricted_until > now
        ).first()

        if file_block:
            remaining = (file_block.restricted_until - now).seconds // 60
            return {
                "blocked": True,
                "reason": f"Access to file '{file_id}' is restricted. Reason: {file_block.reason}. "
                          f"Try again in {remaining} minutes."
            }

    return {"blocked": False, "reason": ""}


def enforce_restriction(username: str, restriction_type: str, target: str,
                        reason: str, duration_minutes: int, db) -> dict:
    """
    Create a new access restriction for a user.

    Args:
        username: The user to restrict.
        restriction_type: One of 'node_block', 'file_block', 'temp_suspend'.
        target: The node_id or file_id to restrict (None for temp_suspend).
        reason: Human-readable reason for the restriction.
        duration_minutes: How long the restriction lasts.
        db: Active database session.

    Returns:
        Dict with restriction details.
    """
    from application_server_models import AccessRestriction

    restriction = AccessRestriction(
        username=username,
        restriction_type=restriction_type,
        target=target,
        reason=reason,
        restricted_until=datetime.utcnow() + timedelta(minutes=duration_minutes),
    )
    db.add(restriction)
    db.commit()
    db.refresh(restriction)

    return {
        "id": restriction.id,
        "username": username,
        "restriction_type": restriction_type,
        "target": target,
        "reason": reason,
        "restricted_until": str(restriction.restricted_until),
    }


def lift_expired_restrictions(db) -> int:
    """
    Remove all expired restrictions from the database.

    Args:
        db: Active database session.

    Returns:
        Number of restrictions removed.
    """
    from application_server_models import AccessRestriction

    now = datetime.utcnow()
    expired = db.query(AccessRestriction).filter(
        AccessRestriction.restricted_until <= now
    ).all()

    count = len(expired)
    for r in expired:
        db.delete(r)
    db.commit()

    return count
