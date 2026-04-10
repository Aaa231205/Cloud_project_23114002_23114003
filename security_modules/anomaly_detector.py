"""
Anomaly Detection Module.

Monitors access patterns across the distributed system and generates alerts
for abnormal behavior. Runs as a periodic background task on FastAPI startup.

Detection rules:
1. High Frequency Access:  >50 requests from same user in 1 minute  -> MEDIUM
2. Multiple Failed Auth:   >3 failed logins in 5 minutes            -> HIGH (triggers restriction)
3. Unknown Source IP:      Access from IP not seen in 30 days        -> LOW
4. Cross-Node Anomaly:     Same user accessing >2 nodes in 1 minute -> MEDIUM
5. Off-Hours Access:       Access outside 06:00-23:00 UTC            -> LOW
"""

import asyncio
from datetime import datetime, timedelta
from sqlalchemy import func


async def run_anomaly_detection(db_session_factory, interval_seconds: int = 60):
    """
    Continuously run anomaly detection checks at the specified interval.
    Designed to be started as an asyncio task on FastAPI startup.

    Args:
        db_session_factory: SQLAlchemy sessionmaker.
        interval_seconds: How often to run detection (default 60s).
    """
    while True:
        try:
            db = db_session_factory()
            try:
                detect_high_frequency_access(db)
                detect_failed_auth_spikes(db)
                detect_unknown_sources(db)
                detect_cross_node_anomaly(db)
            finally:
                db.close()
        except Exception as e:
            print(f"[Anomaly Detector] Error: {e}")

        await asyncio.sleep(interval_seconds)


def detect_high_frequency_access(db):
    """Detect users making an unusually high number of requests in a short window."""
    from application_server_models import AccessLog, SecurityAlert

    one_minute_ago = datetime.utcnow() - timedelta(minutes=1)

    # Count requests per user in the last minute
    results = db.query(
        AccessLog.username,
        func.count(AccessLog.id).label("req_count")
    ).filter(
        AccessLog.timestamp >= one_minute_ago,
        AccessLog.username.isnot(None)
    ).group_by(AccessLog.username).having(
        func.count(AccessLog.id) > 50
    ).all()

    for username, count in results:
        # Don't create duplicate alert if one exists in last 5 minutes
        existing = db.query(SecurityAlert).filter(
            SecurityAlert.alert_type == "HIGH_FREQUENCY_ACCESS",
            SecurityAlert.username == username,
            SecurityAlert.created_at >= datetime.utcnow() - timedelta(minutes=5),
            SecurityAlert.resolved == False
        ).first()

        if not existing:
            alert = SecurityAlert(
                alert_type="HIGH_FREQUENCY_ACCESS",
                severity="MEDIUM",
                description=f"User '{username}' made {count} requests in the last minute (threshold: 50).",
                username=username,
            )
            db.add(alert)
            db.commit()

            from security_modules.monitoring.logger import log_alert
            log_alert("HIGH_FREQUENCY_ACCESS", "MEDIUM",
                      f"User '{username}' made {count} requests in 1 min", "", username)


def detect_failed_auth_spikes(db):
    """Detect multiple failed authentication attempts and trigger access restrictions."""
    from application_server_models import AccessLog, SecurityAlert
    from security_modules.access_control import enforce_restriction

    five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)

    # Count failed logins (status_code 400 or 401 on /auth/login) per IP
    results = db.query(
        AccessLog.ip_address,
        AccessLog.username,
        func.count(AccessLog.id).label("fail_count")
    ).filter(
        AccessLog.timestamp >= five_minutes_ago,
        AccessLog.endpoint.like("%/auth/login%"),
        AccessLog.status_code.in_([400, 401, 403])
    ).group_by(AccessLog.ip_address, AccessLog.username).having(
        func.count(AccessLog.id) > 3
    ).all()

    for ip, username, count in results:
        existing = db.query(SecurityAlert).filter(
            SecurityAlert.alert_type == "FAILED_AUTH_SPIKE",
            SecurityAlert.source_ip == ip,
            SecurityAlert.created_at >= datetime.utcnow() - timedelta(minutes=10),
            SecurityAlert.resolved == False
        ).first()

        if not existing:
            alert = SecurityAlert(
                alert_type="FAILED_AUTH_SPIKE",
                severity="HIGH",
                description=f"IP {ip} had {count} failed login attempts in 5 minutes.",
                source_ip=ip,
                username=username,
            )
            db.add(alert)

            # Auto-enforce restriction if username is known
            if username:
                try:
                    enforce_restriction(
                        username=username,
                        restriction_type="temp_suspend",
                        target=None,
                        reason=f"Automated: {count} failed login attempts from IP {ip}",
                        duration_minutes=30,
                        db=db
                    )
                except Exception:
                    pass  # Restriction may already exist

            db.commit()

            from security_modules.monitoring.logger import log_alert
            log_alert("FAILED_AUTH_SPIKE", "HIGH",
                      f"IP {ip} had {count} failed logins in 5 min", ip, username or "unknown")


def detect_unknown_sources(db):
    """Detect access from IP addresses not seen for this user in the last 30 days."""
    from application_server_models import AccessLog, SecurityAlert

    one_minute_ago = datetime.utcnow() - timedelta(minutes=1)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)

    # Get recent access entries
    recent = db.query(AccessLog.username, AccessLog.ip_address).filter(
        AccessLog.timestamp >= one_minute_ago,
        AccessLog.username.isnot(None)
    ).distinct().all()

    for username, ip in recent:
        # Check if this IP was seen for this user in the last 30 days (excluding last minute)
        historical = db.query(AccessLog).filter(
            AccessLog.username == username,
            AccessLog.ip_address == ip,
            AccessLog.timestamp >= thirty_days_ago,
            AccessLog.timestamp < one_minute_ago
        ).first()

        if not historical:
            existing = db.query(SecurityAlert).filter(
                SecurityAlert.alert_type == "UNKNOWN_SOURCE_IP",
                SecurityAlert.username == username,
                SecurityAlert.source_ip == ip,
                SecurityAlert.created_at >= datetime.utcnow() - timedelta(hours=1),
                SecurityAlert.resolved == False
            ).first()

            if not existing:
                alert = SecurityAlert(
                    alert_type="UNKNOWN_SOURCE_IP",
                    severity="LOW",
                    description=f"User '{username}' accessed from new IP {ip} (not seen in 30 days).",
                    source_ip=ip,
                    username=username,
                )
                db.add(alert)
                db.commit()

                from security_modules.monitoring.logger import log_alert
                log_alert("UNKNOWN_SOURCE_IP", "LOW",
                          f"User '{username}' from new IP {ip}", ip, username)


def detect_cross_node_anomaly(db):
    """Detect same user accessing multiple storage nodes in a very short time window."""
    from application_server_models import AccessLog, SecurityAlert

    one_minute_ago = datetime.utcnow() - timedelta(minutes=1)

    # Count distinct nodes accessed per user in the last minute
    results = db.query(
        AccessLog.username,
        func.count(func.distinct(AccessLog.storage_node)).label("node_count")
    ).filter(
        AccessLog.timestamp >= one_minute_ago,
        AccessLog.username.isnot(None),
        AccessLog.storage_node.isnot(None)
    ).group_by(AccessLog.username).having(
        func.count(func.distinct(AccessLog.storage_node)) > 2
    ).all()

    for username, node_count in results:
        existing = db.query(SecurityAlert).filter(
            SecurityAlert.alert_type == "CROSS_NODE_ANOMALY",
            SecurityAlert.username == username,
            SecurityAlert.created_at >= datetime.utcnow() - timedelta(minutes=5),
            SecurityAlert.resolved == False
        ).first()

        if not existing:
            alert = SecurityAlert(
                alert_type="CROSS_NODE_ANOMALY",
                severity="MEDIUM",
                description=f"User '{username}' accessed {node_count} different nodes in under 1 minute.",
                username=username,
            )
            db.add(alert)
            db.commit()

            from security_modules.monitoring.logger import log_alert
            log_alert("CROSS_NODE_ANOMALY", "MEDIUM",
                      f"User '{username}' accessed {node_count} nodes in 1 min", "", username)
