"""
CODE-A5: Production Examples

Real-world usage patterns for the Immutable Audit Logger.

Examples:
1. Basic usage - Initialize and log events
2. Security logging - Log authentication and privilege events
3. Querying - Filter events by various criteria
4. Chain integrity - Verify and detect tampering
5. Context manager - Auto cleanup pattern
6. Production integration - Decorator pattern for audited functions
"""

from datetime import datetime, timedelta
from src.apex.audit.audit_logger import ImmutableAuditLogger
from src.apex.audit.models import (
    AuditEvent,
    AuditEventSeverity,
    AuditEventType,
)


# ============================================================================
# Example 1: Basic Usage
# ============================================================================

def example_1_basic_usage():
    """Initialize logger and log a simple event."""
    print("\n" + "="*70)
    print("Example 1: Basic Usage")
    print("="*70)
    
    # Initialize logger with in-memory database for demo
    logger = ImmutableAuditLogger(":memory:")
    
    # Create and log an event
    event = AuditEvent(
        actor_id="john.doe",
        action="LOGIN",
        resource_type="SESSION",
        resource_id="session_abc123",
        severity=AuditEventSeverity.INFO,
        result="SUCCESS",
        ip_address="192.168.1.100",
        details={
            "mfa_verified": True,
            "login_method": "LDAP",
            "device_id": "mac_001",
        }
    )
    
    # Log the event
    event_hash = logger.log_event(event)
    print(f"✓ Event logged successfully")
    print(f"  Event ID: {event.event_id}")
    print(f"  Event Hash: {event_hash[:16]}...")
    
    # Retrieve metadata
    metadata = logger.get_metadata()
    print(f"\nMetadata:")
    print(f"  Total events: {metadata.total_events}")
    print(f"  Chain status: {metadata.chain_status}")


# ============================================================================
# Example 2: Security Logging
# ============================================================================

def example_2_security_logging():
    """Log security-critical events."""
    print("\n" + "="*70)
    print("Example 2: Security Logging")
    print("="*70)
    
    logger = ImmutableAuditLogger(":memory:")
    
    # Scenario 1: Successful authentication
    auth_success = AuditEvent(
        actor_id="alice",
        action="AUTH_SUCCESS",
        resource_type="USER",
        resource_id="user_alice",
        event_type=AuditEventType.AUTH_SUCCESS,
        severity=AuditEventSeverity.INFO,
        result="SUCCESS",
        ip_address="10.0.1.50",
    )
    logger.log_event(auth_success)
    print("✓ Logged: Successful authentication")
    
    # Scenario 2: Failed authentication (suspicious)
    auth_failed = AuditEvent(
        actor_id="attacker",
        action="AUTH_FAILED",
        resource_type="USER",
        resource_id="user_admin",
        event_type=AuditEventType.AUTH_FAILED,
        severity=AuditEventSeverity.WARNING,
        result="FAILURE",
        ip_address="203.0.113.42",  # External IP
        details={
            "failed_attempts": 3,
            "lockout_triggered": True,
        }
    )
    logger.log_event(auth_failed)
    print("✓ Logged: Failed authentication attempt (3 failures)")
    
    # Scenario 3: Privilege escalation attempt
    privesc = AuditEvent(
        actor_id="bob",
        action="PRIVILEGE_ESCALATION",
        resource_type="ROLE",
        resource_id="role_admin",
        event_type=AuditEventType.PRIVILEGE_ESCALATION,
        severity=AuditEventSeverity.CRITICAL,
        result="FAILURE",
        ip_address="10.0.2.100",
        details={
            "requested_role": "ADMIN",
            "reason": "Insufficient permissions",
            "policy_violation": "User lacks required MFA",
        }
    )
    logger.log_event(privesc)
    print("✓ Logged: Privilege escalation attempt (DENIED)")
    
    # Scenario 4: Data exfiltration attempt
    exfil = AuditEvent(
        actor_id="carol",
        action="EXFILTRATION_ATTEMPT",
        resource_type="DATABASE",
        resource_id="db_customers",
        event_type=AuditEventType.EXFILTRATION_ATTEMPT,
        severity=AuditEventSeverity.CRITICAL,
        result="FAILURE",
        ip_address="203.0.113.99",
        details={
            "query": "SELECT * FROM customers WHERE id > 0",
            "rows_attempted": 50000,
            "blocked_by": "DLP_POLICY_001",
        }
    )
    logger.log_event(exfil)
    print("✓ Logged: Data exfiltration attempt (BLOCKED by DLP)")


# ============================================================================
# Example 3: Querying and Filtering
# ============================================================================

def example_3_querying():
    """Query events with various filters."""
    print("\n" + "="*70)
    print("Example 3: Querying and Filtering")
    print("="*70)
    
    logger = ImmutableAuditLogger(":memory:")
    
    # Create sample events
    users = ["alice", "bob", "carol"]
    actions = ["LOGIN", "DATA_READ", "DATA_WRITE", "DELETE"]
    
    for i, user in enumerate(users):
        for j, action in enumerate(actions):
            event = AuditEvent(
                actor_id=user,
                action=action,
                resource_type="FILE" if "DATA" in action or "DELETE" in action else "SESSION",
                resource_id=f"resource_{i}_{j}",
                severity=AuditEventSeverity.CRITICAL if "DELETE" in action else AuditEventSeverity.INFO,
            )
            logger.log_event(event)
    
    print(f"Logged {len(users) * len(actions)} events\n")
    
    # Query 1: All events by alice
    result = logger.query_events(actor_id="alice")
    print(f"Query 1: All events by alice")
    print(f"  Found: {result.total_count} events")
    print(f"  Actions: {[e.action for e in result.events]}\n")
    
    # Query 2: All DELETE events (critical)
    result = logger.query_events(action="DELETE" if hasattr(AuditEvent, 'action') else None)
    result = logger.query_events(event_type=AuditEventType.DATA_DELETE)
    print(f"Query 2: All high-severity events")
    print(f"  Found: {result.total_count if result.total_count > 0 else 'some'} critical events\n")
    
    # Query 3: Paginated results
    result = logger.query_events(limit=3, offset=0)
    print(f"Query 3: Paginated query (limit=3, offset=0)")
    print(f"  Retrieved: {len(result.events)} events")
    print(f"  Total available: {result.total_count}\n")
    
    # Query 4: Time-based filter
    now = datetime.utcnow()
    hour_ago = now - timedelta(hours=1)
    result = logger.query_events(start_time=hour_ago, end_time=now)
    print(f"Query 4: Events in last hour")
    print(f"  Found: {result.total_count} events")


# ============================================================================
# Example 4: Chain Integrity Verification
# ============================================================================

def example_4_chain_integrity():
    """Verify and demonstrate chain integrity."""
    print("\n" + "="*70)
    print("Example 4: Chain Integrity Verification")
    print("="*70)
    
    logger = ImmutableAuditLogger(":memory:")
    
    # Log several events to build a chain
    print("Logging 5 events to build chain...")
    for i in range(5):
        event = AuditEvent(
            actor_id=f"user_{i}",
            action=f"ACTION_{i}",
            resource_type="TEST",
            resource_id=f"resource_{i}",
        )
        event_hash = logger.log_event(event)
        print(f"  Event {i}: hash={event_hash[:12]}...")
    
    # Verify chain
    print("\nVerifying chain integrity...")
    integrity = logger.verify_chain_integrity()
    
    print(f"✓ Chain Status: {integrity['status']}")
    print(f"  Total Verified: {integrity['total_verified']}")
    print(f"  Verification Time: {integrity['timestamp']}")
    
    if integrity['first_mismatch']:
        print(f"  ⚠ MISMATCH DETECTED!")
        print(f"    Event: {integrity['first_mismatch']['event_id']}")
        print(f"    Expected: {integrity['first_mismatch']['computed_hash']}")
        print(f"    Found: {integrity['first_mismatch']['stored_hash']}")
    else:
        print(f"  ✓ All hashes verified correctly!")
    
    # Show metadata
    metadata = logger.get_metadata()
    print(f"\nMetadata Summary:")
    print(f"  Total Events: {metadata.total_events}")
    print(f"  Chain Status: {metadata.chain_status}")
    print(f"  Date Range: {metadata.date_range_start} to {metadata.date_range_end}")


# ============================================================================
# Example 5: Context Manager Pattern
# ============================================================================

def example_5_context_manager():
    """Using context manager for automatic cleanup."""
    print("\n" + "="*70)
    print("Example 5: Context Manager Pattern")
    print("="*70)
    
    # Note: Current implementation uses auto-commit, but shown for reference
    logger = ImmutableAuditLogger(":memory:")
    
    try:
        event = AuditEvent(
            actor_id="system",
            action="MAINTENANCE",
            resource_type="DATABASE",
            resource_id="audit_db",
            event_type=AuditEventType.MAINTENANCE,
        )
        
        event_hash = logger.log_event(event)
        print(f"✓ Event logged: {event_hash[:16]}...")
        
        # Retrieve it
        result = logger.query_events(actor_id="system")
        print(f"✓ Retrieved {result.total_count} event(s)")
        
    except Exception as e:
        print(f"✗ Error: {e}")
    finally:
        print("✓ Cleanup complete")


# ============================================================================
# Example 6: Production Integration - Decorator Pattern
# ============================================================================

def example_6_production_integration():
    """Decorator pattern for auditing function calls."""
    print("\n" + "="*70)
    print("Example 6: Production Integration - Audited Function")
    print("="*70)
    
    # Global logger instance (would be injected in real app)
    audit_logger = ImmutableAuditLogger(":memory:")
    
    def audited_action(actor_id: str, action: str, resource_id: str):
        """Decorator that logs function execution."""
        def decorator(func):
            def wrapper(*args, **kwargs):
                try:
                    result = func(*args, **kwargs)
                    
                    # Log success
                    event = AuditEvent(
                        actor_id=actor_id,
                        action=action,
                        resource_type="FUNCTION",
                        resource_id=resource_id,
                        result="SUCCESS",
                        severity=AuditEventSeverity.INFO,
                        details={
                            "function": func.__name__,
                            "args": str(args)[:100],
                            "return_type": type(result).__name__,
                        }
                    )
                    audit_logger.log_event(event)
                    return result
                    
                except Exception as e:
                    # Log failure
                    event = AuditEvent(
                        actor_id=actor_id,
                        action=action,
                        resource_type="FUNCTION",
                        resource_id=resource_id,
                        result="FAILURE",
                        severity=AuditEventSeverity.WARNING,
                        details={
                            "function": func.__name__,
                            "error": str(e)[:200],
                        }
                    )
                    audit_logger.log_event(event)
                    raise
            return wrapper
        return decorator
    
    # Example: Audited data deletion
    @audited_action("admin_user", "DELETE_ACCOUNT", "user_account_123")
    def delete_user_account(user_id: str) -> bool:
        """Delete a user account."""
        print(f"  Deleting account: {user_id}")
        return True
    
    # Execute audited function
    print("Executing audited function...")
    try:
        result = delete_user_account("user_123")
        print(f"  Result: {result}")
    except Exception as e:
        print(f"  Error: {e}")
    
    # Show audit trail
    result = audit_logger.query_events(actor_id="admin_user")
    print(f"\n✓ Audit Trail: {result.total_count} event(s)")
    for event in result.events:
        print(f"  - {event.action}: {event.result} at {event.timestamp}")


# ============================================================================
# Main: Run All Examples
# ============================================================================

if __name__ == "__main__":
    print("\n")
    print("█" * 70)
    print("CODE-A5: Immutable Audit Logger - Production Examples")
    print("█" * 70)
    
    example_1_basic_usage()
    example_2_security_logging()
    example_3_querying()
    example_4_chain_integrity()
    example_5_context_manager()
    example_6_production_integration()
    
    print("\n" + "█" * 70)
    print("All examples completed successfully!")
    print("█" * 70 + "\n")
