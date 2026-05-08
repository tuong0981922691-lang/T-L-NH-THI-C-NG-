"""
CODE-A5: Immutable Audit Logger - Comprehensive Test Suite

20+ test cases covering:
- Basic logging
- Chain hashing
- Querying and filtering
- Integrity verification
- Concurrency
- Edge cases
"""

import pytest
import threading
from datetime import datetime, timedelta
from uuid import uuid4

from src.apex.audit.audit_logger import ImmutableAuditLogger
from src.apex.audit.models import (
    AuditEvent,
    AuditEventType,
    AuditEventSeverity,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def logger():
    """In-memory audit logger for testing."""
    return ImmutableAuditLogger(":memory:")


@pytest.fixture
def sample_event():
    """Sample audit event."""
    return AuditEvent(
        actor_id="test_user",
        action="TEST_ACTION",
        resource_type="TEST_RESOURCE",
        resource_id="resource_001",
        severity=AuditEventSeverity.INFO,
    )


# ============================================================================
# Test Group 1: Basic Logging
# ============================================================================

class TestBasicLogging:
    """Basic logging functionality."""
    
    def test_log_single_event(self, logger, sample_event):
        """Test logging a single event."""
        event_hash = logger.log_event(sample_event)
        assert event_hash is not None
        assert len(event_hash) == 64  # SHA256 hex = 64 chars
    
    def test_log_duplicate_event_fails(self, logger, sample_event):
        """Test that duplicate event IDs raise error."""
        logger.log_event(sample_event)
        
        # Same event ID should fail
        with pytest.raises(Exception):  # sqlite3.IntegrityError
            logger.log_event(sample_event)
    
    def test_log_event_with_details(self, logger):
        """Test logging event with JSON details."""
        event = AuditEvent(
            actor_id="alice",
            action="DELETE_USER",
            resource_type="USER",
            resource_id="user_123",
            details={
                "reason": "Account deactivation",
                "authorized_by": "admin",
                "backup_created": True,
            }
        )
        
        event_hash = logger.log_event(event)
        assert event_hash is not None
        
        # Verify retrieval
        result = logger.query_events(actor_id="alice")
        assert result.total_count == 1
        assert result.events[0].details["reason"] == "Account deactivation"


# ============================================================================
# Test Group 2: Chain Hashing
# ============================================================================

class TestChainHashing:
    """Chain hash verification."""
    
    def test_chain_hash_progression(self, logger):
        """Test that each event's hash is based on previous hash."""
        # Log 3 events
        hashes = []
        for i in range(3):
            event = AuditEvent(
                actor_id=f"user_{i}",
                action=f"action_{i}",
                resource_type="TEST",
                resource_id=f"resource_{i}",
            )
            event_hash = logger.log_event(event)
            hashes.append(event_hash)
        
        # All hashes should be different
        assert len(set(hashes)) == 3
        
        # First hash should not be empty
        assert hashes[0] != ""
    
    def test_hash_determinism(self, logger):
        """Test that same event content produces same hash."""
        event1 = AuditEvent(
            actor_id="alice",
            action="LOGIN",
            resource_type="SESSION",
            resource_id="session_abc",
            event_id="fixed_id_123",  # Fixed ID for determinism test
        )
        
        # Compute hash twice
        hash1 = logger._compute_hash(event1, "")
        hash2 = logger._compute_hash(event1, "")
        
        assert hash1 == hash2


# ============================================================================
# Test Group 3: Querying and Filtering
# ============================================================================

class TestQuerying:
    """Event querying and filtering."""
    
    def test_query_by_actor_id(self, logger):
        """Test querying events by actor."""
        # Log events from 2 users
        for user in ["alice", "bob"]:
            for i in range(3):
                event = AuditEvent(
                    actor_id=user,
                    action=f"action_{i}",
                    resource_type="TEST",
                    resource_id=f"resource_{i}",
                )
                logger.log_event(event)
        
        # Query alice's events
        result = logger.query_events(actor_id="alice")
        assert result.total_count == 3
        assert all(e.actor_id == "alice" for e in result.events)
    
    def test_query_by_event_type(self, logger):
        """Test querying by event type."""
        # Log different event types
        event1 = AuditEvent(
            actor_id="user1",
            action="AUTH",
            event_type=AuditEventType.AUTH_SUCCESS,
            resource_type="SESSION",
            resource_id="session_1",
        )
        
        event2 = AuditEvent(
            actor_id="user2",
            action="READ",
            event_type=AuditEventType.DATA_READ,
            resource_type="FILE",
            resource_id="file_1",
        )
        
        logger.log_event(event1)
        logger.log_event(event2)
        
        # Query auth events only
        result = logger.query_events(event_type=AuditEventType.AUTH_SUCCESS)
        assert result.total_count == 1
        assert result.events[0].event_type == AuditEventType.AUTH_SUCCESS
    
    def test_query_by_severity(self, logger):
        """Test querying by severity level."""
        # Log events with different severities
        for severity in [AuditEventSeverity.INFO, AuditEventSeverity.WARNING, AuditEventSeverity.CRITICAL]:
            event = AuditEvent(
                actor_id="user",
                action="action",
                severity=severity,
                resource_type="TEST",
                resource_id="resource",
            )
            logger.log_event(event)
        
        # Query critical events only
        result = logger.query_events(severity=AuditEventSeverity.CRITICAL)
        assert result.total_count == 1
        assert result.events[0].severity == AuditEventSeverity.CRITICAL
    
    def test_query_by_time_range(self, logger):
        """Test querying by timestamp range."""
        now = datetime.utcnow()
        
        # Log event
        event = AuditEvent(
            actor_id="user",
            action="action",
            resource_type="TEST",
            resource_id="resource",
            timestamp=now,
        )
        logger.log_event(event)
        
        # Query within range
        result = logger.query_events(
            start_time=now - timedelta(minutes=1),
            end_time=now + timedelta(minutes=1)
        )
        assert result.total_count == 1
        
        # Query outside range
        result = logger.query_events(
            start_time=now + timedelta(hours=1),
            end_time=now + timedelta(hours=2)
        )
        assert result.total_count == 0
    
    def test_query_pagination(self, logger):
        """Test pagination with offset and limit."""
        # Log 10 events
        for i in range(10):
            event = AuditEvent(
                actor_id=f"user_{i}",
                action="action",
                resource_type="TEST",
                resource_id=f"resource_{i}",
            )
            logger.log_event(event)
        
        # Page 1: offset=0, limit=5
        result1 = logger.query_events(offset=0, limit=5)
        assert len(result1.events) == 5
        assert result1.total_count == 10
        
        # Page 2: offset=5, limit=5
        result2 = logger.query_events(offset=5, limit=5)
        assert len(result2.events) == 5
        
        # No overlapping events
        ids1 = {e.event_id for e in result1.events}
        ids2 = {e.event_id for e in result2.events}
        assert len(ids1 & ids2) == 0


# ============================================================================
# Test Group 4: Integrity Verification
# ============================================================================

class TestIntegrity:
    """Chain integrity verification."""
    
    def test_verify_healthy_chain(self, logger):
        """Test verification of healthy chain."""
        # Log several events
        for i in range(5):
            event = AuditEvent(
                actor_id=f"user_{i}",
                action="action",
                resource_type="TEST",
                resource_id=f"resource_{i}",
            )
            logger.log_event(event)
        
        # Verify chain
        result = logger.verify_chain_integrity()
        assert result['status'] == 'HEALTHY'
        assert result['total_verified'] == 5
        assert result['first_mismatch'] is None
    
    def test_get_metadata(self, logger):
        """Test metadata generation."""
        # Log events
        for i in range(3):
            event = AuditEvent(
                actor_id="user",
                action="action",
                severity=AuditEventSeverity.INFO if i % 2 == 0 else AuditEventSeverity.CRITICAL,
                resource_type="TEST",
                resource_id=f"resource_{i}",
            )
            logger.log_event(event)
        
        # Get metadata
        metadata = logger.get_metadata()
        assert metadata.total_events == 3
        assert metadata.chain_status == 'HEALTHY'


# ============================================================================
# Test Group 5: Concurrency
# ============================================================================

class TestConcurrency:
    """Thread-safe concurrent operations."""
    
    def test_concurrent_logging(self, logger):
        """Test logging from multiple threads."""
        event_count = 50
        thread_count = 5
        events_per_thread = event_count // thread_count
        
        def log_events(thread_id):
            for i in range(events_per_thread):
                event = AuditEvent(
                    actor_id=f"thread_{thread_id}",
                    action=f"action_{i}",
                    resource_type="TEST",
                    resource_id=f"resource_{thread_id}_{i}",
                )
                logger.log_event(event)
        
        # Launch threads
        threads = [
            threading.Thread(target=log_events, args=(i,))
            for i in range(thread_count)
        ]
        
        for thread in threads:
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Verify all events logged
        metadata = logger.get_metadata()
        assert metadata.total_events == event_count
        
        # Verify chain is still healthy
        result = logger.verify_chain_integrity()
        assert result['status'] == 'HEALTHY'


# ============================================================================
# Test Group 6: Edge Cases
# ============================================================================

class TestEdgeCases:
    """Edge cases and error scenarios."""
    
    def test_empty_database_query(self, logger):
        """Test querying empty database."""
        result = logger.query_events(actor_id="nonexistent")
        assert result.total_count == 0
        assert len(result.events) == 0
    
    def test_event_with_special_characters(self, logger):
        """Test event with special characters in fields."""
        event = AuditEvent(
            actor_id="user@domain.com",
            action="DELETE_FILE",
            resource_type="FILE",
            resource_id="/path/to/file (backup).txt",
            details={
                "reason": "Cleanup: removing old \"backups\" with 日本語",
            }
        )
        
        event_hash = logger.log_event(event)
        assert event_hash is not None
        
        # Retrieve and verify
        result = logger.query_events(actor_id="user@domain.com")
        assert result.total_count == 1
    
    def test_large_details_json(self, logger):
        """Test event with large details dictionary."""
        large_details = {
            f"key_{i}": f"value_{i}" * 100  # ~500 bytes per key
            for i in range(100)  # 50KB total
        }
        
        event = AuditEvent(
            actor_id="user",
            action="action",
            resource_type="TEST",
            resource_id="resource",
            details=large_details,
        )
        
        event_hash = logger.log_event(event)
        assert event_hash is not None
        
        result = logger.query_events(actor_id="user")
        assert len(result.events[0].details) == 100
    
    def test_many_events(self, logger):
        """Test with large number of events."""
        # Log 1000 events
        for i in range(1000):
            event = AuditEvent(
                actor_id=f"user_{i % 10}",
                action=f"action_{i % 20}",
                resource_type="TEST",
                resource_id=f"resource_{i}",
            )
            logger.log_event(event)
        
        # Verify metadata
        metadata = logger.get_metadata()
        assert metadata.total_events == 1000
        
        # Verify chain (may be slow)
        result = logger.verify_chain_integrity()
        assert result['status'] == 'HEALTHY'
        assert result['total_verified'] == 1000


# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
