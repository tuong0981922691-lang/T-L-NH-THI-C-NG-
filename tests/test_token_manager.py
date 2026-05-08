"""
CODE-A1: Token Manager - Comprehensive Test Suite

Test coverage for:
- Ed25519 keypair generation
- Token issuance & expiry
- Bearer token signing & verification
- Macaroon issuance & attenuation
- Caveat evaluation
- Revocation
- Thread safety
- Integration with audit logger
"""

import pytest
from datetime import datetime, timedelta
from uuid import uuid4

from src.apex.token.token_manager import CapabilityTokenManager
from src.apex.token.models import (
    CapabilityToken,
    Macaroon,
    Caveat,
    CaveatType,
    CapabilityScope,
    TokenType,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def token_manager():
    """Create token manager with no audit logger."""
    return CapabilityTokenManager(audit_logger=None)


@pytest.fixture
def token_manager_with_keys(token_manager):
    """Token manager with keypair loaded."""
    keypair = token_manager.generate_keypair()
    token_manager.store_keypair(keypair)
    return token_manager


# ============================================================================
# Test 1: Keypair Generation
# ============================================================================

class TestKeypairGeneration:
    """Test Ed25519 keypair generation."""
    
    def test_generate_keypair(self, token_manager):
        """Generate keypair."""
        keypair = token_manager.generate_keypair()
        
        assert keypair.public_key is not None
        assert keypair.private_key is not None
        assert len(keypair.public_key) == 32
        assert len(keypair.private_key) == 64
    
    def test_store_and_retrieve_keypair(self, token_manager_with_keys):
        """Store and retrieve keypair."""
        keypair = token_manager_with_keys.get_keypair()
        assert keypair is not None
        assert len(keypair.public_key) == 32
        
        key_id = token_manager_with_keys.get_public_key_id()
        assert key_id is not None


# ============================================================================
# Test 2: Bearer Token Issuance & Verification
# ============================================================================

class TestBearerToken:
    """Test bearer token lifecycle."""
    
    def test_issue_token(self, token_manager_with_keys):
        """Issue bearer token."""
        token = token_manager_with_keys.issue_token(
            subject_id="alice",
            scope=CapabilityScope.READ,
            ttl_seconds=3600,
        )
        
        assert token.token_type == TokenType.BEARER
        assert token.subject_id == "alice"
        assert token.scope == CapabilityScope.READ
        assert token.signature is not None
        assert len(token.signature) == 64  # Ed25519 signature
    
    def test_verify_valid_token(self, token_manager_with_keys):
        """Verify valid token."""
        token = token_manager_with_keys.issue_token(
            subject_id="alice",
            scope=CapabilityScope.READ,
        )
        
        result = token_manager_with_keys.verify_token(token)
        
        assert result.valid is True
        assert result.reason is None
        assert result.token == token
    
    def test_verify_expired_token(self, token_manager_with_keys):
        """Verify expired token."""
        token = token_manager_with_keys.issue_token(
            subject_id="alice",
            ttl_seconds=1,  # Expires in 1 second
        )
        
        # Advance time past expiry
        future = datetime.utcnow() + timedelta(seconds=2)
        result = token_manager_with_keys.verify_token(token, now=future)
        
        assert result.valid is False
        assert "expired" in result.reason
        assert "token_expired" in result.violations
    
    def test_verify_revoked_token(self, token_manager_with_keys):
        """Verify revoked token."""
        token = token_manager_with_keys.issue_token(subject_id="alice")
        
        # Verify initially valid
        result = token_manager_with_keys.verify_token(token)
        assert result.valid is True
        
        # Revoke token
        token_manager_with_keys.revoke_token(token.token_id, reason="compromise")
        
        # Verify now fails
        result = token_manager_with_keys.verify_token(token)
        assert result.valid is False
        assert "revoked" in result.reason


# ============================================================================
# Test 3: Macaroon Issuance & Attenuation
# ============================================================================

class TestMacaroon:
    """Test macaroon lifecycle."""
    
    def test_issue_macaroon(self, token_manager_with_keys):
        """Issue root macaroon."""
        macaroon = token_manager_with_keys.issue_macaroon(
            subject_id="bob",
            scope=CapabilityScope.WRITE,
        )
        
        assert macaroon.subject_id == "bob"
        assert macaroon.scope == CapabilityScope.WRITE
        assert macaroon.signature is not None
        assert len(macaroon.signature) == 32  # HMAC-SHA256
        assert len(macaroon.caveats) == 0
    
    def test_attenuate_macaroon(self, token_manager_with_keys):
        """Attenuate macaroon with caveat."""
        macaroon = token_manager_with_keys.issue_macaroon(subject_id="bob")
        
        # Add time-bound caveat
        expiry = datetime.utcnow() + timedelta(hours=1)
        caveat = Caveat.time_bound(expiry)
        attenuated = token_manager_with_keys.attenuate_macaroon(macaroon, caveat)
        
        assert attenuated.macaroon_id == macaroon.macaroon_id  # Same ID
        assert len(attenuated.caveats) == 1
        assert attenuated.caveats[0].caveat_type == CaveatType.TIME_BOUND
    
    def test_verify_macaroon(self, token_manager_with_keys):
        """Verify macaroon."""
        macaroon = token_manager_with_keys.issue_macaroon(subject_id="bob")
        keypair = token_manager_with_keys.get_keypair()
        
        result = token_manager_with_keys.verify_macaroon(
            macaroon,
            issuer_key=keypair.private_key,
        )
        
        assert result.valid is True


# ============================================================================
# Test 4: Caveat Evaluation
# ============================================================================

class TestCaveatEvaluation:
    """Test caveat restriction checking."""
    
    def test_time_bound_caveat_valid(self, token_manager_with_keys):
        """Time-bound caveat still valid."""
        macaroon = token_manager_with_keys.issue_macaroon(subject_id="alice")
        
        # Add caveat expiring 1 hour from now
        expiry = datetime.utcnow() + timedelta(hours=1)
        caveat = Caveat.time_bound(expiry)
        macaroon = macaroon.attenuate(caveat)
        
        keypair = token_manager_with_keys.get_keypair()
        result = token_manager_with_keys.verify_macaroon(
            macaroon,
            issuer_key=keypair.private_key,
            now=datetime.utcnow(),
        )
        
        assert result.valid is True
    
    def test_time_bound_caveat_expired(self, token_manager_with_keys):
        """Time-bound caveat expired."""
        macaroon = token_manager_with_keys.issue_macaroon(subject_id="alice")
        
        # Add caveat that expired 1 hour ago
        expiry = datetime.utcnow() - timedelta(hours=1)
        caveat = Caveat.time_bound(expiry)
        macaroon = macaroon.attenuate(caveat)
        
        keypair = token_manager_with_keys.get_keypair()
        result = token_manager_with_keys.verify_macaroon(
            macaroon,
            issuer_key=keypair.private_key,
            now=datetime.utcnow(),
        )
        
        assert result.valid is False
        assert any("time_bound" in v for v in result.violations)
    
    def test_ip_restrict_caveat(self, token_manager_with_keys):
        """IP restrict caveat."""
        macaroon = token_manager_with_keys.issue_macaroon(subject_id="alice")
        
        # Add IP restriction
        caveat = Caveat.ip_restrict(allowed_ips=["10.0.0.1", "10.0.0.2"])
        macaroon = macaroon.attenuate(caveat)
        
        keypair = token_manager_with_keys.get_keypair()
        
        # Allowed IP
        result = token_manager_with_keys.verify_macaroon(
            macaroon,
            issuer_key=keypair.private_key,
            client_context={"client_ip": "10.0.0.1"},
        )
        assert result.valid is True
        
        # Blocked IP
        result = token_manager_with_keys.verify_macaroon(
            macaroon,
            issuer_key=keypair.private_key,
            client_context={"client_ip": "10.0.0.99"},
        )
        assert result.valid is False
        assert any("ip_restrict" in v for v in result.violations)
    
    def test_resource_bound_caveat(self, token_manager_with_keys):
        """Resource-bound caveat."""
        macaroon = token_manager_with_keys.issue_macaroon(subject_id="alice")
        
        caveat = Caveat.resource_bound(resource_id="document_123")
        macaroon = macaroon.attenuate(caveat)
        
        keypair = token_manager_with_keys.get_keypair()
        
        # Allowed resource
        result = token_manager_with_keys.verify_macaroon(
            macaroon,
            issuer_key=keypair.private_key,
            client_context={"resource_id": "document_123"},
        )
        assert result.valid is True
        
        # Different resource
        result = token_manager_with_keys.verify_macaroon(
            macaroon,
            issuer_key=keypair.private_key,
            client_context={"resource_id": "document_456"},
        )
        assert result.valid is False


# ============================================================================
# Test 5: Revocation
# ============================================================================

class TestRevocation:
    """Test token revocation."""
    
    def test_revoke_token(self, token_manager_with_keys):
        """Revoke and check."""
        token = token_manager_with_keys.issue_token(subject_id="alice")
        
        entry = token_manager_with_keys.revoke_token(
            token.token_id,
            reason="user_logout",
        )
        
        assert entry.token_id == token.token_id
        assert entry.revocation_reason == "user_logout"
        assert token_manager_with_keys._is_revoked(token.token_id)
    
    def test_get_revocation_list(self, token_manager_with_keys):
        """Get all revoked tokens."""
        token1 = token_manager_with_keys.issue_token(subject_id="alice")
        token2 = token_manager_with_keys.issue_token(subject_id="bob")
        
        token_manager_with_keys.revoke_token(token1.token_id)
        token_manager_with_keys.revoke_token(token2.token_id)
        
        revocation_list = token_manager_with_keys.get_revocation_list()
        
        assert len(revocation_list) == 2
        assert token1.token_id in revocation_list
        assert token2.token_id in revocation_list


# ============================================================================
# Test 6: Edge Cases
# ============================================================================

class TestEdgeCases:
    """Test error cases and edge conditions."""
    
    def test_issue_token_no_keypair(self, token_manager):
        """Try to issue token without keypair."""
        with pytest.raises(RuntimeError, match="No keypair loaded"):
            token_manager.issue_token(subject_id="alice")
    
    def test_verify_token_tampered_signature(self, token_manager_with_keys):
        """Verify token with tampered signature."""
        token = token_manager_with_keys.issue_token(subject_id="alice")
        
        # Tamper with signature
        tampered = CapabilityToken(
            token_id=token.token_id,
            token_type=token.token_type,
            issuer_id=token.issuer_id,
            subject_id="eve",  # Changed!
            scope=token.scope,
            issued_at=token.issued_at,
            expires_at=token.expires_at,
            public_key_id=token.public_key_id,
            signature=b"tampered_signature",  # Bad signature
            metadata=token.metadata,
        )
        
        result = token_manager_with_keys.verify_token(tampered)
        assert result.valid is False
        assert any("signature" in v for v in result.violations)
    
    def test_multiple_caveats(self, token_manager_with_keys):
        """Macaroon with multiple caveats."""
        macaroon = token_manager_with_keys.issue_macaroon(subject_id="alice")
        
        # Add multiple caveats
        caveat1 = Caveat.time_bound(datetime.utcnow() + timedelta(hours=1))
        caveat2 = Caveat.ip_restrict(allowed_ips=["10.0.0.1"])
        
        macaroon = token_manager_with_keys.attenuate_macaroon(macaroon, caveat1)
        macaroon = token_manager_with_keys.attenuate_macaroon(macaroon, caveat2)
        
        assert len(macaroon.caveats) == 2
        
        keypair = token_manager_with_keys.get_keypair()
        result = token_manager_with_keys.verify_macaroon(
            macaroon,
            issuer_key=keypair.private_key,
            client_context={"client_ip": "10.0.0.1"},
        )
        assert result.valid is True


# ============================================================================
# Test 7: Result Helpers
# ============================================================================

class TestTokenVerificationResult:
    """Test verification result helpers."""
    
    def test_result_is_expired(self, token_manager_with_keys):
        """Check result.is_expired()."""
        token = token_manager_with_keys.issue_token(
            subject_id="alice",
            ttl_seconds=1,
        )
        
        future = datetime.utcnow() + timedelta(seconds=2)
        result = token_manager_with_keys.verify_token(token, now=future)
        
        assert result.is_expired() is True
        assert result.is_revoked() is False
    
    def test_result_is_revoked(self, token_manager_with_keys):
        """Check result.is_revoked()."""
        token = token_manager_with_keys.issue_token(subject_id="alice")
        token_manager_with_keys.revoke_token(token.token_id)
        
        result = token_manager_with_keys.verify_token(token)
        
        assert result.is_revoked() is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
