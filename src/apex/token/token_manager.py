"""
CODE-A1: Capability Token Manager - Ed25519 Signing & Verification

Implements:
- KeyPair generation (Ed25519)
- Token issuance with Ed25519 signatures
- Token verification (signature + expiry + caveats)
- Macaroon attenuation (add restrictions)
- Revocation list management
- Integration with CODE-A5 audit logging
"""

from typing import Optional, Dict, List, Any, Tuple
from datetime import datetime, timedelta
import json
import threading
from uuid import uuid4
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from .models import (
    KeyPair,
    CapabilityToken,
    Macaroon,
    Caveat,
    CaveatType,
    TokenType,
    CapabilityScope,
    RevocationEntry,
    TokenVerificationResult,
)


class CapabilityTokenManager:
    """
    Manages lifecycle of capability tokens (CapabilityToken & Macaroon).
    
    Features:
    - Ed25519 asymmetric signing
    - Token issuance & expiry
    - Signature verification
    - Macaroon attenuation
    - Revocation list
    - Audit logging integration
    
    Thread-safe: uses locks for shared state (revocation list).
    """
    
    def __init__(self, audit_logger=None):
        """
        Initialize token manager.
        
        Args:
            audit_logger: Optional ImmutableAuditLogger for audit trail
        """
        self.audit_logger = audit_logger
        self._local = threading.local()  # Thread-local key pair storage
        self._revocation_lock = threading.RLock()
        self._revocation_list: Dict[str, RevocationEntry] = {}  # token_id -> RevocationEntry
        self._key_cache: Dict[str, KeyPair] = {}  # public_key_id -> KeyPair (for verification)
    
    # ==================== Key Management ====================
    
    def generate_keypair(self) -> KeyPair:
        """
        Generate Ed25519 asymmetric key pair.
        
        Returns:
            KeyPair with public & private keys (32 + 64 bytes each)
            
        Security:
            - Uses cryptography library's secure random
            - Keys are frozen (immutable dataclass)
            - Store private key securely (e.g., encryption at rest)
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        return KeyPair(
            public_key=public_key.public_bytes_raw(),
            private_key=private_key.private_bytes_raw(),
        )
    
    def store_keypair(self, keypair: KeyPair) -> str:
        """
        Store keypair for this thread.
        
        Returns:
            public_key_id (UUID) for reference
        """
        key_id = str(uuid4())
        self._local.keypair = keypair
        self._local.keypair_id = key_id
        # Cache for verification (in production, fetch from secure store)
        self._key_cache[key_id] = keypair
        return key_id
    
    def get_keypair(self) -> Optional[KeyPair]:
        """Retrieve keypair for this thread."""
        return getattr(self._local, 'keypair', None)
    
    def get_public_key_id(self) -> Optional[str]:
        """Get ID of current thread's keypair."""
        return getattr(self._local, 'keypair_id', None)
    
    # ==================== Bearer Token (CapabilityToken) ====================
    
    def issue_token(
        self,
        subject_id: str,
        scope: CapabilityScope = CapabilityScope.READ,
        ttl_seconds: int = 3600,
        issuer_id: str = "system",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> CapabilityToken:
        """
        Issue a new bearer token signed with Ed25519.
        
        Args:
            subject_id: User/service this token authenticates
            scope: Permission level (READ, WRITE, DELETE, ADMIN)
            ttl_seconds: Time-to-live in seconds (default 1 hour)
            issuer_id: Who issued this token
            metadata: Custom metadata (user context, etc)
        
        Returns:
            CapabilityToken with Ed25519 signature
            
        Raises:
            RuntimeError: If no keypair loaded for this thread
            
        Audit:
            - Logs TOKEN_ISSUED event to audit logger
        """
        keypair = self.get_keypair()
        if not keypair:
            raise RuntimeError("No keypair loaded. Call store_keypair() first.")
        
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=ttl_seconds)
        
        token = CapabilityToken(
            token_id=str(uuid4()),
            token_type=TokenType.BEARER,
            issuer_id=issuer_id,
            subject_id=subject_id,
            scope=scope,
            issued_at=now,
            expires_at=expires_at,
            public_key_id=self.get_public_key_id(),
            signature=b'',  # Placeholder, computed below
            metadata=metadata or {},
        )
        
        # Sign the token payload
        payload = token.to_jwt_payload().encode()
        signature = self._sign_payload(keypair.private_key, payload)
        
        # Create signed token
        signed_token = CapabilityToken(
            token_id=token.token_id,
            token_type=token.token_type,
            issuer_id=token.issuer_id,
            subject_id=token.subject_id,
            scope=token.scope,
            issued_at=token.issued_at,
            expires_at=token.expires_at,
            public_key_id=token.public_key_id,
            signature=signature,
            metadata=token.metadata,
        )
        
        # Audit log
        if self.audit_logger:
            from src.apex.audit import AuditEvent, AuditEventSeverity
            event = AuditEvent(
                event_id=str(uuid4()),
                event_type="TOKEN_ISSUED",
                severity=AuditEventSeverity.INFO,
                timestamp=now,
                actor_id=issuer_id,
                action="issue_token",
                resource_type="token",
                resource_id=token.token_id,
                details={
                    "scope": scope.value,
                    "subject_id": subject_id,
                    "expires_at": expires_at.isoformat(),
                }
            )
            self.audit_logger.log_event(event)
        
        return signed_token
    
    def verify_token(
        self,
        token: CapabilityToken,
        now: Optional[datetime] = None,
    ) -> TokenVerificationResult:
        """
        Verify bearer token (signature + expiry + revocation).
        
        Checks:
        1. Signature valid (Ed25519)
        2. Token not expired
        3. Token not revoked
        
        Args:
            token: CapabilityToken to verify
            now: Current time (for testing, default=utcnow)
        
        Returns:
            TokenVerificationResult with validity + reason + violations
            
        Audit:
            - Logs TOKEN_VERIFIED (success) or TOKEN_VERIFICATION_FAILED
        """
        now = now or datetime.utcnow()
        violations = []
        
        # Check 1: Expiry
        if token.is_expired(now):
            violations.append("token_expired")
        
        # Check 2: Revoked
        if self._is_revoked(token.token_id):
            violations.append("token_revoked")
        
        # Check 3: Signature valid
        try:
            keypair = self._key_cache.get(token.public_key_id)
            if not keypair:
                # Fetch from secure store (placeholder)
                violations.append("key_not_found")
            else:
                # Verify signature
                payload = token.to_jwt_payload().encode()
                self._verify_signature(keypair.public_key, payload, token.signature)
        except InvalidSignature:
            violations.append("signature_invalid")
        except Exception as e:
            violations.append(f"signature_error: {str(e)}")
        
        is_valid = len(violations) == 0
        
        # Audit log
        if self.audit_logger:
            from src.apex.audit import AuditEvent, AuditEventSeverity
            event_type = "TOKEN_VERIFIED" if is_valid else "TOKEN_VERIFICATION_FAILED"
            severity = AuditEventSeverity.INFO if is_valid else AuditEventSeverity.WARNING
            event = AuditEvent(
                event_id=str(uuid4()),
                event_type=event_type,
                severity=severity,
                timestamp=now,
                actor_id=token.subject_id,
                action="verify_token",
                resource_type="token",
                resource_id=token.token_id,
                details={"violations": violations}
            )
            self.audit_logger.log_event(event)
        
        return TokenVerificationResult(
            valid=is_valid,
            reason=violations[0] if violations else None,
            token=token if is_valid else None,
            violations=violations,
            verified_at=now,
        )
    
    # ==================== Macaroon (Delegable Token) ====================
    
    def issue_macaroon(
        self,
        subject_id: str,
        scope: CapabilityScope = CapabilityScope.READ,
        issuer_id: str = "system",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Macaroon:
        """
        Issue root macaroon.
        
        The root macaroon can be attenuated by adding caveats.
        Only the issuer can verify it (has the secret key).
        
        Args:
            subject_id: Who this macaroon authenticates
            scope: Permission level
            issuer_id: Who issued
            metadata: Custom metadata
        
        Returns:
            Root Macaroon (with no caveats)
        """
        import hmac
        import hashlib
        
        keypair = self.get_keypair()
        if not keypair:
            raise RuntimeError("No keypair loaded.")
        
        # Create identifier
        identifier = json.dumps({
            "subject_id": subject_id,
            "scope": scope.value,
            "issued_at": datetime.utcnow().isoformat(),
        }, sort_keys=True).encode()
        
        # Create HMAC key
        key = keypair.private_key[:32]  # Use first 32 bytes as HMAC key
        
        # Sign identifier
        signature = hmac.new(key, identifier, hashlib.sha256).digest()
        
        macaroon = Macaroon(
            macaroon_id=str(uuid4()),
            issuer_id=issuer_id,
            subject_id=subject_id,
            scope=scope,
            identifier=identifier,
            key=key,
            signature=signature,
            caveats=[],
            metadata=metadata or {},
        )
        
        # Audit log
        if self.audit_logger:
            from src.apex.audit import AuditEvent, AuditEventSeverity
            event = AuditEvent(
                event_id=str(uuid4()),
                event_type="MACAROON_ISSUED",
                severity=AuditEventSeverity.INFO,
                timestamp=datetime.utcnow(),
                actor_id=issuer_id,
                action="issue_macaroon",
                resource_type="macaroon",
                resource_id=macaroon.macaroon_id,
                details={"scope": scope.value, "subject_id": subject_id}
            )
            self.audit_logger.log_event(event)
        
        return macaroon
    
    def attenuate_macaroon(
        self,
        macaroon: Macaroon,
        caveat: Caveat,
        actor_id: str = "system",
    ) -> Macaroon:
        """
        Attenuate macaroon by adding caveat.
        
        Can be done by anyone (no key needed).
        Creates new macaroon with additional restriction.
        
        Args:
            macaroon: Original macaroon
            caveat: Caveat to add (e.g., time-bound, IP-restrict)
            actor_id: Who is attenuating
        
        Returns:
            New Macaroon with caveat added
            
        Audit:
            - Logs MACAROON_ATTENUATED
        """
        attenuated = macaroon.attenuate(caveat)
        
        # Audit log
        if self.audit_logger:
            from src.apex.audit import AuditEvent, AuditEventSeverity
            event = AuditEvent(
                event_id=str(uuid4()),
                event_type="MACAROON_ATTENUATED",
                severity=AuditEventSeverity.INFO,
                timestamp=datetime.utcnow(),
                actor_id=actor_id,
                action="attenuate_macaroon",
                resource_type="macaroon",
                resource_id=attenuated.macaroon_id,
                details={
                    "parent_macaroon_id": macaroon.macaroon_id,
                    "caveat_type": caveat.caveat_type.value,
                }
            )
            self.audit_logger.log_event(event)
        
        return attenuated
    
    def verify_macaroon(
        self,
        macaroon: Macaroon,
        issuer_key: bytes,
        client_context: Optional[Dict[str, Any]] = None,
        now: Optional[datetime] = None,
    ) -> TokenVerificationResult:
        """
        Verify macaroon (HMAC + caveats).
        
        Checks:
        1. HMAC signature valid
        2. All caveats satisfied
        
        Args:
            macaroon: Macaroon to verify
            issuer_key: Private key of issuer (to verify HMAC)
            client_context: Request context (IP, time, resource, etc)
                For caveat evaluation
            now: Current time (default=utcnow)
        
        Returns:
            TokenVerificationResult
            
        Audit:
            - Logs MACAROON_VERIFIED or MACAROON_VERIFICATION_FAILED
        """
        import hmac
        import hashlib
        
        now = now or datetime.utcnow()
        client_context = client_context or {}
        violations = []
        
        # Check 1: HMAC valid
        try:
            key = issuer_key[:32]
            expected_sig = hmac.new(
                key,
                macaroon.identifier,
                hashlib.sha256
            ).digest()
            if not hmac.compare_digest(expected_sig, macaroon.signature):
                violations.append("hmac_invalid")
        except Exception as e:
            violations.append(f"hmac_error: {str(e)}")
        
        # Check 2: Caveats satisfied
        for caveat in macaroon.caveats:
            caveat_violations = self._check_caveat(caveat, client_context, now)
            violations.extend(caveat_violations)
        
        is_valid = len(violations) == 0
        
        # Audit log
        if self.audit_logger:
            from src.apex.audit import AuditEvent, AuditEventSeverity
            event_type = "MACAROON_VERIFIED" if is_valid else "MACAROON_VERIFICATION_FAILED"
            severity = AuditEventSeverity.INFO if is_valid else AuditEventSeverity.WARNING
            event = AuditEvent(
                event_id=str(uuid4()),
                event_type=event_type,
                severity=severity,
                timestamp=now,
                actor_id=macaroon.subject_id,
                action="verify_macaroon",
                resource_type="macaroon",
                resource_id=macaroon.macaroon_id,
                details={"violations": violations}
            )
            self.audit_logger.log_event(event)
        
        return TokenVerificationResult(
            valid=is_valid,
            reason=violations[0] if violations else None,
            macaroon=macaroon if is_valid else None,
            violations=violations,
            verified_at=now,
        )
    
    # ==================== Revocation ====================
    
    def revoke_token(
        self,
        token_id: str,
        reason: str = "user_logout",
        revoked_by: str = "system",
    ) -> RevocationEntry:
        """
        Revoke a token immediately.
        
        Args:
            token_id: ID of token to revoke
            reason: Why revoked (logout, compromise, permission_change, etc)
            revoked_by: Who revoked (user, admin, system)
        
        Returns:
            RevocationEntry
            
        Audit:
            - Logs TOKEN_REVOKED
        """
        now = datetime.utcnow()
        entry = RevocationEntry(
            token_id=token_id,
            revoked_at=now,
            revocation_reason=reason,
            revoked_by=revoked_by,
        )
        
        with self._revocation_lock:
            self._revocation_list[token_id] = entry
        
        # Audit log
        if self.audit_logger:
            from src.apex.audit import AuditEvent, AuditEventSeverity
            event = AuditEvent(
                event_id=str(uuid4()),
                event_type="TOKEN_REVOKED",
                severity=AuditEventSeverity.INFO,
                timestamp=now,
                actor_id=revoked_by,
                action="revoke_token",
                resource_type="token",
                resource_id=token_id,
                details={"reason": reason}
            )
            self.audit_logger.log_event(event)
        
        return entry
    
    def _is_revoked(self, token_id: str) -> bool:
        """Check if token is in revocation list."""
        with self._revocation_lock:
            return token_id in self._revocation_list
    
    def get_revocation_list(self) -> Dict[str, RevocationEntry]:
        """Get all revoked tokens."""
        with self._revocation_lock:
            return dict(self._revocation_list)
    
    # ==================== Crypto Primitives ====================
    
    @staticmethod
    def _sign_payload(private_key_bytes: bytes, payload: bytes) -> bytes:
        """
        Sign payload with Ed25519 private key.
        
        Args:
            private_key_bytes: 64-byte Ed25519 private key
            payload: Data to sign
        
        Returns:
            64-byte Ed25519 signature
        """
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        return private_key.sign(payload)
    
    @staticmethod
    def _verify_signature(public_key_bytes: bytes, payload: bytes, signature: bytes) -> None:
        """
        Verify Ed25519 signature.
        
        Args:
            public_key_bytes: 32-byte Ed25519 public key
            payload: Data that was signed
            signature: 64-byte Ed25519 signature
        
        Raises:
            InvalidSignature: If signature doesn't match
        """
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, payload)
    
    @staticmethod
    def _check_caveat(
        caveat: Caveat,
        client_context: Dict[str, Any],
        now: datetime,
    ) -> List[str]:
        """
        Check if caveat is satisfied by client context.
        
        Returns:
            List of violations (empty if satisfied)
        """
        violations = []
        
        if caveat.caveat_type == CaveatType.TIME_BOUND:
            expiry_str = caveat.conditions.get("expiry")
            expiry = datetime.fromisoformat(expiry_str)
            if now >= expiry:
                violations.append(f"caveat_time_bound_expired: {expiry_str}")
        
        elif caveat.caveat_type == CaveatType.IP_RESTRICT:
            allowed_ips = caveat.conditions.get("allowed_ips", [])
            client_ip = client_context.get("client_ip")
            if client_ip and client_ip not in allowed_ips:
                violations.append(f"caveat_ip_restrict_violation: {client_ip} not in {allowed_ips}")
        
        elif caveat.caveat_type == CaveatType.RESOURCE_BOUND:
            resource_id = caveat.conditions.get("resource_id")
            requested_resource = client_context.get("resource_id")
            if requested_resource and requested_resource != resource_id:
                violations.append(f"caveat_resource_bound_violation: {requested_resource} != {resource_id}")
        
        elif caveat.caveat_type == CaveatType.ACTION_LIMIT:
            max_actions = caveat.conditions.get("max_actions", 1)
            actions_performed = client_context.get("actions_performed", 0)
            if actions_performed >= max_actions:
                violations.append(f"caveat_action_limit_exceeded: {actions_performed} >= {max_actions}")
        
        elif caveat.caveat_type == CaveatType.RATE_LIMIT:
            ops_per_minute = caveat.conditions.get("ops_per_minute", 60)
            ops_this_minute = client_context.get("ops_this_minute", 0)
            if ops_this_minute >= ops_per_minute:
                violations.append(f"caveat_rate_limit_exceeded: {ops_this_minute} >= {ops_per_minute}")
        
        # Custom caveats can be added here
        
        return violations
