//! Secure API middleware chain
//!
//! Integrates ALICE-Auth (Ed25519 ZKP) and ALICE-Crypto (XChaCha20-Poly1305)
//! into the gateway pipeline as optional feature-gated middleware.
//!
//! ## Pipeline
//!
//! ```text
//! Client Request → ALICE-API (GCRA rate limit)
//!                      ↓
//!                 ALICE-Auth (Ed25519 signature verify)
//!                      ↓
//!                 ALICE-Crypto (XChaCha20-Poly1305 decrypt)
//!                      ↓
//!                 Backend Service
//! ```

#[cfg(all(feature = "auth", feature = "crypto"))]
use crate::gateway::{
    Backend, Gateway, GatewayConfig, GatewayDecision, GatewayRequest, GatewayStats, Route,
};
#[cfg(all(feature = "auth", feature = "crypto"))]
use crate::sfq::SfqStats;

// ============================================================================
// Auth Middleware (feature = "auth")
// ============================================================================

/// Re-export core auth types
#[cfg(feature = "auth")]
pub use alice_auth::{AliceId, AliceSig};

/// Authentication context extracted from request headers.
///
/// Contains the client's Ed25519 public key and a signature
/// over the request message (e.g., method + path).
#[cfg(feature = "auth")]
#[derive(Clone, Copy)]
pub struct AuthContext {
    /// Client's Ed25519 public key
    pub id: AliceId,
    /// Signature over the request message
    pub sig: AliceSig,
}

#[cfg(feature = "auth")]
impl AuthContext {
    /// Create from raw byte arrays
    #[inline(always)]
    pub fn new(id: [u8; 32], sig: [u8; 64]) -> Self {
        Self {
            id: AliceId::new(id),
            sig: AliceSig::new(sig),
        }
    }

    /// Verify the signature against the given message.
    ///
    /// The message should match what the client signed (typically method + path).
    #[inline(always)]
    pub fn verify(&self, message: &[u8]) -> bool {
        alice_auth::ok(&self.id, message, &self.sig)
    }
}

// ============================================================================
// Crypto Middleware (feature = "crypto")
// ============================================================================

/// Re-export core crypto types
#[cfg(feature = "crypto")]
pub use alice_crypto::stream::{CipherError, Key, Nonce, TAG_SIZE};

/// Decrypt request body in-place (zero allocation).
///
/// Buffer must contain `[ciphertext][16-byte Poly1305 auth tag]`.
/// Returns plaintext length on success.
#[cfg(feature = "crypto")]
#[inline(always)]
pub fn decrypt_body(key: &Key, nonce: &Nonce, buffer: &mut [u8]) -> Result<usize, CipherError> {
    alice_crypto::decrypt_in_place(key, nonce, buffer)
}

/// Decrypt request body in-place with associated data.
///
/// AAD is authenticated but not encrypted — use for binding
/// ciphertext to request metadata (path, method, etc.).
#[cfg(feature = "crypto")]
#[inline(always)]
pub fn decrypt_body_aead(
    key: &Key,
    nonce: &Nonce,
    buffer: &mut [u8],
    aad: &[u8],
) -> Result<usize, CipherError> {
    alice_crypto::decrypt_in_place_aead(key, nonce, buffer, aad)
}

// ============================================================================
// Secure Gateway (feature = "secure" = auth + crypto)
// ============================================================================

/// Secure API Gateway combining rate limiting, Ed25519 auth, and XChaCha20-Poly1305 encryption.
///
/// Wraps the base `Gateway` and inserts auth verification between
/// rate limiting and routing.
///
/// ## Pipeline
///
/// - `process()`: rate limit → **auth** → route → forward
/// - `process_encrypted()`: rate limit → **auth** → route → **decrypt** → forward
#[cfg(all(feature = "auth", feature = "crypto"))]
pub struct SecureGateway<
    const RATE_SLOTS: usize,
    const SFQ_QUEUES: usize,
    const SFQ_DEPTH: usize,
    const MAX_ROUTES: usize,
    const MAX_BACKENDS: usize,
> {
    inner: Gateway<RATE_SLOTS, SFQ_QUEUES, SFQ_DEPTH, MAX_ROUTES, MAX_BACKENDS>,
    secure_stats: SecureStats,
}

/// Statistics for auth/crypto middleware
#[cfg(all(feature = "auth", feature = "crypto"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct SecureStats {
    pub auth_failures: u64,
    pub decrypt_failures: u64,
}

#[cfg(all(feature = "auth", feature = "crypto"))]
impl<
        const RATE_SLOTS: usize,
        const SFQ_QUEUES: usize,
        const SFQ_DEPTH: usize,
        const MAX_ROUTES: usize,
        const MAX_BACKENDS: usize,
    > SecureGateway<RATE_SLOTS, SFQ_QUEUES, SFQ_DEPTH, MAX_ROUTES, MAX_BACKENDS>
{
    /// Create a new secure gateway
    pub fn new(config: GatewayConfig) -> Self {
        Self {
            inner: Gateway::new(config),
            secure_stats: SecureStats::default(),
        }
    }

    /// Add a backend server
    pub fn add_backend(&mut self, backend: Backend) -> Option<u32> {
        self.inner.add_backend(backend)
    }

    /// Add a routing rule
    pub fn add_route(&mut self, route: Route) -> bool {
        self.inner.add_route(route)
    }

    /// Process request through: rate limit → auth → route → forward.
    ///
    /// `sign_message` is the data the client signed (e.g., `b"GET /api/users"`).
    /// Auth is checked after rate limiting to avoid wasting CPU on
    /// Ed25519 verification for rate-limited clients.
    pub fn process(
        &mut self,
        request: &GatewayRequest,
        auth: &AuthContext,
        sign_message: &[u8],
    ) -> GatewayDecision {
        // 1. Payload size + rate limit + route (delegate to inner)
        let decision = self.inner.process(request);

        // Only verify auth if inner gateway would forward
        match decision {
            GatewayDecision::Forward { .. } => {}
            other => return other,
        }

        // 2. Auth check
        if !auth.verify(sign_message) {
            self.secure_stats.auth_failures += 1;
            return GatewayDecision::Unauthorized;
        }

        decision
    }

    /// Process encrypted request: rate limit → auth → route → decrypt → forward.
    ///
    /// Body is decrypted in-place on success. Returns the gateway decision
    /// and the plaintext length (if decryption succeeded).
    pub fn process_encrypted(
        &mut self,
        request: &GatewayRequest,
        auth: &AuthContext,
        sign_message: &[u8],
        key: &Key,
        nonce: &Nonce,
        body: &mut [u8],
    ) -> (GatewayDecision, Option<usize>) {
        // 1. Rate limit + route
        let decision = self.inner.process(request);
        match decision {
            GatewayDecision::Forward { .. } => {}
            other => return (other, None),
        }

        // 2. Auth
        if !auth.verify(sign_message) {
            self.secure_stats.auth_failures += 1;
            return (GatewayDecision::Unauthorized, None);
        }

        // 3. Decrypt body
        match decrypt_body(key, nonce, body) {
            Ok(plaintext_len) => (decision, Some(plaintext_len)),
            Err(_) => {
                self.secure_stats.decrypt_failures += 1;
                (GatewayDecision::DecryptFailed, None)
            }
        }
    }

    /// Get base gateway statistics
    pub fn gateway_stats(&self) -> GatewayStats {
        self.inner.stats()
    }

    /// Get auth/crypto middleware statistics
    pub fn secure_stats(&self) -> SecureStats {
        self.secure_stats
    }

    /// Get queue statistics
    pub fn queue_stats(&self) -> SfqStats {
        self.inner.queue_stats()
    }

    /// Generate next request ID
    pub fn next_request_id(&mut self) -> u64 {
        self.inner.next_request_id()
    }

    /// Mark backend as unhealthy
    pub fn mark_unhealthy(&mut self, backend_id: u32) {
        self.inner.mark_unhealthy(backend_id);
    }

    /// Mark backend as healthy
    pub fn mark_healthy(&mut self, backend_id: u32) {
        self.inner.mark_healthy(backend_id);
    }

    /// Access the inner gateway
    pub fn inner(&self) -> &Gateway<RATE_SLOTS, SFQ_QUEUES, SFQ_DEPTH, MAX_ROUTES, MAX_BACKENDS> {
        &self.inner
    }

    /// Access the inner gateway mutably
    pub fn inner_mut(
        &mut self,
    ) -> &mut Gateway<RATE_SLOTS, SFQ_QUEUES, SFQ_DEPTH, MAX_ROUTES, MAX_BACKENDS> {
        &mut self.inner
    }
}

// ============================================================================
// Convenience type aliases
// ============================================================================

#[cfg(all(feature = "auth", feature = "crypto"))]
pub type DefaultSecureGateway = SecureGateway<1024, 32, 64, 64, 16>;

#[cfg(all(feature = "auth", feature = "crypto"))]
pub type EdgeSecureGateway = SecureGateway<256, 16, 32, 16, 8>;

#[cfg(all(feature = "auth", feature = "crypto"))]
pub type TestSecureGateway = SecureGateway<64, 8, 16, 8, 4>;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "auth")]
    #[test]
    fn test_auth_verify() {
        let identity = alice_auth::Identity::gen().unwrap();
        let message = b"GET /api/users";
        let ctx = AuthContext {
            id: identity.id(),
            sig: identity.sign(message),
        };
        assert!(ctx.verify(message));
        assert!(!ctx.verify(b"tampered"));
    }

    #[cfg(feature = "auth")]
    #[test]
    fn test_auth_context_from_bytes() {
        let identity = alice_auth::Identity::gen().unwrap();
        let message = b"POST /api/data";
        let sig = identity.sign(message);
        let ctx = AuthContext::new(identity.id().into_bytes(), sig.into_bytes());
        assert!(ctx.verify(message));
    }

    #[cfg(feature = "auth")]
    #[test]
    fn test_auth_wrong_signer() {
        let alice = alice_auth::Identity::gen().unwrap();
        let bob = alice_auth::Identity::gen().unwrap();
        let message = b"GET /secret";
        // Alice signs, but we claim it's from Bob
        let ctx = AuthContext {
            id: bob.id(),
            sig: alice.sign(message),
        };
        assert!(!ctx.verify(message));
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_decrypt_body_roundtrip() {
        let key = Key::generate().unwrap();
        let nonce = Nonce::generate().unwrap();
        let plaintext = b"request body content";
        let pt_len = plaintext.len();

        let mut buffer = [0u8; 128];
        buffer[..pt_len].copy_from_slice(plaintext);
        let ct_len =
            alice_crypto::encrypt_in_place(&key, &nonce, &mut buffer[..pt_len + TAG_SIZE], pt_len)
                .unwrap();

        let result_len = decrypt_body(&key, &nonce, &mut buffer[..ct_len]).unwrap();
        assert_eq!(result_len, pt_len);
        assert_eq!(&buffer[..result_len], plaintext);
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_decrypt_body_wrong_key() {
        let key1 = Key::generate().unwrap();
        let key2 = Key::generate().unwrap();
        let nonce = Nonce::generate().unwrap();
        let plaintext = b"secret";
        let pt_len = plaintext.len();

        let mut buffer = [0u8; 128];
        buffer[..pt_len].copy_from_slice(plaintext);
        let ct_len =
            alice_crypto::encrypt_in_place(&key1, &nonce, &mut buffer[..pt_len + TAG_SIZE], pt_len)
                .unwrap();

        assert!(decrypt_body(&key2, &nonce, &mut buffer[..ct_len]).is_err());
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_decrypt_body_aead_roundtrip() {
        let key = Key::generate().unwrap();
        let nonce = Nonce::generate().unwrap();
        let plaintext = b"aead body";
        let aad = b"GET /api/data";
        let pt_len = plaintext.len();

        let mut buffer = [0u8; 128];
        buffer[..pt_len].copy_from_slice(plaintext);
        let ct_len = alice_crypto::encrypt_in_place_aead(
            &key,
            &nonce,
            &mut buffer[..pt_len + TAG_SIZE],
            pt_len,
            aad,
        )
        .unwrap();

        let result_len = decrypt_body_aead(&key, &nonce, &mut buffer[..ct_len], aad).unwrap();
        assert_eq!(result_len, pt_len);
        assert_eq!(&buffer[..result_len], plaintext);
    }

    #[cfg(all(feature = "auth", feature = "crypto"))]
    #[test]
    fn test_secure_gateway_forward() {
        use crate::routing::HttpMethod;

        let mut gw = TestSecureGateway::new(GatewayConfig::default());
        gw.add_backend(Backend::new(1, b"127.0.0.1", 8080));
        let mut route = Route::new(b"/api/");
        route.add_backend(1);
        gw.add_route(route);

        let identity = alice_auth::Identity::gen().unwrap();
        let sign_msg = b"GET /api/users";
        let auth = AuthContext {
            id: identity.id(),
            sig: identity.sign(sign_msg),
        };

        let mut path = [0u8; 256];
        path[..10].copy_from_slice(b"/api/users");
        let request = GatewayRequest {
            client_hash: 12345,
            request_id: 1,
            method: HttpMethod::Get,
            path,
            path_len: 10,
            content_length: 0,
            header_size: 100,
            timestamp_ns: 0,
        };

        let decision = gw.process(&request, &auth, sign_msg);
        assert!(matches!(decision, GatewayDecision::Forward { backend_id: 1 }));
    }

    #[cfg(all(feature = "auth", feature = "crypto"))]
    #[test]
    fn test_secure_gateway_unauthorized() {
        use crate::routing::HttpMethod;

        let mut gw = TestSecureGateway::new(GatewayConfig::default());
        gw.add_backend(Backend::new(1, b"127.0.0.1", 8080));
        let mut route = Route::new(b"/");
        route.add_backend(1);
        gw.add_route(route);

        let identity = alice_auth::Identity::gen().unwrap();
        let auth = AuthContext {
            id: identity.id(),
            sig: identity.sign(b"wrong message"),
        };

        let mut path = [0u8; 256];
        path[0] = b'/';
        let request = GatewayRequest {
            client_hash: 12345,
            request_id: 1,
            method: HttpMethod::Get,
            path,
            path_len: 1,
            content_length: 0,
            header_size: 100,
            timestamp_ns: 0,
        };

        let decision = gw.process(&request, &auth, b"GET /");
        assert_eq!(decision, GatewayDecision::Unauthorized);
        assert_eq!(gw.secure_stats().auth_failures, 1);
    }

    #[cfg(all(feature = "auth", feature = "crypto"))]
    #[test]
    fn test_secure_gateway_encrypted_pipeline() {
        use crate::routing::HttpMethod;

        let mut gw = TestSecureGateway::new(GatewayConfig::default());
        gw.add_backend(Backend::new(1, b"127.0.0.1", 8080));
        let mut route = Route::new(b"/");
        route.add_backend(1);
        gw.add_route(route);

        // Identity + encryption keys
        let identity = alice_auth::Identity::gen().unwrap();
        let key = Key::generate().unwrap();
        let nonce = Nonce::generate().unwrap();

        let sign_msg = b"POST /";
        let auth = AuthContext {
            id: identity.id(),
            sig: identity.sign(sign_msg),
        };

        // Encrypt body
        let plaintext = b"encrypted payload";
        let pt_len = plaintext.len();
        let mut body = [0u8; 128];
        body[..pt_len].copy_from_slice(plaintext);
        let ct_len =
            alice_crypto::encrypt_in_place(&key, &nonce, &mut body[..pt_len + TAG_SIZE], pt_len)
                .unwrap();

        let mut path = [0u8; 256];
        path[0] = b'/';
        let request = GatewayRequest {
            client_hash: 12345,
            request_id: 1,
            method: HttpMethod::Post,
            path,
            path_len: 1,
            content_length: ct_len,
            header_size: 100,
            timestamp_ns: 0,
        };

        let (decision, plaintext_len) =
            gw.process_encrypted(&request, &auth, sign_msg, &key, &nonce, &mut body[..ct_len]);
        assert!(matches!(decision, GatewayDecision::Forward { backend_id: 1 }));
        assert_eq!(plaintext_len, Some(pt_len));
        assert_eq!(&body[..pt_len], plaintext);
    }

    #[cfg(all(feature = "auth", feature = "crypto"))]
    #[test]
    fn test_secure_gateway_decrypt_failure() {
        use crate::routing::HttpMethod;

        let mut gw = TestSecureGateway::new(GatewayConfig::default());
        gw.add_backend(Backend::new(1, b"127.0.0.1", 8080));
        let mut route = Route::new(b"/");
        route.add_backend(1);
        gw.add_route(route);

        let identity = alice_auth::Identity::gen().unwrap();
        let key = Key::generate().unwrap();
        let wrong_key = Key::generate().unwrap();
        let nonce = Nonce::generate().unwrap();

        let sign_msg = b"POST /";
        let auth = AuthContext {
            id: identity.id(),
            sig: identity.sign(sign_msg),
        };

        // Encrypt with key, try to decrypt with wrong_key
        let plaintext = b"secret data";
        let pt_len = plaintext.len();
        let mut body = [0u8; 128];
        body[..pt_len].copy_from_slice(plaintext);
        let ct_len =
            alice_crypto::encrypt_in_place(&key, &nonce, &mut body[..pt_len + TAG_SIZE], pt_len)
                .unwrap();

        let mut path = [0u8; 256];
        path[0] = b'/';
        let request = GatewayRequest {
            client_hash: 12345,
            request_id: 1,
            method: HttpMethod::Post,
            path,
            path_len: 1,
            content_length: ct_len,
            header_size: 100,
            timestamp_ns: 0,
        };

        let (decision, plaintext_len) = gw.process_encrypted(
            &request,
            &auth,
            sign_msg,
            &wrong_key,
            &nonce,
            &mut body[..ct_len],
        );
        assert_eq!(decision, GatewayDecision::DecryptFailed);
        assert_eq!(plaintext_len, None);
        assert_eq!(gw.secure_stats().decrypt_failures, 1);
    }
}
