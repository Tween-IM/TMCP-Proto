# TMCP Protocol Changelog

All notable changes to Tween Mini-App Communication Protocol (TMCP) will be documented in this file.

## [1.5.0] - 2025-12-31

### Changed

- **Complete Migration from Keycloak to Matrix Authentication Service (MAS)**
  - Replaced Section 16.10 OAuth Server Implementation with MAS-based architecture
  - Updated all authentication flows to use MAS as OAuth 2.0 authorization server
  - Added Device Authorization Grant (RFC 8628) as recommended flow for mini-apps
  - Added Authorization Code Flow with PKCE (RFC 7636) for web mini-apps
  - Removed all Keycloak-specific configuration and references
  - Integrated MAS client credentials for TMCP Server operations

- **Section 4: Identity and Authentication (Complete Rewrite)**
  - Implemented dual-token architecture: TEP Token (JWT) + MAS Access Token
  - TEP Token: Long-lived JWT for TMCP-specific operations with custom claims
  - MAS Access Token: Short-lived (5 min), memory-only, automatic refresh
  - Added comprehensive client-side token management for iOS, Android, and web
  - Added TEP token structure with MAS session reference claims
  - Added TMCP Server authentication middleware implementation
  - Added MAS integration requirements with client registration

- **Section 3.1.2: TMCP Server Architecture (Enhanced)**
  - Added detailed server component architecture diagram
  - Added MAS Client configuration and token management
  - Added TMCP Server OAuth 2.0 token endpoint implementation
  - Clarified Application Service role in Matrix event sending

- **Section 5: Authorization Framework (Updated)**
  - Separated TMCP Scopes from Matrix Scopes
  - Added Matrix scope definitions per MSC2967
  - Updated scope request format to include both scope types
  - Added scope mapping table for TMCP and Matrix operations

- **Appendix A: Complete Protocol Flow Example (Updated)**
  - Rewrote to reflect MAS authentication flow
  - Added Device Authorization Grant steps
  - Updated payment flow to show TEP + AS token architecture
  - Added visual in-chat payment receipt rendering example

### Added

- **Section 4.11: In-Chat Payment Architecture**
  - Added virtual payment bot user (`@_tmcp_payments:tween.example`)
  - Defined payment event types (`m.tween.payment.*`)
  - Added rich payment event structure for client rendering
  - Added third-party wallet integration via webhooks
  - Added payment event idempotency handling
  - Added client rendering requirements for payment cards

- **Section 4.7: MAS Integration Requirements**
  - Added TMCP Server client registration in MAS
  - Added mini-app client registration in MAS
  - Added scope definitions for Matrix API access

### Security

- **Enhanced Token Security**
  - Memory-only storage for MAS access tokens prevents XSS theft
  - Clear separation between TMCP and Matrix authentication
  - Automatic token refresh reduces client complexity
  - Virtual payment bot prevents user impersonation in Matrix events

- **Webhook Security**
  - Added signature verification for third-party wallet callbacks
  - Defined callback payload structure with transaction details

### Removed

- All Keycloak-specific OAuth server implementation
- Keycloak realm configuration examples
- Keycloak client registration documentation
- Keycloak MFA integration references

## [1.4.0] - 2025-12-28

### Added
- **Section 10.4: WebView Security Requirements**
  - Mandatory security controls for mini-app sandboxing
  - Content Security Policy requirements and validation
  - JavaScript bridge security with postMessage validation
  - URL validation and sensitive data protection
  - Certificate pinning and lifecycle management

- **Section 10.5: Capability Negotiation**
  - Feature detection API for mini-app platform capabilities
  - Standardized capability categories (camera, location, payment, storage, etc.)
  - Server-side validation and rate limiting
  - Graceful degradation for unsupported features

- **Section 7.7: Circuit Breaker Pattern for Payment Failures**
  - Resilience pattern for Wallet Service outages
  - Configurable failure thresholds and recovery timeouts
  - Circuit states: CLOSED, OPEN, HALF_OPEN
  - Metrics exposure for monitoring

- **Section 9.3: Mini-App Review Process**
  - Automated security checks for CSP, HTTPS, credentials
  - Manual review criteria for permissions, content, and business validation
  - Review timeline and appeal process
  - Multi-tier classification (official, verified, community, beta)

- **Enhanced Section 4.3.1: JWT Security Requirements**
  - Algorithm whitelist validation (RS256, RS384, RS512)
  - Not-before claim (nbf) validation
  - Token type claim for explicit typing
  - Issuer and audience validation

- **Enhanced Section 6.4: Wallet Verification Interface**
  - Protocol-defined verification status endpoint
  - Standardized response format for verification levels
  - Clear separation between protocol interface and Wallet Service implementation

- **Enhanced Section 7.5.6: Group Gift Atomicity**
  - Database-level locking for concurrent gift opening
  - PostgreSQL SELECT FOR UPDATE implementation
  - Race condition prevention and error handling

- **Enhanced Section 11.4: Rate Limiting**
  - Per-endpoint rate limits with token bucket algorithm
  - Distributed rate limiting for multi-instance deployments
  - Account suspension for abuse patterns
  - Enhanced response headers and error codes

### Changed
- **Federation Terminology**: Standardized "controlled federation environments" throughout document
- **Section Numbering**: Fixed numbering conflicts (WebView moved to 10.4, Capability to 10.5, MFA to 7.6, Circuit Breaker to 7.7)
- **Document Metadata**: Updated date to December 2025, changed identifier to TMCP-001

### Security
- **WebView Hardening**: Comprehensive security requirements for mini-app execution environments
- **JWT Validation**: Enhanced token security with algorithm whitelisting and claim validation
- **Circuit Breaker Protection**: Automatic service degradation handling for payment operations

### Documentation
- **Appendix C: WebView Implementation Details**: Moved detailed platform-specific implementations from main spec
- **Appendix D: Webhook Signature Verification**: Moved from Appendix C
- **Table of Contents**: Updated with corrected section numbering and appendix references

## [1.3.0] - 2025-12-20

### Added
- **Section 7.2.3: Recipient Acceptance Protocol**
  - Added two-step confirmation pattern for P2P transfers
  - Defined acceptance flow with 24-hour window
  - Added accept/reject endpoints for recipients
  - Implemented auto-expiry with refund mechanism
  - Added Matrix events for pending acceptance and status updates

- **Section 7.5: Group Gift Distribution Protocol**
  - Added culturally relevant gamified gifting alternative
  - Defined individual and group gift creation flows
  - Implemented random and equal distribution algorithms
  - Added gift opening protocol with leaderboard
  - Created Matrix events for gift creation and opening

- **Updated Section 7.1: Payment State Machine**
  - Added P2P transfer states with recipient acceptance
  - Added group gift states (created → active → opened)
  - Updated state transitions to reflect new flows

- **Updated Section 8.1: New Matrix Event Types**
  - Added m.tween.wallet.p2p.status for transfer updates
  - Added m.tween.gift and m.tween.gift.opened for group gifts
  - Added m.tween.wallet.invite for wallet invitations

- **Updated Section 10.2: New JSON-RPC Methods**
  - Added tween.wallet.sendGift for creating group gifts
  - Added tween.wallet.openGift for opening received gifts
  - Added tween.wallet.acceptTransfer and tween.wallet.rejectTransfer

- **Updated Section 12.2: Additional Error Codes**
  - Added RECIPIENT_NO_WALLET, RECIPIENT_ACCEPTANCE_REQUIRED
  - Added TRANSFER_EXPIRED, GIFT_EXPIRED

- **Updated Section 6.2.1: Verification Tiers**
  - Added verification tier information to balance responses
  - Defined tier requirements and corresponding limits
  - Added upgrade path for enhanced features

## [1.2.0] - 2025-12-19

### Added
- **Section 7.4: Multi-Factor Authentication for Payments**
  - Added MFA challenge-response mechanism for payment authorization
  - Defined standard MFA method types (transaction_pin, biometric, totp)
  - Added device registration protocol for biometric MFA
  - Updated payment state machine to include MFA_REQUIRED state
  - Added Wallet Service MFA interface requirements

- **Section 10.3: Mini-App Storage System**
  - Added key-value storage protocol for mini-apps
  - Defined storage quotas (10MB per user/app, 1MB per key, 1000 keys)
  - Added offline storage support with conflict resolution
  - Implemented batch operations for efficiency
  - Added storage scopes (storage:read, storage:write) with auto-approval

- **Section 8.1.4: App Lifecycle Events**
  - Added Matrix events for app installation, updates, and uninstallation
  - Defined event formats for lifecycle tracking

- **Section 16: Official and Preinstalled Mini-Apps**
  - Added mini-app classification system (official, verified, community, beta)
  - Defined preinstallation manifest format and loading process
  - Added internal URL scheme (tween-internal://) for official apps
  - Implemented mini-app store protocol with discovery and installation
  - Added app ranking algorithm and trending detection
  - Defined privileged scopes for official apps
  - Added update management protocol with verification requirements
  - Modified OAuth flow for official apps to use PKCE with pre-approved basic scopes

- **Section 11.4.1: Rate Limiting Implementation Guidance**
  - Added required rate limit headers (X-RateLimit-*)
  - Defined token bucket/sliding window algorithm recommendation
  - Added 429 status code with retry_after header

- **Section 12.2: Additional Error Codes**
  - Added MFA_REQUIRED, MFA_LOCKED, INVALID_MFA_CREDENTIALS
  - Added STORAGE_QUOTA_EXCEEDED, APP_NOT_REMOVABLE, APP_NOT_FOUND, DEVICE_NOT_REGISTERED

### Security Enhancements
- Biometric attestation for MFA using device-bound keys
- Enhanced token security for official apps
- Audit logging requirements for privileged operations

### Implementation Guidance
- Added Section 16.10: OAuth Server Implementation with Keycloak
  - Comprehensive Keycloak realm configuration
  - Client registration process for mini-apps
  - Token service configuration with JWT signing
  - MFA service integration details

### Documentation
- Added Appendix D: Protocol Change Log for tracking evolution
- Updated Table of Contents to reflect new Section numbering

---

## [Unreleased] - Future

### Planned
- GraphQL API alternative to REST endpoints
- WebSocket support for real-time mini-app communication
- Advanced fraud detection and prevention mechanisms
- Cross-platform mini-app packaging and distribution

---

## Format

This changelog follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format with modifications for TMCP protocol's specific needs.

### Types of Changes
- `Added` for new features
- `Changed` for modifications to existing features
- `Deprecated` for removed features
- `Security` for security-related changes
- `Documentation` for documentation updates