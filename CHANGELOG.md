# TMCP Protocol Changelog

All notable changes to Tween Mini-App Communication Protocol (TMCP) will be documented in this file.

## [1.7.0] - 2026-01-16

### Added

- **Developer Authentication and Enrollment (Section 4.4)**
  - Added comprehensive developer enrollment flow using Matrix authentication
  - Defined Developer Token (DEVELOPER_TOKEN) structure as JWT with developer claims
  - Added developer token issuance, refresh, and logout endpoints
  - Added organization management for team-based development
  - Added role-based access control (RBAC) with admin, developer, and viewer roles
  - Added developer whitelist management for security
  - Updated Section 9.1 Registration to reference developer enrollment as prerequisite
  - Added Section 4.4.9 Developer Console Authentication
    - Clarified that Developer Console is NOT a mini-app
    - Explained Developer Console uses platform service credentials configured during deployment
    - Documented distinction between platform services and mini-apps
    - Resolved chicken-and-egg problem for developer console registration
    - Added security considerations for platform service credentials

- **Hybrid Client Support for Mini-Apps with Frontend and Backend**
  - Added `hybrid` client type to support mini-apps with both WebView frontend and backend server
  - Hybrid clients receive two sets of credentials: public client (frontend) and confidential client (backend)
  - Updated mini-app registration (Section 9.1.1) to support hybrid client type
  - Added hybrid client registration request/response examples
  - Added client type comparison table for public, confidential, and hybrid clients

- **Webhook Delivery Specification for Hybrid Clients**
  - Added Section 9.1.2 with comprehensive webhook delivery documentation
  - Defined webhook event types (payment.completed, payment.failed, payment.refunded, scope.revoked, wallet.updated)
  - Specified webhook delivery requirements (signature verification, reliable delivery, idempotency)
  - Added webhook request format with security headers
  - Added backend client authentication for webhook operations
  - Added webhook error handling table and security best practices

### Fixed

- **Security: Removed client_secret requirement from public client authentication flows**
  - Removed `client_secret` from Matrix Session Delegation flow (Section 4.3.1)
  - Removed `client_secret` from Device Authorization Grant (Section 4.3.2)
  - Removed `client_secret` from Authorization Code Grant with PKCE (Section 4.3.3)
   - Updated TEP Token Issuance Requirements to distinguish public vs confidential clients (Section 4.10)
   - Updated mini-app registration to support both public and confidential client types (Section 9.1.1)
   - Updated MAS client registration tables to support public clients (Sections 4.13, 16.10)

### Changed

- **MAS Client Registration for Hybrid Clients**
  - Updated Section 4.13 to document dual-client registration for hybrid type
  - Updated Section 16.10 with MAS configuration for hybrid clients
  - Both frontend and backend clients share same mini-app registration and scope permissions

### Security

- **OAuth 2.0 Public Client Support**: Protocol now properly supports OAuth 2.0 public clients (browser/mobile apps) that cannot securely store secrets
  - Public clients use PKCE or Matrix token introspection for authentication
  - Confidential clients (backend servers) can still use client_secret for enhanced security
  - Hybrid clients combine both approaches for complete mini-app ecosystem
  - Mini-app registration includes `client_type` parameter to specify authentication method
  - Prevents security exposure of secrets in frontend code

- **Webhook Security**: Enhanced webhook delivery with HMAC-SHA256 signature verification
  - All webhooks include `X-Webhook-Signature` header for authenticity
  - Timestamp validation prevents replay attacks
  - Idempotency handling prevents duplicate processing
  - Reliable delivery with exponential backoff retry mechanism

## [1.6.1] - 2025-01-14

### Fixed

- **RFC Compliance: Removed Implementation Code from Main Specification**
  - Removed YAML configuration examples from Sections 3.1.2, 4.3.1, 4.11.2, and 10.4.2
  - Removed TypeScript client implementation code from Section 6.3.9
  - Replaced configuration examples with requirements tables per RFC standards

- **RFC Compliance: Fixed Marketing Language**
  - Verified no marketing terms remain (seamless, super-app, best-in-class, etc.)
  - All replaced with technical specification language

- **Document Structure: Fixed Section Numbering**
  - Fixed broken Table of Contents (sections 5-6 were swapped)
  - Removed malformed "## 17. Appendices" fragment at incorrect location
  - Corrected misnumbered "## 5" to "## 6. Wallet Integration Layer"
  - Verified all sections 1-17 are in correct order

### Changed

- **Requirements Tables**: Converted YAML configuration to requirement tables with |Parameter|Required|Description| format

## [1.6.0] - 2025-01-10

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

## [1.6.0] - 2025-12-21

### RFC Compliance - Complete Document Cleanup

This release represents a **comprehensive RFC compliance overhaul** of the TMCP specification, addressing all implementation code and marketing language issues throughout the document.

---

### Section 3 - Protocol Architecture

#### 3.1.2: TMCP Server Configuration
- **Removed**: Python `MASClientConfig` class implementation
- **Removed**: Python `token_endpoint` function implementation
- **Replaced with**: Behavioral configuration requirements table
- **Replaced with**: TEP Token Issuance Requirements with claim definitions

---

### Section 4 - Identity and Authentication

#### 4.1: Authentication Architecture
- Added flow selection logic table for authentication methods
- Updated dual-token architecture description for RFC compliance
- Replaced "seamless user experience" with technical description

#### 4.2: Matrix Authentication Service (MAS) Integration
- Replaced generic authentication overview with proper MAS Integration documentation
- Added MAS endpoints table (OAuth 2.0 Discovery, Authorize, Token, Introspect, Revoke)
- Added TMCP Server MAS Client Registration requirements table

#### 4.3: Authentication Flows
- **New Section 4.3.1: Matrix Session Delegation**
  - Added complete authentication flow for logged-in Element users
  - Includes flow diagram, request/response formats, and implementation requirements
  - Token Exchange grant type (RFC 8693) for sub-second authentication
  - Consent flow for sensitive scopes
  - Matrix token introspection (RFC 7662) specification
- **Renumbered Section 4.3.2: Device Authorization Grant**
  - Updated for "new users" use case
  - Added TEP exchange step after MAS authentication
- **Renumbered Section 4.3.3: Authorization Code Grant**
  - Maintained for web mini-apps

#### 4.3.1: Matrix Session Delegation
- **Removed**: TypeScript `authenticateWithConsent()` implementation
- **Kept**: HTTP request/response examples (protocol specifications)
- **Kept**: Parameter tables (RFC-compliant)

#### 4.4: TEP Token Structure
- Added `delegated_from` and `matrix_session_ref` claims for delegated sessions

#### 4.5: Client-Side Token Management
- Replaced iOS Swift, Android Kotlin, and Web JavaScript storage code with requirements tables
- Removed all platform-specific implementation code
- Added storage requirements specification for each platform
- Simplified to behavioral requirements using MUST/SHOULD statements

#### 4.6: TMCP Server Authentication Middleware
- Replaced complete Python `TMCPAuthMiddleware` implementation with behavioral specification
- Added token validation requirements table
- Added scope authorization requirements
- Added Matrix token management requirements
- Added error response specifications

#### 4.7: MAS Integration Requirements
- Replaced MAS client registration YAML with requirements table
- Replaced mini-app client registration YAML with requirements table

#### 4.9.2: Token Validation
- **Removed**: Python `validate_matrix_token()` function
- **Replaced with**: Behavioral validation requirements
- **Replaced with**: Introspection request/response examples (HTTP protocol)

#### 4.9: Security Considerations
- Added comparison table of authentication flows
- Added token validation requirements subsection
- Added replay attack prevention requirements
- Added scope escalation prevention requirements

#### 4.10: Matrix Integration
- **Removed**: Python `handle_matrix_operation()` function
- **Replaced with**: Matrix proxy requirements table

#### 4.11.5: Client Rendering Requirements
- **Removed**: ASCII UI mockups for payment cards
- **Removed**: TypeScript `PaymentEventHandler` class
- **Replaced with**: Behavioral rendering requirements
- **Moved**: Implementation code to Appendix B

#### 4.11.7: Third-Party Wallet Integration
- **Removed**: Python `verify_wallet_callback()` function
- **Removed**: Python `create_payment_event()` function
- **Replaced with**: Signature verification requirements table
- **Replaced with**: Event creation flow specification

#### 4.11.8: Payment Event Idempotency
- **Removed**: Python `PaymentEventService` class
- **Replaced with**: Idempotency requirements table
- **Replaced with**: Processing flow table

#### 4.11: In-Chat Payment Architecture
- Replaced "seamless user experience" with "integrated payment events"

---

### Section 5 - Authorization Framework

#### 5.5: Scope Validation
- **Removed**: Python `validate_scopes()` function
- **Replaced with**: Validation requirements specification
- **Replaced with**: Validation response format table

---

### Section 6 - Wallet Integration

#### 6.4.3: Verification Status Validation
- **Removed**: JavaScript `validatePaymentEligibility()` function
- **Replaced with**: Verification requirements specification
- **Replaced with**: Feature access check table
- **Replaced with**: Error response table

---

### Section 7 - Payment Protocol

#### 7.2.4: Recipient Acceptance Protocol
- **Removed**: JavaScript `processExpiredTransfers()` function
- **Replaced with**: Expiry processing requirements
- **Replaced with**: Expiry event format specification

#### 7.3.2: Payment Authorization
- **Removed**: JavaScript payment authorization signature code
- **Replaced with**: Payment authorization requirements table
- **Replaced with**: Algorithm specification for hardware key signing

#### 7.5.5: Gift Distribution Protocols
- **Removed**: JavaScript `calculateRandomDistributions()` function
- **Removed**: JavaScript `calculateEqualDistributions()` function
- **Replaced with**: Random distribution algorithm specification
- **Replaced with**: Equal distribution algorithm specification
- **Replaced with**: Distribution constraints table

#### 7.5.6: Group Gift Atomicity
- **Removed**: SQL PostgreSQL transaction query
- **Removed**: JavaScript concurrent opening handling
- **Replaced with**: Transaction flow requirements table
- **Replaced with**: Concurrency handling specification
- **Replaced with**: Error response table

---

### Section 10 - Communication Verbs

#### 10.4.5: Secure Communication Patterns
- **Removed**: Java WRONG/CORRECT examples
- **Replaced with**: Secure communication requirements table

#### 10.4.6: Certificate Pinning
- **Removed**: Kotlin CertificatePinner configuration
- **Replaced with**: Certificate pinning requirements specification

#### 10.4.7: WebView Lifecycle Management
- **Removed**: Java onPause/onDestroy lifecycle methods
- **Replaced with**: Lifecycle cleanup requirements table

---

### Section 11 - Security Considerations

#### 11.4.2: Token Bucket Algorithm
- **Removed**: Python `RateLimiter` class
- **Replaced with**: Token bucket algorithm requirements
- **Replaced with**: Bucket initialization specification
- **Replaced with**: Token refill specification
- **Replaced with**: Rate limit response headers

#### 11.4.3: Distributed Rate Limiting
- **Removed**: Python `DistributedRateLimiter` class
- **Replaced with**: Redis sorted set requirements
- **Replaced with**: Request counting specification
- **Replaced with**: Redis operations table

---

### Section 12 - Error Handling
- Added authentication-specific error responses (invalid_grant, consent_required, invalid_scope)

---

### Section 15 - References
- Added RFC 7662 (Token Introspection)
- Added RFC 7009 (Token Revocation)
- Added RFC 8628 (Device Authorization Grant)
- Added RFC 8693 (Token Exchange Grant)
- Updated Matrix Spec to v1.15
- Added MSC3861 (MAS reference)

---

### Marketing Language Fixes (Throughout Document)

| Original Term | Replacement |
|--------------|-------------|
| "super-apps" | "integrated application platforms" |
| "super-app ecosystem" | "integrated application platform" |
| "Mini-Application Ecosystem" | "Mini-Application Integration" |
| "Zero modification" | "No modification" |
| "seamless" user experience | "authentication without additional user interaction" |
| "Follows industry patterns" | "Implements standard patterns" |
| "Excellent UX" | "efficient protocol flow" |
| "seamless authentication flow" | "authentication flow without requiring user interaction with existing session" |

---

### RFC Compliance Documentation
- Created CLAUDE.md with comprehensive RFC compliance rules
- Defines content categories that belong vs don't belong in RFC
- Provides writing guidelines and review checklists
- Documents patterns for replacing implementation code with specifications

---

### Chapter Numbering

Fixed chapter numbering throughout:
- Section 4: Identity and Authentication
- Section 5: Wallet Integration Layer
- Section 6: Authorization Framework
- Section 7: Payment Protocol
- Section 8: Event System
- Section 9: Mini-App Lifecycle
- Section 10: Communication Verbs
- Section 11: Security Considerations
- Section 12: Error Handling
- Section 13: Federation Considerations
- Section 14: IANA Considerations
- Section 15: References
- Section 16: Official and Preinstalled Mini-Apps
- Section 17: Appendices (A, B, C, D)

---

### Document Structure Compliance

The document now follows proper RFC structure:
1. Abstract
2. Status of This Memo
3. Copyright Notice
4. Table of Contents
5. Introduction
6. Conventions and Terminology
7. Protocol Specification (main content)
8. Security Considerations
9. IANA Considerations
10. References
11. Appendices

---

### RFC 2119 Compliance

All requirements now use proper RFC 2119 notation:
- **MUST**: Absolute requirements
- **MUST NOT**: Absolute prohibitions
- **SHOULD**: Recommended practices
- **SHOULD NOT**: Recommendations to avoid
- **MAY**: Optional features

---

### Implementation Code Removed

| Section | Code Type | Status |
|---------|-----------|--------|
| 3.1.2 | Python (MASClientConfig, token_endpoint) | Removed |
| 4.9.2 | Python (validate_matrix_token) | Removed |
| 4.10 | Python (handle_matrix_operation) | Removed |
| 4.11.5 | TypeScript (PaymentEventHandler), ASCII UI | Removed |
| 4.11.7 | Python (webhook functions) | Removed |
| 4.11.8 | Python (PaymentEventService) | Removed |
| 5.5 | Python (validate_scopes) | Removed |
| 6.4.3 | JavaScript (validatePaymentEligibility) | Removed |
| 7.2.4 | JavaScript (processExpiredTransfers) | Removed |
| 7.3.2 | JavaScript (payment authorization) | Removed |
| 7.5.5 | JavaScript (distribution algorithms) | Removed |
| 7.5.6 | SQL, JavaScript (transactions) | Removed |
| 10.4.5 | Java (secure patterns) | Removed |
| 10.4.6 | Kotlin (certificate pinning) | Removed |
| 10.4.7 | Java (lifecycle) | Removed |
| 11.4.2 | Python (RateLimiter) | Removed |
| 11.4.3 | Python (DistributedRateLimiter) | Removed |

---

### What Was Preserved

- **HTTP request/response examples** (protocol specifications - RFC-compliant)
- **JSON data structure examples** (protocol specifications - RFC-compliant)
- **Parameter/claim tables** (RFC-compliant)
- **Flow diagrams** (RFC-compliant)
- **Error response formats** (RFC-compliant)

---

### Appendices Structure

- **Appendix A**: Complete Protocol Flow Example (behavioral, no implementation code)
- **Appendix B**: SDK Interface Definitions (TypeScript interfaces only)
- **Appendix C**: WebView Implementation Details (platform-specific code - correct location)
- **Appendix D**: Webhook Signature Verification (Python example - correct location)

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