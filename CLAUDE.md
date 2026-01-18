# TMCP RFC Compliance Rules

## Overview

This document defines rules for maintaining RFC (Request for Comments) compliance when editing TMCP specification documents. RFCs are standards documents, not implementation guides or tutorials. They define protocols, data structures, and behaviors - not code implementations or UI guidance.

---

## Content Categories

### ✅ BELONGS IN RFC (MUST KEEP)

**Protocol Specifications:**
- HTTP request/response formats
- JSON data structures and schemas
- Protocol flow diagrams
- Message formats and event types
- Endpoint specifications
- Parameter definitions and constraints

**Requirements Definitions:**
- MUST/SHOULD/MAY requirements using RFC 2119 notation
- Behavioral specifications (what the protocol MUST do)
- Security requirements and considerations
- Error response formats
- State machine specifications
- Timeout and retry requirements

**Data Structures:**
- Token structures (JWT claims)
- Claim definitions with required/optional fields
- Scope definitions and hierarchies
- Event payload formats
- Configuration parameter definitions

**Tables and References:**
- Parameter/claim reference tables
- Error code tables
- Comparison tables (e.g., authentication flows)
- References to standards RFCs
- Normative and informative references

**Architectural Descriptions:**
- System component diagrams
- Communication patterns
- Data flow specifications
- Security model descriptions
- Deployment considerations

### ❌ DOES NOT BELONG IN RFC (MUST REMOVE/REPLACE)

**Implementation Code:**
```yaml
PROBLEMATIC:
  - Full class implementations (Python, TypeScript, etc.)
  - Complete function bodies with logic
  - Platform-specific SDK code
  - Configuration file formats (YAML examples)
```

**Solution:** Replace with behavioral specification
```
The server MUST validate subject_token by introspecting it at MAS endpoint.
```

**Tutorial/Guide Content:**
- Step-by-step implementation tutorials
- "How to" guides
- Platform-specific storage implementations
- UI/UX design guidance
- ASCII art UI mockups

**Release Notes:**
```yaml
PROBLEMATIC:
  - "Added in TMCP v1.0"
  - "Released in version 2.1"
  - Changelog entries
```

**Solution:** Use objective language
```
This section defines the Matrix Session Delegation flow.
```

**Marketing Language:**
```yaml
PROBLEMATIC TERMS:
  - "seamless" user experience
  - "super-app" ecosystem
  - "best-in-class" features
  - "industry-leading" performance
  - Product branding terms
```

**Solution:** Use technical terminology
```
This protocol enables authentication without additional user interaction.
This specification defines an integrated application platform.
```

---

## Writing Guidelines

### 1. Specify WHAT, Not HOW

**❌ WRONG (Prescriptive Implementation):**
```python
async def handle_token_exchange(request: TokenExchangeRequest):
    introspection = await mas_client.introspect_token(...)
    if not introspection.active:
        raise Unauthorized("Invalid or expired Matrix token")
    # ... 50 more lines of implementation code
```

**✅ RIGHT (Behavioral Specification):**
```
The TMCP Server MUST process token exchange requests as follows:

1. Validate subject_token by introspecting it at MAS endpoint
2. Verify the `active` claim is true
3. Extract Matrix User ID from `sub` claim
4. If `active` is false, return 401 Unauthorized
```

### 2. Use RFC 2119 Requirements Notation

All requirements MUST use RFC 2119 keywords:
- MUST (absolute requirement)
- MUST NOT (absolute prohibition)
- REQUIRED (synonym for MUST)
- SHALL (synonym for MUST)
- SHALL NOT (synonym for MUST NOT)
- SHOULD (recommended practice)
- SHOULD NOT (recommended to avoid)
- MAY (optional feature)

**Examples:**
```
Clients MUST validate TEP tokens on each request.
The server SHOULD include retry headers.
Clients MAY implement offline caching.
```

### 3. Code Examples: Protocol vs Implementation

**✅ ACCEPTABLE: Protocol Examples (HTTP/JSON):**
```http
POST /oauth2/token HTTP/1.1
Host: tmcp.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<TOKEN>
```

```json
{
  "access_token": "tep.eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

**❌ UNACCEPTABLE: Implementation Examples:**
```python
class TMCPAuthMiddleware:
    def __init__(self, config):
        self.jwt_public_key = config.jwt_public_key
        # ... full class implementation
```

### 4. Configuration: Requirements vs Formats

**❌ WRONG (Prescriptive Format):**
```yaml
# MAS configuration (config.yaml)
clients:
  - client_id: tmcp_server_001
    client_auth_method: client_secret_post
    # ... specific YAML structure
```

**✅ RIGHT (Requirements Table):**
```
The TMCP Server MUST be registered as a confidential client in MAS with:

| Parameter | Required | Value |
|-----------|-----------|--------|
| `client_auth_method` | Yes | `client_secret_post` |
| `grant_types` | Yes | MUST include: `urn:ietf:params:oauth:grant-type:token-exchange`, `refresh_token` |
| `scope` | Yes | MUST include: `urn:matrix:org.matrix.msc2967.client:api:*` |
```

### 5. UI/UX: Remove All Implementation Guidance

**❌ REMOVE:**
- ASCII art UI mockups
- "Display this screen to user"
- Color scheme specifications
- Button placement guidelines
- Step-by-step user instructions

**✅ KEEP:**
- Protocol flow diagrams (boxes and arrows, not UI mockups)
- Error response formats that clients must render
- API response structures

### 6. Platform-Specific Code: Move to Appendix

If platform-specific examples are needed for clarity:

**❌ WRONG: In Specification Section**
```swift
import Security

struct TokenStorage {
    static func storeTEP(_ token: String) throws {
        // ... full iOS implementation
    }
}
```

**✅ RIGHT: In Appendix or Separate Document**
```
Appendix B: SDK Interface Definitions

This appendix provides implementation examples for:
- iOS (Swift)
- Android (Kotlin)
- Web (JavaScript)

These are non-normative examples for implementer guidance.
```

### 7. Marketing Language Translation

| Marketing Term | Technical Replacement |
|----------------|---------------------|
| "seamless" user experience | "authentication without additional user interaction" |
| "super-app" | "integrated application platform" |
| "best-in-class" | "compliant with this specification" |
| "excellent UX" | "efficient protocol flow" |
| "industry-leading" | remove entirely (non-technical) |
| "zero-latency" | "sub-200ms response time" (with metrics) |
| "instant" | "<1 second" or specify timing |

### 8. Section Structure Pattern

Each specification section SHOULD follow:

```
#### N.M Section Title

[Purpose/Objective - optional but recommended]

[Prerequisites - if applicable]

[Protocol Flow - diagram or steps]

[Request/Response Format - HTTP/JSON examples]

[Parameters/Data Structure - tables]

[Server/Client Requirements - MUST/SHOULD statements]

[Error Responses - if applicable]

[Security Considerations - if applicable]
```

---

## Review Checklist

When reviewing or editing TMCP RFC sections:

### Code Content
- [ ] Are there full class/function implementations?
- [ ] Are there platform-specific SDK examples (Swift, Kotlin, etc.)?
- [ ] Are there configuration file format examples (YAML, TOML)?
- [ ] If yes to any, REMOVE or REPLACE with behavioral specification

### Language Style
- [ ] Are there marketing terms (seamless, super-app, best-in-class)?
- [ ] Are there release note phrases ("Added in v1.0")?
- [ ] Are there "how-to" tutorial explanations?
- [ ] If yes to any, REPLACE with technical/specification language

### Format Compliance
- [ ] Are HTTP request/response examples present for all endpoints?
- [ ] Are parameter/claim tables provided for data structures?
- [ ] Are RFC 2119 requirements keywords used correctly?
- [ ] Are error response formats specified?
- [ ] Are normative references to standards RFCs included?

### Content Location
- [ ] Are implementation code examples moved to Appendix B?
- [ ] Are UI/UX guidelines removed?
- [ ] Are configuration formats replaced with requirement tables?

---

## Common Patterns to Apply

### Pattern 1: Replacing Implementation Code

**BEFORE:**
```python
async def validate_matrix_token(token: str) -> IntrospectionResult:
    response = await http_client.post(
        f"{MAS_URL}/oauth2/introspect",
        auth=(TMCP_CLIENT_ID, TMCP_CLIENT_SECRET),
        data={"token": token}
    )
    result = response.json()
    if not result.get("active"):
        raise InvalidTokenError("Matrix token is not active")
    return IntrospectionResult(...)
```

**AFTER:**
```
The TMCP Server MUST validate Matrix tokens using MAS introspection endpoint (RFC 7662):

Request:
POST /oauth2/introspect HTTP/1.1
Host: mas.tween.example
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(tmcp_server_001:client_secret)

token=<MATRIX_TOKEN>

Response:
{
  "active": true,
  "scope": "urn:matrix:org.matrix.msc2967.client:api:*",
  "client_id": "element_web_001",
  "sub": "@alice:tween.example",
  "exp": 1735689900
}

The server MUST reject tokens where `active` is false with HTTP 401 Unauthorized.
```

### Pattern 2: Replacing Configuration Examples

**BEFORE:**
```yaml
# Application Service Configuration
id: tween-miniapps
url: https://tmcp.internal.example.com
as_token: <APPLICATION_SERVICE_TOKEN>
hs_token: <HOMESERVER_TOKEN>
sender_localpart: _tmcp
namespaces:
  users:
    - exclusive: true
      regex: "@_tmcp_.*"
```

**AFTER:**
```
TMCP Server MUST register as a Matrix Application Service with:

| Parameter | Required | Description |
|-----------|-----------|-------------|
| `id` | Yes | Unique identifier for the AS |
| `url` | Yes | URL where TMCP Server is accessible |
| `sender_localpart` | Yes | Localpart for AS user (e.g., `_tmcp`) |
| `namespaces.users` | Yes | Regex pattern for AS-controlled users, MUST be exclusive |

The AS MUST provide both `as_token` and `hs_token` for authentication.
```

### Pattern 3: Replacing Release Notes

**BEFORE:**
```
#### 4.3.1 Matrix Session Delegation

**Added in TMCP v1.0** - This flow enables seamless mini-app authentication for users already logged into Element.
```

**AFTER:**
```
#### 4.3.1 Matrix Session Delegation

**Purpose**: This flow enables mini-app authentication for users with existing Matrix sessions without additional user interaction.

**Prerequisites**:
- User MUST have active Matrix session
- Client MUST have valid Matrix access token
- TMCP Server MUST be registered as MAS client
```

---

## References

**RFC Style Guide:**
- RFC 7322: "IETF Trust Management System Protocol" - Example of good RFC writing
- RFC 6749: "OAuth 2.0 Authorization Framework" - Protocol specification reference
- RFC 7519: "JSON Web Token (JWT)" - Data structure specification reference

**Standards to Reference:**
- RFC 2119: Key words for use in RFCs
- RFC 8628: OAuth 2.0 Device Authorization Grant
- RFC 7662: OAuth 2.0 Token Introspection
- RFC 8693: OAuth 2.0 Token Exchange

---

## Decision Trees

### When to Keep Code Example

```
Is it HTTP/JSON example?
├─ Yes → KEEP (it's protocol specification)
└─ No → Is it full class/function implementation?
    ├─ Yes → REMOVE (move to Appendix B)
    └─ No → Is it illustrative snippet (3-5 lines)?
        ├─ Yes → MAY KEEP if essential for clarity
        └─ No → REMOVE
```

### When to Replace Marketing Language

```
Does term describe user experience quality?
├─ Yes → REPLACE with technical description
│   "seamless" → "without user interaction"
│   "instant" → "<1 second" (or specify timing)
│   "excellent" → "efficient" (with metrics)
└─ No → KEEP
```

---

## Quick Reference

### RFC Structure (Required Sections)
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

### Document Status
- ✅ This is a Proposed Standard
- ✅ Requests discussion and improvements
- ✅ Distribution is unlimited

### Key Principles
1. **Protocol, not code**: Define WHAT, not HOW
2. **Standard, not guide**: Specification, not tutorial
3. **Technical, not marketing**: Precise language
4. **Requirements, not implementation**: MUST/SHOULD statements
5. **Platform-agnostic**: Support multiple implementations
