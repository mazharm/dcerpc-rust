# Security Considerations

This document outlines security considerations for the dcerpc-rust implementation.

## Overview

dcerpc-rust implements the DCE RPC protocol with a focus on security, reliability, and wire compatibility. This document describes the security measures in place and best practices for deployment.

## Security Features

### 1. Buffer Overflow Protection

#### NDR Array Decoding
- **Allocation Limits**: Maximum allocation size of 64 MB (`MAX_NDR_ALLOCATION_SIZE`) prevents memory exhaustion attacks
- **Array Element Limits**: Maximum 64 million elements (`MAX_NDR_ARRAY_ELEMENTS`) per array
- **Integer Overflow Protection**: All array offset and count additions use `checked_add()` to prevent wraparound attacks
- **Bounds Checking**: All buffer operations use Rust's bounds-checked slicing via the `bytes` crate

Example vulnerable code pattern (FIXED in this PR):
```rust
// VULNERABLE: Could overflow on 32-bit systems or with malicious input
if offset + actual_count > max_count { ... }

// SECURE: Uses checked_add to detect overflow
let total = offset.checked_add(actual_count).ok_or(NdrError::IntegerOverflow)?;
if total > max_count { ... }
```

### 2. Resource Exhaustion Protection

#### Connection Limits
- **Max Connections**: Default 10,000 concurrent connections (configurable via `DceRpcServerConfig`)
- **Semaphore-based Limiting**: New connections blocked when limit reached
- **Connection Timeout**: Default 5 minutes (configurable via `connection_timeout_secs`)
- **Idle Timeout**: Default 10 minutes (configurable via `idle_timeout_secs`)

#### Fragment Assembly
- **UDP Fragment Limit**: Maximum 10,000 pending fragment assemblies
- **Fragment TTL**: 60-second timeout for UDP fragment assembly
- **LRU Eviction**: Oldest assemblies evicted when cache is full

#### PDU Size Limits
- **Default Max PDU**: 65,536 bytes (64 KB)
- **Fragment Size**: 4,280 bytes default (negotiated during bind)
- **Configurable**: Both limits can be adjusted via server config

### 3. Authentication & Authorization

#### Supported Mechanisms (Windows)
- **SSPI Integration**: Windows SSPI for Kerberos and NTLM authentication
- **Security Levels**: 
  - `Connect`: No authentication
  - `Call`: Per-call authentication
  - `PktIntegrity`: Packet integrity checking
  - `PktPrivacy`: Packet encryption

#### Authentication Caveats
- **Windows-only**: Strong authentication requires Windows SSPI
- **No Mutual Auth**: Currently one-way server authentication only
- **Context Management**: New SSPI context per connection (no caching)

### 4. Input Validation

#### NDR Decoding
- **Conformance Validation**: `actual_count <= max_count` for arrays
- **String Validation**: Null terminator checking
- **Enum Validation**: Invalid enum values rejected with `InvalidEnumValue` error
- **Union Validation**: Invalid discriminants rejected with `InvalidDiscriminant` error
- **Pointer Validation**: Null pointer checks for unique and full pointers

#### Protocol Validation
- **PDU Header Validation**: Version, type, and flag validation
- **Fragment Validation**: Sequence number and fragment flag checking
- **Bind Validation**: Syntax negotiation and context validation

### 5. Safe Rust Practices

#### Minimal Unsafe Code
- **Total unsafe blocks**: 19 (all in `sspi.rs` for Windows FFI)
- **Purpose**: Windows SSPI API calls only
- **Audited**: All unsafe blocks reviewed for soundness
- **Isolated**: Unsafe code isolated to platform-specific modules

#### Memory Safety
- **No raw pointers** in safe code
- **Bounds-checked** array access
- **No manual memory management** (except SSPI context cleanup)
- **Thread-safe**: Using `parking_lot` RwLocks (non-poisoning)

## Known Limitations

### 1. No Connection Pooling
**Impact**: Each client connection creates a new TCP stream  
**Mitigation**: Application-level connection pooling recommended for high-throughput scenarios  
**Status**: Documented limitation, not a security issue

### 2. Windows-Only Strong Authentication
**Impact**: Non-Windows platforms limited to no-auth mode  
**Mitigation**: Use external authentication layer (e.g., TLS, VPN)  
**Status**: Platform limitation

### 3. Single-Threaded Endpoint Mapper
**Impact**: Port 135 EPM not designed for high volume  
**Mitigation**: Cache endpoint mappings at client side  
**Status**: Protocol design limitation

## Deployment Best Practices

### 1. Server Configuration

#### Production Settings
```rust
DceRpcServerConfig {
    max_pdu_size: 65536,
    max_connections: 1000,          // Adjust based on capacity
    max_xmit_frag: 4280,
    max_recv_frag: 4280,
    max_concurrent_fragments: 100,
    connection_timeout_secs: Some(300),  // 5 minutes
    idle_timeout_secs: Some(600),        // 10 minutes
}
```

#### High-Security Settings
```rust
DceRpcServerConfig {
    max_connections: 100,           // Reduce attack surface
    connection_timeout_secs: Some(60),   // 1 minute
    idle_timeout_secs: Some(120),        // 2 minutes
    // ... other defaults
}
```

### 2. Network Security

#### Recommended Layers
- **Firewall**: Restrict access to port 135 (EPM) and dynamic RPC ports
- **TLS**: Use TLS termination proxy for encryption on non-Windows
- **Network Segmentation**: Isolate RPC services in trusted network zones

### 3. Monitoring

#### Key Metrics
- `connections_active`: Monitor for connection exhaustion
- `connections_rejected`: High rejection rate indicates attack or capacity issue
- `requests_failed`: Monitor for malformed requests
- `fragments_evicted_limit`: High eviction rate indicates attack or config issue

### 4. Logging

#### Security Events
- Failed authentication attempts
- Rejected connections (capacity limit)
- Protocol violations
- Fragment assembly timeouts

## Vulnerability Reporting

If you discover a security vulnerability, please report it to the maintainers privately before public disclosure.

**Contact**: Create a private security advisory on GitHub

## Security Audit History

| Date | Version | Auditor | Findings |
|------|---------|---------|----------|
| 2025-01-20 | 0.1.0 | GitHub Copilot | Integer overflow in VaryingArray (FIXED), Missing timeout configs (FIXED) |

## Testing

### Security Test Coverage

#### Integer Overflow Tests
- `test_varying_array_integer_overflow_protection`: Tests offset + actual_count overflow detection
- `test_conformant_varying_array_overflow_detection`: Tests conformance mismatch with large offsets

#### Allocation Limit Tests
- Tests verify `MAX_NDR_ALLOCATION_SIZE` enforcement
- Tests verify `MAX_NDR_ARRAY_ELEMENTS` enforcement

#### Run Security Tests
```bash
cargo test --package midl-ndr
cargo test --package dcerpc
cargo test --package integration-tests
```

## References

- [MS-RPCE]: DCE RPC Protocol Extensions
- [DCE 1.1 RPC Specification](https://pubs.opengroup.org/onlinepubs/9629399/)
- [NDR Specification](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm)

## Changelog

### Version 0.1.0 (2025-01-20)
- **FIXED**: Integer overflow vulnerability in `VaryingArray::ndr_decode()`
- **ADDED**: `connection_timeout_secs` and `idle_timeout_secs` to `DceRpcServerConfig`
- **ADDED**: Security test cases for integer overflow protection
- **DOCUMENTED**: Security considerations and best practices
