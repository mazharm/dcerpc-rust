# Security Considerations

This document outlines security considerations, mitigations, and best practices for the dcerpc-rust implementation.

## Security Features

### Memory Safety

#### Buffer Overflow Protection
- **PDU Size Limits**: Maximum PDU size enforced (default: 64 KB)
- **Fragment Size Limits**: Configurable max_xmit_frag and max_recv_frag (default: 4280 bytes)
- **Array Allocation Limits**: Maximum array elements limited to 64 MB (`MAX_NDR_ARRAY_ELEMENTS`)
- **Per-Connection Memory Budget**: Each connection limited to 16 MB of allocated memory (configurable via `max_connection_memory_budget`)

#### Integer Overflow Protection
- **Saturating Arithmetic**: All size calculations use saturating arithmetic to prevent overflow
- **Checked Operations**: Integer overflow detection in conformant array operations
- **Fragment Calculation**: Overhead calculations use saturating_add/saturating_sub

#### Bounds Checking
- **Authentication Verifier**: Validates auth_length against data buffer size before parsing
- **Buffer Operations**: All slice operations validate bounds before access
- **AsyncRead Contract**: Debug assertions verify AsyncRead implementations don't violate buffer size guarantees

### Denial of Service (DoS) Mitigations

#### Connection Limits
- **Maximum Connections**: Configurable connection limit enforced via semaphore (default: 10,000)
- **Connection Rejection**: Graceful rejection when limit reached
- **Connection Tracking**: Real-time statistics of active connections

#### Resource Limits
- **Fragment Limits**: Maximum concurrent fragments per connection (default: 100)
- **Memory Budget**: Total memory allocation limit per connection (16 MB default)
- **PDU Size**: Maximum PDU size prevents unbounded allocations

#### Rate Limiting
- Connection-level semaphore prevents connection exhaustion
- Per-connection fragment limits prevent fragment flooding

### Authentication and Encryption

#### SSPI Integration (Windows)
- **Supported Mechanisms**: NTLM, Kerberos, Negotiate (SPNEGO)
- **Authentication Levels**:
  - None (1): No authentication
  - Connect (2): Connection-level authentication
  - Call (3): Per-call authentication
  - Pkt (4): Per-packet authentication
  - PktIntegrity (5): Packet signing
  - PktPrivacy (6): Packet encryption

#### Security Context Management
- **Handle Lifetime**: Proper cleanup via Drop implementation
- **Buffer Management**: SSPI-allocated buffers freed via FreeContextBuffer
- **Context Validation**: Status codes checked before handle use

### Wire Protocol Security

#### Input Validation
- **Header Validation**: Fragment length validated against minimum and maximum bounds
- **Auth Verifier**: Length validation before buffer access
- **Alignment Checks**: Proper NDR alignment enforced

#### Endianness Handling
- **Context-Aware**: Little-endian and big-endian support via NdrContext
- **Consistent Encoding**: Proper byte order for all multi-byte values

## Unsafe Code Audit

### Documented Unsafe Blocks

All unsafe code blocks are documented with safety invariants:

#### dcerpc_transport.rs
- **Buffer Management**: Safe use of spare_capacity_mut() with proper initialization tracking
- **Invariants**: AsyncRead contract enforced via debug_assert

#### sspi.rs (Windows only)
- **FFI Safety**: All Windows SSPI API calls documented
- **Handle Management**: Credentials and context handles properly initialized and freed
- **Buffer Safety**: Output buffer sizes validated before slice creation
- **Memory Management**: SSPI-allocated memory freed via appropriate APIs

### Safety Guarantees

1. **Memory Safety**: No unsafe memory access without proper bounds checking
2. **Type Safety**: Proper alignment and type handling in NDR encoding/decoding
3. **Thread Safety**: SspiContext not Send/Sync (Windows SSPI is not thread-safe)
4. **Resource Cleanup**: All handles and allocations cleaned up via Drop

## Security Best Practices

### For Server Implementations

1. **Configure Limits**: Set appropriate values for:
   - `max_connections`: Based on expected load
   - `max_pdu_size`: Typically 64 KB
   - `max_xmit_frag` / `max_recv_frag`: Typically 4280 bytes
   - `max_concurrent_fragments`: Based on memory constraints
   - `max_connection_memory_budget`: Prevent per-connection memory exhaustion

2. **Enable Authentication**: Use at least `PktIntegrity` level for sensitive operations

3. **Monitor Statistics**: Track connection rejections and failed requests

4. **Implement Timeouts**: Set appropriate connection and operation timeouts

### For Client Implementations

1. **Validate Server Responses**: Check response sizes and types
2. **Use Authentication**: Enable authentication for sensitive operations
3. **Handle Errors**: Properly handle RpcError variants
4. **Connection Pooling**: Reuse connections when appropriate

### For IDL Compilers and Stubs

1. **Input Validation**: Validate all input parameters before encoding
2. **Size Limits**: Respect MAX_NDR_ARRAY_ELEMENTS limits
3. **Error Handling**: Use proper Result types for fallible operations

## Vulnerability Disclosure

If you discover a security vulnerability, please:

1. **Do Not** open a public issue
2. Email security concerns to the maintainers
3. Provide details of the vulnerability
4. Allow time for assessment and fix before public disclosure

## Security Audit History

- **2024-01**: Initial security review
  - Fixed buffer safety in dcerpc_transport.rs
  - Added integer overflow protection in fragmentation.rs
  - Enhanced bounds checking in security.rs
  - Documented unsafe blocks in sspi.rs
  - Added per-connection memory budgeting

## Known Limitations

1. **Windows SSPI Only**: Authentication currently requires Windows platform
2. **No TLS Support**: Raw TCP transport without TLS (use external proxy if needed)
3. **No Built-in Auditing**: Applications should implement audit logging
4. **Single-threaded SSPI**: Windows SSPI contexts are not thread-safe

## Future Security Enhancements

- [ ] Cross-platform authentication (GSS-API on Unix)
- [ ] TLS/SSL transport support
- [ ] Built-in audit logging
- [ ] Rate limiting at server level
- [ ] Connection-level timeout enforcement
- [ ] Advanced DoS detection and mitigation

## References

- [MS-RPCE: Remote Procedure Call Protocol Extensions](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/)
- [DCE 1.1: Remote Procedure Call](https://pubs.opengroup.org/onlinepubs/9629399/)
- [MS-DCOM: Distributed Component Object Model](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/)
- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)
