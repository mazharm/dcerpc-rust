//! DCE RPC PDU Fragmentation Support
//!
//! This module implements multi-PDU fragmentation for DCE RPC as defined in:
//! - DCE 1.1: Remote Procedure Call (C706) Section 12.5
//! - MS-RPCE: Remote Procedure Call Protocol Extensions
//!
//! When stub data exceeds the negotiated `max_xmit_frag`/`max_recv_frag` limits,
//! the PDU must be split into multiple fragments. Each fragment carries:
//! - The same call_id
//! - FIRST_FRAG flag on first fragment
//! - LAST_FRAG flag on last fragment
//! - Fragment of the stub data
//!
//! # Fragment Structure
//!
//! ```text
//! max_frag size limit (e.g., 4280 bytes)
//! ├── PDU Header (16 bytes)
//! ├── Request/Response body header (8 bytes)
//! ├── Object UUID (16 bytes, optional, request only)
//! ├── Stub data fragment (variable)
//! ├── Auth padding (0-15 bytes, if authenticated)
//! └── Auth verifier (8 + auth_value bytes, if authenticated)
//! ```

use crate::dcerpc::{PacketFlags, PduHeader, RequestPdu, ResponsePdu};
use crate::error::{Result, RpcError};
use bytes::{Bytes, BytesMut};

/// Fragment generator for splitting outgoing PDUs into multiple fragments.
///
/// When stub data exceeds the maximum fragment size negotiated during bind,
/// the generator splits the data across multiple PDUs while maintaining
/// proper fragment flags and call identification.
pub struct FragmentGenerator;

impl FragmentGenerator {
    /// Calculate the maximum stub data size that can fit in a single fragment.
    ///
    /// # Arguments
    /// * `max_frag` - Maximum fragment size negotiated during bind (e.g., 4280)
    /// * `auth_len` - Length of authentication value (0 if no auth)
    /// * `has_object_uuid` - Whether the request has an object UUID
    ///
    /// # Returns
    /// Maximum bytes of stub data per fragment
    pub fn max_stub_size(max_frag: u16, auth_len: u16, has_object_uuid: bool) -> usize {
        let header_size = PduHeader::SIZE; // 16 bytes
        let body_header_size = RequestPdu::BODY_HEADER_SIZE; // 8 bytes (alloc_hint + ctx_id + opnum)
        let object_uuid_size = if has_object_uuid { 16 } else { 0 };

        let auth_overhead = if auth_len > 0 {
            // Auth padding (worst case 15 bytes) + auth verifier header (8 bytes) + auth value
            15 + 8 + auth_len as usize
        } else {
            0
        };

        let overhead = header_size + body_header_size + object_uuid_size + auth_overhead;

        if max_frag as usize > overhead {
            max_frag as usize - overhead
        } else {
            0
        }
    }

    /// Fragment a Request PDU into multiple fragments if needed.
    ///
    /// # Arguments
    /// * `request` - The original request PDU to fragment
    /// * `max_frag` - Maximum fragment size (from bind negotiation)
    ///
    /// # Returns
    /// A vector of request PDUs. If the original fits within max_frag,
    /// returns a single-element vector with the original (flags set properly).
    pub fn fragment_request(request: &RequestPdu, max_frag: u16) -> Vec<RequestPdu> {
        let auth_len = request
            .auth_verifier
            .as_ref()
            .map(|av| av.auth_value.len() as u16)
            .unwrap_or(0);
        let has_object = request.object_uuid.is_some();
        let max_stub = Self::max_stub_size(max_frag, auth_len, has_object);

        // If stub fits in single fragment, return as complete PDU
        if request.stub_data.len() <= max_stub {
            let mut single = request.clone();
            single.header.packet_flags = PacketFlags::complete();
            return vec![single];
        }

        let mut fragments = Vec::new();
        let stub_data = &request.stub_data;
        let total_len = stub_data.len();
        let mut offset = 0;

        while offset < total_len {
            let remaining = total_len - offset;
            let chunk_size = remaining.min(max_stub);
            let is_first = offset == 0;
            let is_last = offset + chunk_size >= total_len;

            let chunk = stub_data.slice(offset..offset + chunk_size);

            let mut frag = RequestPdu {
                header: request.header.clone(),
                alloc_hint: total_len as u32, // Total stub size across all fragments
                context_id: request.context_id,
                opnum: request.opnum,
                object_uuid: request.object_uuid,
                stub_data: chunk,
                auth_verifier: None, // Auth added per-fragment during actual send
            };

            // Set fragment flags
            let mut flags = PacketFlags::new();
            if is_first {
                flags.set_first_frag();
            }
            if is_last {
                flags.set_last_frag();
            }
            frag.header.packet_flags = flags;

            fragments.push(frag);
            offset += chunk_size;
        }

        fragments
    }

    /// Fragment a Response PDU into multiple fragments if needed.
    ///
    /// # Arguments
    /// * `response` - The original response PDU to fragment
    /// * `max_frag` - Maximum fragment size (from bind negotiation)
    ///
    /// # Returns
    /// A vector of response PDUs. If the original fits within max_frag,
    /// returns a single-element vector with the original (flags set properly).
    pub fn fragment_response(response: &ResponsePdu, max_frag: u16) -> Vec<ResponsePdu> {
        let auth_len = response
            .auth_verifier
            .as_ref()
            .map(|av| av.auth_value.len() as u16)
            .unwrap_or(0);
        // Response has no object UUID
        let max_stub = Self::max_stub_size(max_frag, auth_len, false);

        // If stub fits in single fragment, return as complete PDU
        if response.stub_data.len() <= max_stub {
            let mut single = response.clone();
            single.header.packet_flags = PacketFlags::complete();
            return vec![single];
        }

        let mut fragments = Vec::new();
        let stub_data = &response.stub_data;
        let total_len = stub_data.len();
        let mut offset = 0;

        while offset < total_len {
            let remaining = total_len - offset;
            let chunk_size = remaining.min(max_stub);
            let is_first = offset == 0;
            let is_last = offset + chunk_size >= total_len;

            let chunk = stub_data.slice(offset..offset + chunk_size);

            let mut frag = ResponsePdu {
                header: response.header.clone(),
                alloc_hint: total_len as u32, // Total stub size across all fragments
                context_id: response.context_id,
                cancel_count: response.cancel_count,
                stub_data: chunk,
                auth_verifier: None, // Auth added per-fragment during actual send
            };

            // Set fragment flags
            let mut flags = PacketFlags::new();
            if is_first {
                flags.set_first_frag();
            }
            if is_last {
                flags.set_last_frag();
            }
            frag.header.packet_flags = flags;

            fragments.push(frag);
            offset += chunk_size;
        }

        fragments
    }
}

/// Fragment assembler for reassembling incoming fragmented PDUs.
///
/// Collects fragments until all are received (FIRST_FRAG through LAST_FRAG),
/// then returns the complete reassembled stub data.
pub struct FragmentAssembler {
    /// Call ID for this assembly session
    call_id: u32,
    /// Accumulated stub data
    stub_data: BytesMut,
    /// Context ID from the first fragment
    context_id: u16,
    /// Operation number (for requests only)
    opnum: Option<u16>,
    /// Whether we've received the first fragment
    received_first: bool,
    /// Whether we've received the last fragment
    received_last: bool,
    /// Expected total size from alloc_hint (if provided)
    expected_size: Option<u32>,
}

impl FragmentAssembler {
    /// Create a new fragment assembler for the given call ID.
    pub fn new(call_id: u32) -> Self {
        Self {
            call_id,
            stub_data: BytesMut::new(),
            context_id: 0,
            opnum: None,
            received_first: false,
            received_last: false,
            expected_size: None,
        }
    }

    /// Get the call ID this assembler is tracking.
    pub fn call_id(&self) -> u32 {
        self.call_id
    }

    /// Get the context ID from the first fragment.
    pub fn context_id(&self) -> u16 {
        self.context_id
    }

    /// Get the opnum (for request fragments).
    pub fn opnum(&self) -> Option<u16> {
        self.opnum
    }

    /// Check if assembly is complete.
    pub fn is_complete(&self) -> bool {
        self.received_first && self.received_last
    }

    /// Add a fragment to the assembler.
    ///
    /// # Arguments
    /// * `header` - The PDU header
    /// * `stub` - The stub data from this fragment
    /// * `ctx_id` - The context ID
    /// * `opnum` - The operation number (for requests, None for responses)
    /// * `alloc_hint` - The alloc_hint field (total expected size)
    ///
    /// # Returns
    /// * `Ok(Some(data))` - Assembly complete, returns full stub data
    /// * `Ok(None)` - Fragment added, waiting for more
    /// * `Err(_)` - Fragment error (wrong call_id, out of order, etc.)
    pub fn add_fragment(
        &mut self,
        header: &PduHeader,
        stub: &[u8],
        ctx_id: u16,
        opnum: Option<u16>,
        alloc_hint: u32,
    ) -> Result<Option<Bytes>> {
        // Verify call ID
        if header.call_id != self.call_id {
            return Err(RpcError::CallIdMismatch {
                expected: self.call_id,
                got: header.call_id,
            });
        }

        let is_first = header.packet_flags.is_first_frag();
        let is_last = header.packet_flags.is_last_frag();

        // Handle first fragment
        if is_first {
            if self.received_first {
                return Err(RpcError::FragmentAssemblyError(
                    "received duplicate first fragment".to_string(),
                ));
            }
            self.received_first = true;
            self.context_id = ctx_id;
            self.opnum = opnum;
            if alloc_hint > 0 {
                self.expected_size = Some(alloc_hint);
                self.stub_data.reserve(alloc_hint as usize);
            }
        } else if !self.received_first {
            return Err(RpcError::FragmentOutOfOrder);
        }

        // Verify context ID consistency
        if ctx_id != self.context_id {
            return Err(RpcError::ContextMismatch);
        }

        // Add stub data
        self.stub_data.extend_from_slice(stub);

        // Handle last fragment
        if is_last {
            if self.received_last {
                return Err(RpcError::FragmentAssemblyError(
                    "received duplicate last fragment".to_string(),
                ));
            }
            self.received_last = true;
        }

        // Check if assembly is complete
        if self.received_first && self.received_last {
            let complete_data = self.stub_data.split().freeze();
            Ok(Some(complete_data))
        } else {
            Ok(None)
        }
    }

    /// Reset the assembler for reuse with a new call.
    pub fn reset(&mut self, call_id: u32) {
        self.call_id = call_id;
        self.stub_data.clear();
        self.context_id = 0;
        self.opnum = None;
        self.received_first = false;
        self.received_last = false;
        self.expected_size = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dcerpc::PacketType;

    #[test]
    fn test_max_stub_size_calculation() {
        // Default max_frag=4280, no auth, no object UUID
        // Overhead = 16 (header) + 8 (body) = 24
        // Max stub = 4280 - 24 = 4256
        let max_stub = FragmentGenerator::max_stub_size(4280, 0, false);
        assert_eq!(max_stub, 4256);

        // With object UUID (request with object)
        // Overhead = 16 + 8 + 16 = 40
        // Max stub = 4280 - 40 = 4240
        let max_stub = FragmentGenerator::max_stub_size(4280, 0, true);
        assert_eq!(max_stub, 4240);

        // With auth (16 byte signature)
        // Overhead = 16 + 8 + 15 (padding) + 8 (auth header) + 16 (auth value) = 63
        // Max stub = 4280 - 63 = 4217
        let max_stub = FragmentGenerator::max_stub_size(4280, 16, false);
        assert_eq!(max_stub, 4217);
    }

    #[test]
    fn test_fragment_single_pdu() {
        // Small stub data that fits in one fragment
        let stub = Bytes::from(vec![0u8; 100]);
        let request = RequestPdu::new(1, 5, stub.clone());

        let fragments = FragmentGenerator::fragment_request(&request, 4280);

        assert_eq!(fragments.len(), 1);
        assert!(fragments[0].header.packet_flags.is_first_frag());
        assert!(fragments[0].header.packet_flags.is_last_frag());
        assert_eq!(fragments[0].stub_data, stub);
    }

    #[test]
    fn test_fragment_multiple_pdus() {
        // Large stub data that requires multiple fragments
        let total_size = 10000;
        let stub = Bytes::from(vec![0u8; total_size]);
        let request = RequestPdu::new(1, 5, stub.clone());

        // Use small max_frag for testing: 1000 bytes
        // Overhead = 24, so max_stub = 976 per fragment
        let fragments = FragmentGenerator::fragment_request(&request, 1000);

        // 10000 / 976 = 10.24 -> 11 fragments
        assert!(fragments.len() > 1);

        // Verify first fragment
        assert!(fragments[0].header.packet_flags.is_first_frag());
        assert!(!fragments[0].header.packet_flags.is_last_frag());
        assert_eq!(fragments[0].header.call_id, 1);
        assert_eq!(fragments[0].opnum, 5);
        assert_eq!(fragments[0].alloc_hint, total_size as u32);

        // Verify middle fragments
        for frag in &fragments[1..fragments.len() - 1] {
            assert!(!frag.header.packet_flags.is_first_frag());
            assert!(!frag.header.packet_flags.is_last_frag());
        }

        // Verify last fragment
        let last = fragments.last().unwrap();
        assert!(!last.header.packet_flags.is_first_frag());
        assert!(last.header.packet_flags.is_last_frag());

        // Verify total data reconstructed
        let total_stub: Vec<u8> = fragments
            .iter()
            .flat_map(|f| f.stub_data.iter().copied())
            .collect();
        assert_eq!(total_stub.len(), total_size);
    }

    #[test]
    fn test_fragment_response() {
        let total_size = 5000;
        let stub = Bytes::from(vec![0xAA; total_size]);
        let response = ResponsePdu::new(42, stub.clone());

        // Use small max_frag: 1000 bytes
        let fragments = FragmentGenerator::fragment_response(&response, 1000);

        assert!(fragments.len() > 1);

        // Verify call_id preserved
        for frag in &fragments {
            assert_eq!(frag.header.call_id, 42);
            assert_eq!(frag.alloc_hint, total_size as u32);
        }

        // Reconstruct and verify
        let total_stub: Vec<u8> = fragments
            .iter()
            .flat_map(|f| f.stub_data.iter().copied())
            .collect();
        assert_eq!(total_stub.len(), total_size);
        assert!(total_stub.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn test_assembler_complete() {
        let mut assembler = FragmentAssembler::new(1);

        // Create headers for 3 fragments
        let mut header1 = PduHeader::new(PacketType::Request, 1);
        header1.packet_flags = PacketFlags::new();
        header1.packet_flags.set_first_frag();

        let mut header2 = PduHeader::new(PacketType::Request, 1);
        header2.packet_flags = PacketFlags::new(); // Middle fragment

        let mut header3 = PduHeader::new(PacketType::Request, 1);
        header3.packet_flags = PacketFlags::new();
        header3.packet_flags.set_last_frag();

        // Add fragments
        let result = assembler
            .add_fragment(&header1, b"Hello", 0, Some(5), 15)
            .unwrap();
        assert!(result.is_none());
        assert!(!assembler.is_complete());

        let result = assembler
            .add_fragment(&header2, b", ", 0, Some(5), 15)
            .unwrap();
        assert!(result.is_none());
        assert!(!assembler.is_complete());

        let result = assembler
            .add_fragment(&header3, b"World!", 0, Some(5), 15)
            .unwrap();
        assert!(result.is_some());
        assert!(assembler.is_complete());

        let complete = result.unwrap();
        assert_eq!(complete.as_ref(), b"Hello, World!");
        assert_eq!(assembler.opnum(), Some(5));
    }

    #[test]
    fn test_assembler_single_fragment() {
        let mut assembler = FragmentAssembler::new(1);

        // Single fragment with both flags
        let header = PduHeader::new(PacketType::Request, 1);
        // PacketFlags::complete() sets both FIRST_FRAG and LAST_FRAG

        let result = assembler
            .add_fragment(&header, b"Complete", 0, Some(0), 8)
            .unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_ref(), b"Complete");
    }

    #[test]
    fn test_assembler_call_id_mismatch() {
        let mut assembler = FragmentAssembler::new(1);

        let header = PduHeader::new(PacketType::Request, 2); // Wrong call_id

        let result = assembler.add_fragment(&header, b"data", 0, Some(0), 4);
        assert!(matches!(result, Err(RpcError::CallIdMismatch { .. })));
    }

    #[test]
    fn test_assembler_out_of_order() {
        let mut assembler = FragmentAssembler::new(1);

        // Try to add middle fragment without first
        let mut header = PduHeader::new(PacketType::Request, 1);
        header.packet_flags = PacketFlags::new(); // No FIRST_FRAG

        let result = assembler.add_fragment(&header, b"data", 0, Some(0), 4);
        assert!(matches!(result, Err(RpcError::FragmentOutOfOrder)));
    }

    #[test]
    fn test_alloc_hint_propagation() {
        let total_size = 3000;
        let stub = Bytes::from(vec![0u8; total_size]);
        let request = RequestPdu::new(1, 5, stub);

        let fragments = FragmentGenerator::fragment_request(&request, 1000);

        // All fragments should have the same alloc_hint = total stub size
        for frag in &fragments {
            assert_eq!(frag.alloc_hint, total_size as u32);
        }
    }

    #[test]
    fn test_assembler_reset() {
        let mut assembler = FragmentAssembler::new(1);

        // Add a fragment
        let header = PduHeader::new(PacketType::Request, 1);
        assembler
            .add_fragment(&header, b"data", 0, Some(5), 4)
            .unwrap();

        assert!(assembler.received_first);

        // Reset for new call
        assembler.reset(2);

        assert_eq!(assembler.call_id(), 2);
        assert!(!assembler.received_first);
        assert!(!assembler.received_last);
    }
}
