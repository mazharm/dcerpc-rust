# DCE RPC Integration Test Suite

Comprehensive integration tests for the DCE RPC Rust implementation, covering MSRPC, DCOM, NDR encoding, and advanced scenarios.

## Test Categories

### 1. Stress Tests (`stress_tests.rs`)
Multi-threading and concurrency tests designed to expose race conditions:

- **High Concurrency Many Clients**: 50 clients, 100 requests each, simultaneous
- **Rapid Fire Single Client**: 1000 sequential requests from one client
- **Varying Payload Sizes**: Concurrent requests with 1-16KB payloads
- **Connection Churn**: Rapid connect/disconnect cycles
- **Parallel Requests Shared Connection**: 50 parallel requests on single connection
- **Data Integrity Under Load**: 20 clients, 200 requests each, checksum verification
- **Thundering Herd**: 100 clients connect simultaneously
- **Sustained Load**: 5-second continuous load test

### 2. Apartment Tests (`apartment_tests.rs`)
DCOM threading model tests for MTA and STA:

- **MTA Concurrent Calls**: Verify MTA allows true concurrency
- **STA Serialized Calls**: Verify STA serializes through message queue
- **MTA Many Objects**: 50 objects, 10 calls each
- **Apartment Dispatcher**: Routing calls to correct apartment
- **MTA High Contention**: 100 clients, 50 calls each on single MTA
- **STA Shutdown During Calls**: Graceful shutdown handling
- **Object Not Found**: Error handling for missing objects
- **Mixed Apartment Workload**: Combined MTA and STA operations

### 3. Complex Types Tests (`complex_types_tests.rs`)
MIDL NDR encoding for various data types:

- **Simple Struct**: Point {x, y} encoding/decoding
- **Conformant Array**: Variable-length arrays
- **NDR Strings**: ANSI string encoding (empty, short, long)
- **NDR Wide Strings**: Unicode strings with various characters
- **Nested Structures**: Complex nested types with optional fields
- **Unique Pointer**: Nullable pointer encoding
- **Large Data Transfer**: Up to 512KB transfers
- **String Processing**: String concatenation across RPC
- **Struct Transformation**: Server-side modification
- **Concurrent Complex Operations**: Mixed operations under load

### 4. Multi-Hop Tests (`multi_hop_tests.rs`)
Chain of RPC calls (A->B->C):

- **Three-Hop Chain**: Frontend -> Backend -> Database
- **Aggregate Through Chain**: Query with multiple DB calls
- **Concurrent Multi-Hop**: 20 clients through the chain
- **Multi-Hop MTA**: Chain using DCOM MTA apartments
- **Multi-Hop STA**: Chain using DCOM STA apartments

### 5. Circular Call Tests (`circular_call_tests.rs`)
Callback scenarios (A->B->A):

- **Simple Callback**: A calls B, B calls back to A
- **Concurrent Callbacks**: 20 concurrent circular call chains
- **Circular MTA**: Callbacks within MTA apartments
- **Circular STA**: Callbacks within STA apartments (reentrancy)
- **Deep Circular Recursion**: 10-level recursive callbacks

### 6. Pipe Tests (`pipe_tests.rs`)
RPC pipe streaming scenarios:

- **Basic Chunks**: Send/receive chunked data
- **Chunk Echo**: Round-trip data integrity
- **Sum Stream**: Process stream of integers
- **Large Pipe Transfer**: Up to 500KB streaming
- **Bidirectional Pipe**: Transform data in chunks
- **Concurrent Pipe Ops**: 10 clients, 20 ops each
- **Empty Pipe**: Edge case handling
- **Single Byte Chunks**: Worst-case fragmentation
- **Pipe Struct**: Test Pipe<T> API
- **Pipe Codec Roundtrip**: NDR encode/decode

## Running Tests

### Run All Tests (Recommended)

```bash
# Using the test harness
cargo run -p integration-tests

# Or using cargo test
cargo test -p integration-tests --all-targets
```

### Run Specific Test Category

```bash
# Stress tests
cargo test -p integration-tests --test stress_tests -- --nocapture

# Apartment tests
cargo test -p integration-tests --test apartment_tests -- --nocapture

# Complex types tests
cargo test -p integration-tests --test complex_types_tests -- --nocapture

# Multi-hop tests
cargo test -p integration-tests --test multi_hop_tests -- --nocapture

# Circular call tests
cargo test -p integration-tests --test circular_call_tests -- --nocapture

# Pipe tests
cargo test -p integration-tests --test pipe_tests -- --nocapture
```

### Run Individual Test

```bash
# Run a specific test
cargo test -p integration-tests --test stress_tests test_high_concurrency_many_clients -- --nocapture
```

### With Debug Logging

```bash
RUST_LOG=debug cargo test -p integration-tests -- --nocapture
```

### With Release Optimizations (for performance testing)

```bash
cargo test -p integration-tests --release -- --nocapture
```

## Test Configuration

Key parameters in `common.rs`:

```rust
// Port allocation starts at 10000
static NEXT_PORT: AtomicU16 = AtomicU16::new(10000);

// Adjust for stress tests
const NUM_CLIENTS: usize = 50;        // Number of concurrent clients
const REQUESTS_PER_CLIENT: usize = 100; // Requests per client
```

## Expected Output

Successful test run:
```
================================================================================
     DCE RPC Integration Test Suite
================================================================================

Test Categories:
--------------------------------------------------------------------------------
  1. Stress Tests - Multi-threading at large scale, race condition detection
  2. Apartment Tests - MTA and STA threading models for DCOM
  ...

Starting comprehensive test suite...

================================================================================
Running: Stress Tests
================================================================================
...
test result: ok. 8 passed; 0 failed

================================================================================
FINAL SUMMARY
================================================================================

Categories: 6 | Passed: 6 | Failed: 0
Total Duration: 45.123s

Category                       Status     Duration        Details
--------------------------------------------------------------------------------
Stress Tests                   PASS       12.345s        PASSED
Apartment Tests                PASS       8.234s         PASSED
...

All tests passed!
```

## Troubleshooting

### Port Conflicts
If tests fail with "address already in use":
```bash
# Check for processes using test ports
netstat -an | findstr "100[0-9][0-9]"

# Kill any leftover test processes
taskkill /F /IM integration-tests.exe
```

### Timeouts
For slow systems, increase test timeouts in individual test files:
```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
```

### Memory Issues
Reduce concurrent clients for memory-constrained systems:
```rust
const NUM_CLIENTS: usize = 10;  // Reduced from 50
```

## Architecture

```
tests/integration/
├── Cargo.toml              # Package configuration
├── README.md               # This file
└── src/
    ├── main.rs             # Test harness entry point
    ├── common.rs           # Shared utilities
    ├── stress_tests.rs     # Concurrency tests
    ├── apartment_tests.rs  # MTA/STA tests
    ├── complex_types_tests.rs  # NDR encoding tests
    ├── multi_hop_tests.rs  # Chain call tests
    ├── circular_call_tests.rs  # Callback tests
    └── pipe_tests.rs       # Streaming tests
```

## Dependencies

- `dcerpc`: Core DCE RPC implementation
- `dcom`: DCOM apartment support
- `midl-ndr`: NDR encoding/decoding
- `tokio`: Async runtime
- `bytes`: Buffer manipulation
- `futures`: Async utilities
- `parking_lot`: Fast synchronization
- `rand`: Random data generation

## Contributing

When adding new tests:

1. Choose the appropriate test file based on category
2. Use `init_logging()` at the start of each test
3. Use `next_port()` for server port allocation
4. Use `ConcurrentStats` for tracking success/failure
5. Print clear test results with expected values
6. Use assertions with descriptive messages
