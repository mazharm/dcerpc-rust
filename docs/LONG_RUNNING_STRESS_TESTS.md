# Long-Running Stress Tests

This document describes the long-running stress tests for the DCE RPC / DCOM Rust implementation. These tests are designed to run for extended periods (hours or days) to uncover:

- Memory leaks
- Race conditions
- Resource exhaustion
- Performance degradation over time
- Data corruption under load

## Test Coverage

### Transports

| Transport | Test Name | Description |
|-----------|-----------|-------------|
| TCP | `test_tcp_msrpc_sustained_load` | Sustained MSRPC calls over TCP with data integrity verification |
| TCP | `test_tcp_msrpc_connection_churn` | Rapid connect/disconnect cycles to detect connection leaks |
| TCP | `test_tcp_msrpc_fragmentation_stress` | Large payloads (4KB-100KB) requiring PDU fragmentation |
| UDP | `test_udp_sustained_load` | Connectionless protocol stress with retry/timeout handling |
| Named Pipes | `test_named_pipe_sustained_load` | Windows named pipe transport (Windows only) |

### DCOM Threading Models

| Model | Test Name | Description |
|-------|-----------|-------------|
| MTA | `test_dcom_mta_sustained_load` | Multi-threaded apartment concurrent call verification |
| STA | `test_dcom_sta_thread_safety_stress` | Single-threaded apartment serialization verification |
| Mixed | `test_dcom_mixed_apartments_stress` | Combined MTA/STA with cross-apartment routing |

### NDR Encoding

| Test Name | Description |
|-----------|-------------|
| `test_ndr_encoding_stress` | Exercises all NDR types: arrays, strings, structs, pointers |

### Full Stack

| Test Name | Description |
|-----------|-------------|
| `test_full_stack_stress` | Combined test of TCP + UDP + DCOM MTA + DCOM STA + NDR |

## Running the Tests

### Prerequisites

1. Rust toolchain (1.70+)
2. Build the project in release mode for accurate performance metrics

### Quick Start

```bash
# Navigate to the project directory
cd dcerpc-rust

# Run all long-running stress tests for 1 hour (default)
cargo test --test longrunning_stress_tests --release -- --ignored --nocapture

# Run a specific test
cargo test --test longrunning_stress_tests test_tcp_msrpc_sustained_load --release -- --ignored --nocapture
```

### Configuration via Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `STRESS_TEST_DURATION_SECS` | 3600 (1 hour) | Test duration in seconds |
| `STRESS_TEST_CLIENTS` | 20 | Number of concurrent clients |
| `STRESS_TEST_REPORT_INTERVAL_SECS` | 60 | Progress report interval |
| `STRESS_TEST_MEMORY_CHECK_INTERVAL_SECS` | 300 | Memory sampling interval |

### Example Commands

```bash
# Run for 24 hours with 50 clients
STRESS_TEST_DURATION_SECS=86400 STRESS_TEST_CLIENTS=50 \
    cargo test --test longrunning_stress_tests --release -- --ignored --nocapture

# Run for 1 week (604800 seconds)
STRESS_TEST_DURATION_SECS=604800 \
    cargo test --test longrunning_stress_tests test_full_stack_stress --release -- --ignored --nocapture

# Run with frequent progress reports (every 30 seconds)
STRESS_TEST_DURATION_SECS=3600 STRESS_TEST_REPORT_INTERVAL_SECS=30 \
    cargo test --test longrunning_stress_tests --release -- --ignored --nocapture

# Run quick smoke test (5 minutes)
STRESS_TEST_DURATION_SECS=300 \
    cargo test --test longrunning_stress_tests --release -- --ignored --nocapture
```

### Running in Background

For multi-day tests, use `nohup` or `screen`/`tmux`:

```bash
# Using nohup
nohup cargo test --test longrunning_stress_tests --release -- --ignored --nocapture \
    > stress_test_$(date +%Y%m%d_%H%M%S).log 2>&1 &

# Using screen
screen -S stress_test
STRESS_TEST_DURATION_SECS=604800 cargo test --test longrunning_stress_tests --release -- --ignored --nocapture
# Press Ctrl+A then D to detach
# Reconnect with: screen -r stress_test
```

## Understanding the Output

### Progress Reports

During test execution, you'll see periodic progress reports like:

```
================================================================================
TCP MSRPC - Progress Report
================================================================================
Duration: 3600.05s
----------------------------------------
OPERATIONS:
  Total:     1234567
  Successful: 1234560 (99.99%)
  Failed:    7
  Timeouts:  0
----------------------------------------
LATENCY:
  Average:   1.234ms
  Minimum:   0.123ms
  Maximum:   45.678ms
----------------------------------------
THROUGHPUT:
  Overall:   342.93 ops/sec
  Recent:    345.12 ops/sec
----------------------------------------
CONNECTIONS:
  Created:   100
  Dropped:   95
  Errors:    0
----------------------------------------
DATA INTEGRITY:
  Corruptions:       0
  Checksum Failures: 0
----------------------------------------
MEMORY:
  Peak: 52428800 bytes (50.00 MB)
================================================================================
```

### Key Metrics to Watch

1. **Success Rate**: Should stay above 99% for TCP, 90% for UDP
2. **Data Corruptions**: Should always be 0
3. **Checksum Failures**: Should always be 0
4. **Memory Growth**: Watch for continuous growth indicating leaks
5. **Latency Trends**: Max latency spikes may indicate contention
6. **Throughput Stability**: Recent throughput should stay consistent

### Warning Signs

- **Memory Growth > 50%**: Possible memory leak
- **Any Data Corruptions**: Critical bug in serialization/transport
- **Declining Throughput**: Resource exhaustion or degradation
- **Increasing Latency**: Contention or resource starvation
- **STA Thread Safety Violations**: Threading model bug

## Test Descriptions

### TCP MSRPC Sustained Load (`test_tcp_msrpc_sustained_load`)

Maintains persistent TCP connections while continuously sending requests:
- Multiple concurrent clients
- Various operation types (echo, reverse, sum, checksum)
- NDR encoding/decoding of complex types
- Data integrity verification via checksums
- Periodic connection recycling (every 30 seconds)

**What it catches:**
- TCP connection leaks
- Buffer corruption
- NDR encoding bugs
- Memory leaks in request processing

### TCP Connection Churn (`test_tcp_msrpc_connection_churn`)

Rapidly creates and destroys TCP connections:
- Connect, send one request, disconnect
- No connection pooling
- Stress tests connection handling code

**What it catches:**
- Socket handle leaks
- Connection state corruption
- Race conditions in connection setup/teardown

### TCP Fragmentation Stress (`test_tcp_msrpc_fragmentation_stress`)

Sends large payloads that require PDU fragmentation:
- Payload sizes: 4KB, 8KB, 16KB, 32KB, 64KB, 100KB
- Verifies data integrity across fragments
- Tests fragment assembly logic

**What it catches:**
- Fragment reassembly bugs
- Buffer overflow/underflow
- Memory corruption in large transfers

### UDP Sustained Load (`test_udp_sustained_load`)

Tests the connectionless protocol:
- Activity ID based call tracking
- Automatic retry on timeout
- Smaller payloads (UDP size limits)

**What it catches:**
- Packet loss handling bugs
- Activity ID collision handling
- Sequence number wraparound issues

### DCOM MTA Stress (`test_dcom_mta_sustained_load`)

Tests multi-threaded apartment behavior:
- Verifies concurrent execution allowed
- Tracks maximum concurrency achieved
- Data integrity under concurrent access

**What it catches:**
- Lock contention issues
- Thread safety violations
- Object lifetime management bugs

### DCOM STA Thread Safety (`test_dcom_sta_thread_safety_stress`)

Tests single-threaded apartment serialization:
- Verifies calls are serialized
- Detects concurrent execution violations
- Message queue stress

**What it catches:**
- STA message queue bugs
- Reentrancy issues
- Thread affinity violations

### NDR Encoding Stress (`test_ndr_encoding_stress`)

Exercises all NDR data types:
- Conformant arrays (variable length)
- Conformant varying strings
- Complex nested structures
- Unique pointers
- Large buffer allocations

**What it catches:**
- NDR encoding bugs
- Alignment issues
- Buffer size calculations
- Pointer tracking bugs

### Full Stack Stress (`test_full_stack_stress`)

Combines all components simultaneously:
- TCP clients with NDR encoding
- UDP clients
- DCOM MTA calls
- DCOM STA calls

**What it catches:**
- Resource contention between components
- Global resource limits
- Cross-component interference

## Interpreting Failures

### Data Corruption Detected

```
assertion failed: `(left == right)`
  left: `0`,
 right: `5`: Data corruption detected!
```

**Action:** This is a critical bug. Check:
1. NDR encoding/decoding logic
2. Buffer handling in transport layer
3. Fragment assembly code
4. Thread safety of shared buffers

### STA Thread Safety Violations

```
assertion failed: STA thread safety violations detected! 3 concurrent calls
```

**Action:** Check:
1. STA message queue implementation
2. Call dispatcher routing logic
3. Thread affinity enforcement

### Memory Growth Warning

```
MEMORY:
  Peak: 1073741824 bytes (1024.00 MB)
  Growth: 536870912 bytes (100.00%)
  WARNING: Significant memory growth detected!
```

**Action:** Use a memory profiler to identify:
1. Leaked allocations
2. Growing caches without bounds
3. Accumulating connection state

### Low Success Rate

```
assertion failed: Success rate too low: 85.50%
```

**Action:** Check logs for:
1. Connection failures
2. Timeout patterns
3. Server error responses
4. Resource exhaustion (file descriptors, ports)

## Best Practices

1. **Start Small**: Run for 5 minutes first to catch obvious issues
2. **Monitor System Resources**: Watch file descriptors, memory, CPU
3. **Check Logs**: Enable `RUST_LOG=debug` for detailed tracing
4. **Release Mode**: Always run stress tests in release mode
5. **Isolated Environment**: Run on dedicated hardware if possible
6. **Baseline Metrics**: Establish baseline performance before changes
7. **Regular Runs**: Include stress tests in CI (shorter duration)

## Adding New Stress Tests

When adding new stress tests, follow this template:

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore] // Only run explicitly
async fn test_your_new_stress_test() {
    init_logging();

    let test_duration = get_test_duration();
    let num_clients = get_num_clients();
    let report_interval = get_report_interval();

    println!("\n");
    println!("=".repeat(80));
    println!("YOUR TEST NAME");
    println!("Duration: {:?}", test_duration);
    println!("Clients: {}", num_clients);
    println!("=".repeat(80));

    // Setup servers/resources

    let stats = Arc::new(ExtendedStats::new());
    let running = Arc::new(AtomicBool::new(true));

    // Start reporter
    let reporter_stats = stats.clone();
    let reporter_running = running.clone();
    let reporter_handle = tokio::spawn(async move {
        stats_reporter(reporter_stats, reporter_running, report_interval, "Your Test").await;
    });

    // Spawn client workers
    // ...

    // Wait for duration
    tokio::time::sleep(test_duration).await;
    running.store(false, Ordering::SeqCst);

    // Cleanup and report
    // ...

    stats.print_report("YOUR TEST - FINAL RESULTS");

    // Assertions
    assert_eq!(stats.data_corruption_count.load(Ordering::Relaxed), 0);
    assert!(stats.success_rate() > 99.0);
}
```

## Troubleshooting

### Tests Won't Start

1. Ensure `--ignored` flag is passed
2. Check for port conflicts
3. Verify Windows Firewall allows local connections

### High Failure Rate on Start

1. Server may need more startup time
2. Increase initial sleep duration
3. Check for resource limits (ulimit)

### Memory Profiling

```bash
# On Linux with valgrind
valgrind --tool=massif cargo test --test longrunning_stress_tests test_name --release -- --ignored --nocapture

# On Windows, use Visual Studio profiler or WinDbg
```

### CPU Profiling

```bash
# On Linux with perf
perf record cargo test --test longrunning_stress_tests test_name --release -- --ignored --nocapture
perf report
```
