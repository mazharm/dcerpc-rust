//! Integration Test Harness
//!
//! Runs all integration tests and provides comprehensive reporting.
//!
//! # Usage
//!
//! Run all tests:
//! ```
//! cargo run -p integration-tests
//! ```
//!
//! Run specific test categories:
//! ```
//! cargo test -p integration-tests --test stress_tests
//! cargo test -p integration-tests --test apartment_tests
//! cargo test -p integration-tests --test complex_types_tests
//! cargo test -p integration-tests --test multi_hop_tests
//! cargo test -p integration-tests --test circular_call_tests
//! cargo test -p integration-tests --test pipe_tests
//! ```
//!
//! Run with increased logging:
//! ```
//! RUST_LOG=debug cargo run -p integration-tests
//! ```

mod common;

use std::process::Command;
use std::time::{Duration, Instant};
use common::TestSuiteResults;

/// Test category
#[derive(Debug, Clone)]
struct TestCategory {
    name: &'static str,
    description: &'static str,
    test_name: &'static str,
}

const TEST_CATEGORIES: &[TestCategory] = &[
    TestCategory {
        name: "Stress Tests",
        description: "Multi-threading at large scale, race condition detection",
        test_name: "stress_tests",
    },
    TestCategory {
        name: "Fragmentation Tests",
        description: "Large PDU transfer with multi-fragment support",
        test_name: "fragmentation_tests",
    },
    TestCategory {
        name: "Apartment Tests",
        description: "MTA and STA threading models for DCOM",
        test_name: "apartment_tests",
    },
    TestCategory {
        name: "Complex Types Tests",
        description: "MIDL NDR encoding for complex data types",
        test_name: "complex_types_tests",
    },
    TestCategory {
        name: "Multi-Hop Tests",
        description: "Chain of RPC calls (A->B->C)",
        test_name: "multi_hop_tests",
    },
    TestCategory {
        name: "Circular Call Tests",
        description: "Callback scenarios (A->B->A)",
        test_name: "circular_call_tests",
    },
    TestCategory {
        name: "Pipe Tests",
        description: "RPC pipe streaming scenarios",
        test_name: "pipe_tests",
    },
];

fn print_banner() {
    println!(r#"
================================================================================
     ____   ____ _____   ____  ____   ____   ___       _            _
    |  _ \ / ___|  ___| |  _ \|  _ \ / ___| |_ _|_ __ | |_ ___  ___| |_
    | | | | |   | |_    | |_) | |_) | |      | || '_ \| __/ _ \/ __| __|
    | |_| | |___|  _|   |  _ <|  __/| |___   | || | | | ||  __/\__ \ |_
    |____/ \____|_|     |_| \_\_|    \____| |___|_| |_|\__\___||___/\__|

               Comprehensive Integration Test Suite
================================================================================
"#);
}

fn print_test_categories() {
    println!("Test Categories:");
    println!("{}", "-".repeat(80));
    for (i, cat) in TEST_CATEGORIES.iter().enumerate() {
        println!("  {}. {} - {}", i + 1, cat.name, cat.description);
    }
    println!("{}", "-".repeat(80));
    println!();
}

fn run_test_category(category: &TestCategory) -> (bool, Duration, String) {
    println!("\n{}", "=".repeat(80));
    println!("Running: {}", category.name);
    println!("{}", "=".repeat(80));

    let start = Instant::now();

    let output = Command::new("cargo")
        .args(["test", "-p", "integration-tests", "--test", category.test_name, "--", "--nocapture"])
        .output();

    let duration = start.elapsed();

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            // Print output
            if !stdout.is_empty() {
                println!("{}", stdout);
            }
            if !stderr.is_empty() {
                eprintln!("{}", stderr);
            }

            let success = output.status.success();
            let summary = if success {
                "PASSED".to_string()
            } else {
                format!("FAILED (exit code: {:?})", output.status.code())
            };

            (success, duration, summary)
        }
        Err(e) => {
            (false, duration, format!("Failed to execute: {}", e))
        }
    }
}

fn main() {
    print_banner();
    print_test_categories();

    println!("Starting comprehensive test suite...\n");

    let total_start = Instant::now();
    let mut results = Vec::new();

    for category in TEST_CATEGORIES {
        let (success, duration, summary) = run_test_category(category);
        results.push((category.name, success, duration, summary));
    }

    let total_duration = total_start.elapsed();

    // Print final summary
    println!("\n{}", "=".repeat(80));
    println!("FINAL SUMMARY");
    println!("{}", "=".repeat(80));

    let passed = results.iter().filter(|(_, s, _, _)| *s).count();
    let failed = results.iter().filter(|(_, s, _, _)| !*s).count();

    println!("\nCategories: {} | Passed: {} | Failed: {}", results.len(), passed, failed);
    println!("Total Duration: {:?}", total_duration);
    println!();

    println!("{:<30} {:<10} {:<15} {}", "Category", "Status", "Duration", "Details");
    println!("{}", "-".repeat(80));

    for (name, success, duration, summary) in &results {
        let status = if *success { "PASS" } else { "FAIL" };
        println!("{:<30} {:<10} {:<15?} {}", name, status, duration, summary);
    }

    println!("{}", "=".repeat(80));

    // Exit with appropriate code
    if failed > 0 {
        println!("\nSome tests failed!");
        std::process::exit(1);
    } else {
        println!("\nAll tests passed!");
        std::process::exit(0);
    }
}
