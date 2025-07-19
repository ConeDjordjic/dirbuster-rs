//! This module tests all major components including parsing, wildcard detection,
//! output formatting, and core busting functionality.

#[cfg(test)]
use crate::buster::{BustResult, DetailedResponse, ScanConfig, ScanState};
use crate::output::format_output;
use crate::parser::*;
use crate::wildcard::{WildcardProfile, WildcardSample};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::fs;

// Helper function to create a sample ScanConfig
fn create_test_config() -> ScanConfig {
    ScanConfig {
        base_url: "https://example.com".to_string(),
        retries: 2,
        delay_min: 0,
        delay_max: 0,
        rotate_user_agent: false,
        rotate_ip_headers: false,
        user_agents: vec!["test-agent".to_string()],
        auth_header: None,
        basic_auth: None,
        bearer_token: None,
        custom_headers: HashMap::new(),
        filter_codes: vec![],
        filter_size: None,
        filter_time: None,
        filter_words: None,
        show_content_length: true,
        show_response_time: true,
        detect_wildcards: false,
    }
}

// Helper function to create a sample ScanState
fn create_test_state() -> ScanState {
    ScanState {
        global_delay: AtomicU64::new(0),
        found_count: AtomicUsize::new(0),
        error_count: AtomicUsize::new(0),
        filtered_count: AtomicUsize::new(0),
        should_stop: AtomicBool::new(false),
        wildcard_profile: WildcardProfile::new(),
    }
}

// Helper function to create a sample DetailedResponse
fn create_test_response(word: &str, status: u16, content_length: Option<u64>) -> DetailedResponse {
    DetailedResponse {
        word: word.to_string(),
        status,
        content_length,
        response_time: Duration::from_millis(100),
        word_count: Some(50),
    }
}

// PARSER TESTS
#[tokio::test]
async fn test_parse_word_list_from_file() {
    let test_content = "admin\nlogin\ntest\n\nempty_line_above\n";
    let temp_file = "/tmp/test_wordlist.txt";
    fs::write(temp_file, test_content).await.unwrap();

    let result = parse_word_list(temp_file).unwrap();
    assert_eq!(result.len(), 4);
    assert_eq!(result[0], "admin");
    assert_eq!(result[1], "login");
    assert_eq!(result[2], "test");
    assert_eq!(result[3], "empty_line_above");

    fs::remove_file(temp_file).await.unwrap();
}

#[test]
fn test_parse_word_list_empty() {
    let temp_file = "/tmp/empty_wordlist.txt";
    std::fs::write(temp_file, "").unwrap();

    let result = parse_word_list(temp_file).unwrap();
    assert_eq!(result.len(), 0);

    std::fs::remove_file(temp_file).unwrap();
}

#[test]
fn test_parse_user_agents_default() {
    let result = parse_user_agents("").unwrap();
    assert_eq!(result.len(), 5);
    assert!(result[0].contains("Chrome"));
    assert!(result[1].contains("Safari"));
    assert!(result[2].contains("Firefox"));
    assert!(result[3].contains("iPhone"));
    assert!(result[4].contains("dirbuster-rs"));
}

#[tokio::test]
async fn test_parse_user_agents_from_file() {
    let test_content = "Mozilla/5.0 (Test) Agent1\nMozilla/5.0 (Test) Agent2\n";
    let temp_file = "/tmp/test_user_agents.txt";
    fs::write(temp_file, test_content).await.unwrap();

    let result = parse_user_agents(temp_file).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0], "Mozilla/5.0 (Test) Agent1");
    assert_eq!(result[1], "Mozilla/5.0 (Test) Agent2");

    fs::remove_file(temp_file).await.unwrap();
}

#[test]
fn test_parse_custom_headers() {
    let headers = vec![
        "Authorization: Bearer token123".to_string(),
        "X-API-Key: secret".to_string(),
        "Content-Type: application/json".to_string(),
    ];

    let result = parse_custom_headers(&headers);
    assert_eq!(result.len(), 3);
    assert_eq!(
        result.get("Authorization"),
        Some(&"Bearer token123".to_string())
    );
    assert_eq!(result.get("X-API-Key"), Some(&"secret".to_string()));
    assert_eq!(
        result.get("Content-Type"),
        Some(&"application/json".to_string())
    );
}

#[test]
fn test_parse_custom_headers_malformed() {
    let headers = vec![
        "Authorization: Bearer token123".to_string(),
        "MalformedHeader".to_string(),
        "X-API-Key: secret".to_string(),
    ];

    let result = parse_custom_headers(&headers);
    assert_eq!(result.len(), 2); // Only valid headers should be parsed
    assert_eq!(
        result.get("Authorization"),
        Some(&"Bearer token123".to_string())
    );
    assert_eq!(result.get("X-API-Key"), Some(&"secret".to_string()));
}

#[test]
fn test_parse_size_filter_range() {
    let result = parse_size_filter("100-500");
    assert_eq!(result, Some((100, 500)));
}

#[test]
fn test_parse_size_filter_single() {
    let result = parse_size_filter("404");
    assert_eq!(result, Some((404, 404)));
}

#[test]
fn test_parse_size_filter_invalid() {
    let result = parse_size_filter("invalid");
    assert_eq!(result, None);
}

#[test]
fn test_parse_word_filter_range() {
    let result = parse_word_filter("50-200");
    assert_eq!(result, Some((50, 200)));
}

#[test]
fn test_parse_word_filter_single() {
    let result = parse_word_filter("10");
    assert_eq!(result, Some((10, 10)));
}

#[test]
fn test_should_filter_response_by_status_code() {
    let mut config = create_test_config();
    config.filter_codes = vec![404, 403];

    let response = create_test_response("test", 404, Some(1000));
    assert!(should_filter_response(&response, &config));

    let response = create_test_response("test", 200, Some(1000));
    assert!(!should_filter_response(&response, &config));
}

#[test]
fn test_should_filter_response_by_content_length() {
    let mut config = create_test_config();
    config.filter_size = Some((100, 500));

    let response = create_test_response("test", 200, Some(50)); // Too small
    assert!(should_filter_response(&response, &config));

    let response = create_test_response("test", 200, Some(600)); // Too large
    assert!(should_filter_response(&response, &config));

    let response = create_test_response("test", 200, Some(300)); // Within range
    assert!(!should_filter_response(&response, &config));
}

#[test]
fn test_should_filter_response_by_response_time() {
    let mut config = create_test_config();
    config.filter_time = Some(50); // 50ms max

    let mut response = create_test_response("test", 200, Some(1000));
    response.response_time = Duration::from_millis(100); // Too slow
    assert!(should_filter_response(&response, &config));

    response.response_time = Duration::from_millis(30); // Within limit
    assert!(!should_filter_response(&response, &config));
}

#[test]
fn test_should_filter_response_by_word_count() {
    let mut config = create_test_config();
    config.filter_words = Some((20, 100));

    let mut response = create_test_response("test", 200, Some(1000));
    response.word_count = Some(10); // Too few words
    assert!(should_filter_response(&response, &config));

    response.word_count = Some(150); // Too many words
    assert!(should_filter_response(&response, &config));

    response.word_count = Some(50); // Within range
    assert!(!should_filter_response(&response, &config));
}

// WILDCARD TESTS
#[test]
fn test_wildcard_profile_creation() {
    let profile = WildcardProfile::new();
    assert!(profile.size_ranges.is_empty());
    assert!(profile.sha256_hashes.is_empty());
    assert!(profile.common_status_codes.is_empty());
    assert!(profile.title_patterns.is_empty());
    assert!(profile.error_message_patterns.is_empty());
    assert!(profile.header_patterns.is_empty());
    assert!(profile.line_count_ranges.is_empty());
    assert!(profile.word_count_ranges.is_empty());
    assert!(profile.html_tag_count_range.is_none());
}

#[test]
fn test_wildcard_sample_creation() {
    let headers = HashMap::from([
        ("content-type".to_string(), "text/html".to_string()),
        ("server".to_string(), "nginx".to_string()),
    ]);

    let html_body =
        r#"<html><head><title>404 Not Found</title></head><body>404 Not Found</body></html>"#;

    let sample = WildcardSample::from_response(html_body, 404, &headers);

    assert_eq!(sample.status_code, 404);
    assert_eq!(sample.size, html_body.len());
    assert_eq!(sample.title, Some("404 Not Found".to_string()));
    assert_eq!(sample.error_message, Some("404 Not Found".to_string()));
    assert_eq!(sample.line_count, 1);
    assert_eq!(sample.word_count, 5);
    assert_eq!(sample.html_tag_count, 8);
    assert_eq!(
        sample.headers.get("content-type"),
        Some(&"text/html".to_string())
    );
}

#[test]
fn test_wildcard_profile_add_sample() {
    let mut profile = WildcardProfile::new();
    let headers = HashMap::from([("content-type".to_string(), "text/html".to_string())]);

    let html_body =
        r#"<html><head><title>404 Not Found</title></head><body>404 Not Found</body></html>"#;
    let sample = WildcardSample::from_response(html_body, 404, &headers);

    profile.add_sample(&sample);

    assert!(profile.common_status_codes.contains(&404));
    assert!(profile.sha256_hashes.contains(&sample.sha256));
    assert!(profile.title_patterns.contains("404 Not Found"));
    assert!(profile.error_message_patterns.contains("404 Not Found"));
    assert!(!profile.size_ranges.is_empty());
    assert!(!profile.line_count_ranges.is_empty());
    assert!(!profile.word_count_ranges.is_empty());
    assert!(profile.html_tag_count_range.is_some());
}

#[test]
fn test_wildcard_profile_merge_ranges() {
    let mut ranges = vec![(100, 200), (300, 400)];
    WildcardProfile::merge_range(&mut ranges, 150, 250);

    // Should merge the overlapping ranges
    assert_eq!(ranges.len(), 2);
    assert!(ranges.contains(&(100, 250)));
    assert!(ranges.contains(&(300, 400)));
}

#[test]
fn test_wildcard_profile_is_likely_wildcard() {
    let mut profile = WildcardProfile::new();
    let headers = HashMap::from([("content-type".to_string(), "text/html".to_string())]);

    let html_body =
        r#"<html><head><title>404 Not Found</title></head><body>404 Not Found</body></html>"#;
    let sample = WildcardSample::from_response(html_body, 404, &headers);

    // Add the sample to build the profile
    profile.add_sample(&sample);

    // Test with the same sample - should be detected as wildcard
    assert!(profile.is_likely_wildcard(&sample));

    // Test with a different sample - should not be detected as wildcard
    let different_body =
        r#"<html><head><title>Welcome</title></head><body>Hello World</body></html>"#;
    let different_sample = WildcardSample::from_response(different_body, 200, &headers);
    assert!(!profile.is_likely_wildcard(&different_sample));
}

// OUTPUT TESTS
#[test]
fn test_format_output_success() {
    let config = create_test_config();
    let response = create_test_response("admin", 200, Some(1000));
    let result = BustResult::Success(response);

    let output = format_output(&result, &config);
    assert!(output.contains("admin"));
    assert!(output.contains("200"));
    assert!(output.contains("1000B"));
    assert!(output.contains("100ms"));
    assert!(output.contains("✓"));
}

#[test]
fn test_format_output_not_found() {
    let config = create_test_config();
    let response = create_test_response("nonexistent", 404, Some(500));
    let result = BustResult::NotFound(response);

    let output = format_output(&result, &config);
    assert!(output.contains("nonexistent"));
    assert!(output.contains("404"));
    assert!(output.contains("500B"));
    assert!(output.contains("100ms"));
    assert!(!output.contains("✓"));
}

#[test]
fn test_format_output_error() {
    let config = create_test_config();
    let result = BustResult::Error("test".to_string(), "Connection timeout".to_string());

    let output = format_output(&result, &config);
    assert!(output.contains("test"));
    assert!(output.contains("ERROR"));
    assert!(output.contains("Connection timeout"));
}

#[test]
fn test_format_output_filtered() {
    let config = create_test_config();
    let response = create_test_response("filtered", 200, Some(100));
    let result = BustResult::Filtered(response);

    let output = format_output(&result, &config);
    assert!(output.contains("filtered"));
    assert!(output.contains("200"));
    assert!(output.contains("[FILTERED]"));
}

#[test]
fn test_format_output_without_optional_fields() {
    let mut config = create_test_config();
    config.show_content_length = false;
    config.show_response_time = false;

    let response = create_test_response("test", 200, Some(1000));
    let result = BustResult::Success(response);

    let output = format_output(&result, &config);
    assert!(output.contains("test"));
    assert!(output.contains("200"));
    assert!(!output.contains("1000B"));
    assert!(!output.contains("100ms"));
}

// INTEGRATION TESTS
#[test]
fn test_detailed_response_creation() {
    let response = DetailedResponse {
        word: "test".to_string(),
        status: 200,
        content_length: Some(1000),
        response_time: Duration::from_millis(150),
        word_count: Some(75),
    };

    assert_eq!(response.word, "test");
    assert_eq!(response.status, 200);
    assert_eq!(response.content_length, Some(1000));
    assert_eq!(response.response_time, Duration::from_millis(150));
    assert_eq!(response.word_count, Some(75));
}

// EDGE CASE TESTS
#[test]
fn test_empty_html_wildcard_detection() {
    let headers = HashMap::new();
    let sample = WildcardSample::from_response("", 404, &headers);

    assert_eq!(sample.size, 0);
    assert_eq!(sample.title, None);
    assert_eq!(sample.error_message, None);
    assert_eq!(sample.line_count, 0);
    assert_eq!(sample.word_count, 0);
    assert_eq!(sample.html_tag_count, 0);
}

#[test]
fn test_malformed_html_wildcard_detection() {
    let headers = HashMap::new();
    let malformed_html = r#"<html><head><title>Test</title><body>No closing tags"#;
    let sample = WildcardSample::from_response(malformed_html, 200, &headers);

    assert_eq!(sample.title, Some("Test".to_string()));
    assert_eq!(sample.html_tag_count, 5);
}

#[test]
fn test_large_content_hash_sampling() {
    let headers = HashMap::new();
    let large_content = "A".repeat(5000); // Larger than HASH_SAMPLE_SIZE
    let sample = WildcardSample::from_response(&large_content, 200, &headers);

    assert_eq!(sample.size, 5000);
    assert!(!sample.sha256.is_empty());
    // The hash should be based on the first 1024 characters
}

#[test]
fn test_unicode_content_handling() {
    let headers = HashMap::new();
    let unicode_content = "Hello 世界! 🌍 Testing unicode handling";
    let sample = WildcardSample::from_response(unicode_content, 200, &headers);

    assert_eq!(sample.size, unicode_content.len());
    assert_eq!(sample.word_count, 6);
    assert!(!sample.sha256.is_empty());
}

// PERFORMANCE TESTS
#[test]
fn test_wildcard_profile_performance() {
    let mut profile = WildcardProfile::new();
    let headers = HashMap::from([("content-type".to_string(), "text/html".to_string())]);

    // Add many samples to test performance
    for i in 0..1000 {
        let html_body = format!(
            r#"<html><head><title>Page {i}</title></head><body>Content {i}</body></html>"#,
        );
        let sample = WildcardSample::from_response(&html_body, 404, &headers);
        profile.add_sample(&sample);
    }

    // Test that the profile still works correctly with many samples
    assert_eq!(profile.common_status_codes.len(), 1);
    assert_eq!(profile.sha256_hashes.len(), 1000);
    assert!(!profile.size_ranges.is_empty());
}

#[test]
fn test_concurrent_state_updates() {
    use std::sync::Arc;
    use std::thread;

    let state = Arc::new(create_test_state());
    let mut handles = vec![];

    // Spawn multiple threads to update state concurrently
    for _ in 0..10 {
        let state_clone = Arc::clone(&state);
        let handle = thread::spawn(move || {
            for _ in 0..100 {
                state_clone.found_count.fetch_add(1, Ordering::Relaxed);
                state_clone.error_count.fetch_add(1, Ordering::Relaxed);
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }

    // Check that all updates were applied correctly
    assert_eq!(state.found_count.load(Ordering::Relaxed), 1000);
    assert_eq!(state.error_count.load(Ordering::Relaxed), 1000);
}
