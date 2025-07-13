//! This module contains the core logic for the directory busting process.
//! It defines the data structures for scan configuration and results,
//! and the main function for sending HTTP requests with retries and evasion techniques.

use crate::parser;
use crate::wildcard::*;
use rand::Rng;
use rand::prelude::IndexedRandom;
use reqwest::Client;
use reqwest::header::USER_AGENT;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::time::{Instant, sleep};

/// Represents the outcome of a single directory/file bust attempt.
#[derive(Debug, Clone)]
pub enum BustResult {
    /// A successful request (typically 2xx status code) that was not filtered.
    Success(DetailedResponse),
    /// A request that resulted in a non-successful status code (e.g., 404) and was not filtered.
    NotFound(DetailedResponse),
    /// A request that failed due to a network error or other issue.
    Error(String, String),
    /// A response that was filtered out based on user-defined criteria.
    Filtered(DetailedResponse),
}

/// Contains detailed information about a single HTTP response.
#[derive(Debug, Clone)]
pub struct DetailedResponse {
    /// The word from the wordlist that was used for this request.
    pub word: String,
    /// The HTTP status code of the response.
    pub status: u16,
    /// The content length of the response body, if available.
    pub content_length: Option<u64>,
    /// The time it took to receive the response.
    pub response_time: Duration,
    /// The number of words in the response body.
    pub word_count: Option<usize>,
}

/// Holds all the configuration settings for the scan.
/// This struct is shared across all concurrent tasks.
#[derive(Clone)]
pub struct ScanConfig {
    pub base_url: String,
    pub retries: usize,
    pub delay_min: u64,
    pub delay_max: u64,
    pub rotate_user_agent: bool,
    pub rotate_ip_headers: bool,
    pub user_agents: Vec<String>,
    pub auth_header: Option<String>,
    pub basic_auth: Option<String>,
    pub bearer_token: Option<String>,
    pub custom_headers: HashMap<String, String>,
    pub filter_codes: Vec<u16>,
    pub filter_size: Option<(u64, u64)>, // min, max
    pub filter_time: Option<u64>,
    pub filter_words: Option<(usize, usize)>,
    pub show_content_length: bool,
    pub show_response_time: bool,
    pub detect_wildcards: bool,
}

/// Holds the mutable state of the scan, shared across all concurrent tasks.
/// Uses atomic types and Mutexes for thread-safe operations.
pub struct ScanState {
    /// A global delay added to requests, used for backing off when rate-limited.
    pub global_delay: AtomicU64,
    /// Counter for successful (found) responses.
    pub found_count: AtomicUsize,
    /// Counter for requests that resulted in an error.
    pub error_count: AtomicUsize,
    /// Counter for responses that were filtered out.
    pub filtered_count: AtomicUsize,
    /// A flag to signal all tasks to stop gracefully (e.g., on Ctrl+C).
    pub should_stop: AtomicBool,
    /// The profile generated for detecting wildcard responses.
    pub wildcard_profile: WildcardProfile,
}

/// Represents the data saved to a file for resuming a scan.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ScanProgress {
    /// The list of words that have already been processed.
    pub processed_words: Vec<String>,
    /// The timestamp when the progress was saved.
    pub timestamp: u64,
}

/// Generates a random IP address string.
fn random_ip() -> String {
    let mut rng = rand::rng();
    format!(
        "{}.{}.{}.{}",
        rng.random_range(1..255),
        rng.random_range(0..255),
        rng.random_range(0..255),
        rng.random_range(1..255)
    )
}

/// Selects a random User-Agent string from the provided list.
fn random_user_agent(ua_vec: &[String]) -> &str {
    ua_vec
        .choose(&mut rand::rng())
        .map(|s| s.as_str())
        .unwrap_or("dirbuster-rs/1.0 (+https://github.com/ConeDjordjic/dirbuster-rs)")
}

/// Selects a random Referer header value.
fn random_referer() -> &'static str {
    let referers = [
        "https://google.com",
        "https://bing.com",
        "https://duckduckgo.com",
        "https://github.com",
    ];
    referers
        .choose(&mut rand::rng())
        .expect("Can't choose referer")
}

/// Selects a random Accept-Language header value.
fn random_language() -> &'static str {
    let langs = [
        "en-US,en;q=0.9",
        "en-GB,en;q=0.8",
        "fr-FR,fr;q=0.7",
        "de-DE,de;q=0.6",
        "es-ES,es;q=0.5",
    ];
    langs
        .choose(&mut rand::rng())
        .expect("Can't choose language")
}

/// Selects a random Accept-Encoding header value.
fn random_encoding() -> &'static str {
    let encs = ["gzip, deflate, br", "gzip, deflate", "br", "*"];
    encs.choose(&mut rand::rng())
        .expect("Can't choose language")
}

/// Performs a single HTTP GET request for a given word, with retry logic.
///
/// This is the core function of the scanner. It constructs the full URL,
/// applies delays, rotates headers, sends the request, and handles the response
/// or any errors, retrying as configured.
pub async fn bust_url_with_retry(
    client: &Client,
    word: String,
    config: &ScanConfig,
    state: &ScanState,
) -> BustResult {
    let mut rng = rand::rng();

    // Add a random suffix for cache-busting
    let suffix = match rng.random_range(0..4) {
        0 => format!("?_cb={}", rng.random_range(10000..99999)),
        1 => format!("#{}", rng.random_range(1000..9999)),
        2 => format!(";sessionid={}", rng.random_range(100000..999999)),
        _ => String::new(),
    };

    let full_path = format!(
        "{}/{}{}",
        config.base_url.trim_end_matches('/'),
        word,
        suffix
    );

    for attempt in 0..=config.retries {
        if state.should_stop.load(Ordering::Relaxed) {
            return BustResult::Error(word, "Scan stopped by user".to_string());
        }

        // Apply delay between requests
        let mut sleep_base = if config.delay_max > config.delay_min {
            rng.random_range(config.delay_min..=config.delay_max)
        } else {
            config.delay_min
        };

        let extra_backoff = state.global_delay.load(Ordering::Relaxed);
        sleep_base += extra_backoff;

        if sleep_base > 0 {
            let jitter = rng.random_range(0..100);
            sleep(Duration::from_millis(sleep_base + jitter)).await;
        }

        let start_time = Instant::now();
        let mut request = client.get(&full_path);

        // Apply header rotation and other evasion techniques
        if config.rotate_user_agent {
            request = request.header(USER_AGENT, random_user_agent(&config.user_agents));
        }

        if config.rotate_ip_headers {
            let spoofed_ip = random_ip();
            request = request
                .header("X-Forwarded-For", &spoofed_ip)
                .header("X-Real-IP", &spoofed_ip)
                .header("True-Client-IP", &spoofed_ip);
        }

        // Apply authentication headers
        if let Some(auth) = &config.auth_header {
            request = request.header("Authorization", auth);
        }

        if let Some(basic) = &config.basic_auth {
            if let Some((user, pass)) = basic.split_once(':') {
                request = request.basic_auth(user, Some(pass));
            }
        }

        if let Some(token) = &config.bearer_token {
            request = request.bearer_auth(token);
        }

        for (key, value) in &config.custom_headers {
            request = request.header(key, value);
        }

        // Apply common browser-like headers
        request = request
            .header("Referer", random_referer())
            .header("Accept-Language", random_language())
            .header("Accept-Encoding", random_encoding())
            .header(
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            )
            .header("DNT", "1")
            .header("Connection", "keep-alive")
            .header("Sec-Fetch-Site", "none")
            .header("Sec-Fetch-Mode", "navigate")
            .header("Sec-Fetch-User", "?1")
            .header("Sec-Fetch-Dest", "document")
            .header("Upgrade-Insecure-Requests", "1");

        // Occasionally add a small request body
        if rng.random_range(0..10) < 3 {
            request = request.body(" ".repeat(rng.random_range(10..50)));
        }

        match request.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let headers = response.headers().clone();
                let content_length = response.content_length();
                let response_time = start_time.elapsed();

                let response_text: String = response.text().await.unwrap_or_default();

                let word_count = if config.show_content_length || config.filter_words.is_some() {
                    Some(response_text.split_whitespace().count())
                } else {
                    None
                };

                let detailed_response = DetailedResponse {
                    word: word.clone(),
                    status,
                    content_length,
                    response_time,
                    word_count,
                };

                match status {
                    200..=299 => {
                        state.global_delay.store(0, Ordering::Relaxed);

                        if parser::should_filter_response(&detailed_response, config) {
                            return BustResult::Filtered(detailed_response);
                        }

                        let headers_map: HashMap<String, String> = headers
                            .iter()
                            .map(|(k, v)| {
                                (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())
                            })
                            .collect();

                        if config.detect_wildcards {
                            let sample =
                                WildcardSample::from_response(&response_text, status, &headers_map);
                            if state.wildcard_profile.is_likely_wildcard(&sample) {
                                return BustResult::Filtered(detailed_response);
                            }
                        }
                        return BustResult::Success(detailed_response);
                    }
                    429 => {
                        // Rate limited, increase global delay and retry
                        state.global_delay.fetch_add(500, Ordering::Relaxed);
                        if attempt < config.retries {
                            sleep(Duration::from_millis(1000 * (attempt + 1) as u64)).await;
                            continue;
                        }
                        return BustResult::Error(word, "Rate limited".to_string());
                    }
                    500..=599 => {
                        // Server error, retry after a short delay
                        if attempt < config.retries {
                            sleep(Duration::from_millis(500 * (attempt + 1) as u64)).await;
                            continue;
                        }

                        if parser::should_filter_response(&detailed_response, config) {
                            return BustResult::Filtered(detailed_response);
                        }

                        return BustResult::NotFound(detailed_response);
                    }
                    _ => {
                        // Handle other status codes (e.g., 404, 403)
                        if parser::should_filter_response(&detailed_response, config) {
                            return BustResult::Filtered(detailed_response);
                        }
                        return BustResult::NotFound(detailed_response);
                    }
                }
            }
            Err(e) => {
                let error_msg = e.to_string();
                // Retry on common network errors
                if (error_msg.contains("timeout")
                    || error_msg.contains("connection")
                    || error_msg.contains("dns"))
                    && attempt < config.retries
                {
                    sleep(Duration::from_millis(1000 * (attempt + 1) as u64)).await;
                    continue;
                }
                return BustResult::Error(word, error_msg);
            }
        }
    }

    BustResult::Error(word, "Max retries exceeded".to_string())
}
