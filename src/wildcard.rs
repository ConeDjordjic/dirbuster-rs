//! This module implements the logic for detecting and filtering wildcard responses.
//!
//! A wildcard response occurs when a server returns a "soft 404" page (often with a 200 OK status)
//! for any requested path that does not exist. This can clutter scan results.
//! This module builds a profile of what a "not found" page looks like by making requests
//! to known non-existent paths, and then compares subsequent responses against this profile.

use crate::ScanConfig;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// A pre-compiled regex to extract the content of a <title> tag.
static TITLE_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)<title>\s*(.*?)\s*</title>").unwrap());
/// A pre-compiled regex to find HTML tags.
static HTML_TAG_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"</?\w+[^>]*>").unwrap());

/// Represents a profile of a wildcard response.
///
/// This struct aggregates characteristics from multiple sample responses to non-existent pages
/// to create a robust signature for identifying other similar responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WildcardProfile {
    /// Ranges of content sizes observed in wildcard responses.
    pub size_ranges: Vec<(usize, usize)>,
    /// A set of SHA256 hashes of wildcard response bodies.
    pub sha256_hashes: HashSet<String>,
    /// A set of status codes observed in wildcard responses.
    pub common_status_codes: HashSet<u16>,
    /// A set of page titles found in wildcard responses.
    pub title_patterns: HashSet<String>,
    /// A set of common error messages found in wildcard responses.
    pub error_message_patterns: HashSet<String>,
    /// A map of header keys to sets of observed values in wildcard responses.
    pub header_patterns: HashMap<String, HashSet<String>>,
    /// Ranges of line counts observed in wildcard responses.
    pub line_count_ranges: Vec<(usize, usize)>,
    /// Ranges of word counts observed in wildcard responses.
    pub word_count_ranges: Vec<(usize, usize)>,
    /// The range of HTML tag counts observed in wildcard responses.
    pub html_tag_count_range: Option<(usize, usize)>,
}

impl WildcardProfile {
    /// Creates a new, empty `WildcardProfile`.
    pub fn new() -> Self {
        Self {
            size_ranges: Vec::new(),
            sha256_hashes: HashSet::new(),
            common_status_codes: HashSet::new(),
            title_patterns: HashSet::new(),
            error_message_patterns: HashSet::new(),
            header_patterns: HashMap::new(),
            line_count_ranges: Vec::new(),
            word_count_ranges: Vec::new(),
            html_tag_count_range: None,
        }
    }

    /// Adds a new sample to the profile, updating its characteristics.
    pub fn add_sample(&mut self, resp: &WildcardSample) {
        self.common_status_codes.insert(resp.status_code);
        self.sha256_hashes.insert(resp.sha256.clone());

        let tol = (resp.size as f64 * 0.05).ceil() as usize;
        let min_size = resp.size.saturating_sub(tol);
        let max_size = resp.size + tol;

        for (k, v) in &resp.headers {
            self.header_patterns
                .entry(k.clone())
                .or_default()
                .insert(v.clone());
        }

        if let Some(title) = &resp.title {
            self.title_patterns.insert(title.clone());
        }
        if let Some(err) = &resp.error_message {
            self.error_message_patterns.insert(err.clone());
        }

        let line_tol = (resp.line_count as f64 * 0.1).ceil() as usize;
        let min_line = resp.line_count.saturating_sub(line_tol);
        let max_line = resp.line_count + line_tol;

        let word_tol = (resp.word_count as f64 * 0.1).ceil() as usize;
        let min_word = resp.word_count.saturating_sub(word_tol);
        let max_word = resp.word_count + word_tol;

        Self::merge_range(&mut self.size_ranges, min_size, max_size);
        Self::merge_range(&mut self.line_count_ranges, min_line, max_line);
        Self::merge_range(&mut self.word_count_ranges, min_word, max_word);

        self.update_tag_count_range(resp.html_tag_count);
    }

    /// Merges a new min/max pair into a vector of ranges.
    fn merge_range(ranges: &mut Vec<(usize, usize)>, min: usize, max: usize) {
        let mut merged = false;
        for (rmin, rmax) in ranges.iter_mut() {
            // This is the simplified condition for checking if two ranges overlap.
            if min <= *rmax && *rmin <= max {
                *rmin = (*rmin).min(min);
                *rmax = (*rmax).max(max);
                merged = true;
                break;
            }
        }
        if !merged {
            ranges.push((min, max));
        }
    }

    /// Updates the HTML tag count range with a new value.
    fn update_tag_count_range(&mut self, count: usize) {
        match &mut self.html_tag_count_range {
            Some((min, max)) => {
                *min = (*min).min(count);
                *max = (*max).max(count);
            }
            None => {
                self.html_tag_count_range = Some((count, count));
            }
        }
    }

    /// Checks if a given response sample is likely a wildcard based on the profile.
    pub fn is_likely_wildcard(&self, resp: &WildcardSample) -> bool {
        let mut match_count = 0;
        let mut confidence = 0.0;

        // 1. Exact SHA256 match
        if self.sha256_hashes.contains(&resp.sha256) {
            confidence += 0.9;
        }

        // 2. Title pattern match
        if let Some(title) = &resp.title {
            if self.title_patterns.contains(title) {
                confidence += 0.7;
                match_count += 1;
            }
        }

        // 3. Error message pattern match
        if let Some(err) = &resp.error_message {
            if self.error_message_patterns.contains(err) {
                confidence += 0.8;
                match_count += 1;
            }
        }

        // 4. Size range match
        let size_match = self
            .size_ranges
            .iter()
            .any(|(min, max)| resp.size >= *min && resp.size <= *max);
        if size_match {
            confidence += 0.3;
            match_count += 1;
        }

        // 5. Multiple metrics matching
        let line_match = self
            .line_count_ranges
            .iter()
            .any(|(min, max)| resp.line_count >= *min && resp.line_count <= *max);
        let word_match = self
            .word_count_ranges
            .iter()
            .any(|(min, max)| resp.word_count >= *min && resp.word_count <= *max);
        let tag_match = if let Some((min, max)) = self.html_tag_count_range {
            resp.html_tag_count >= min && resp.html_tag_count <= max
        } else {
            false
        };

        if line_match {
            match_count += 1;
            confidence += 0.2;
        }
        if word_match {
            match_count += 1;
            confidence += 0.2;
        }
        if tag_match {
            match_count += 1;
            confidence += 0.2;
        }

        // 6. Don't filter based on status code alone for 200 OK responses
        if resp.status_code == 200 {
            // For 200 OK, require high confidence or multiple matches
            confidence >= 0.7 || (match_count >= 3 && confidence >= 0.5)
        } else {
            // For non-200 status codes, be more aggressive
            if self.common_status_codes.contains(&resp.status_code) {
                confidence += 0.6;
            }
            confidence >= 0.5 || match_count >= 2
        }
    }
}

/// Represents the characteristics of a single HTTP response used for wildcard detection.
#[derive(Debug, Clone)]
pub struct WildcardSample {
    pub size: usize,
    pub sha256: String,
    pub status_code: u16,
    pub title: Option<String>,
    pub error_message: Option<String>,
    pub headers: HashMap<String, String>,
    pub line_count: usize,
    pub word_count: usize,
    pub html_tag_count: usize,
}

impl WildcardSample {
    /// Creates a `WildcardSample` from an HTTP response body, status, and headers.
    pub fn from_response(body: &str, status_code: u16, headers: &HashMap<String, String>) -> Self {
        let size = body.len();

        // --- Optimization ---
        // Hashing the full body is slow. We only hash a small sample for performance.
        const HASH_SAMPLE_SIZE: usize = 1024;
        let sample = if body.len() > HASH_SAMPLE_SIZE {
            // Find the nearest character boundary at or before HASH_SAMPLE_SIZE
            let mut end_index = HASH_SAMPLE_SIZE;
            while end_index > 0 && !body.is_char_boundary(end_index) {
                end_index -= 1;
            }
            &body[..end_index]
        } else {
            body
        };
        let sha256 = sha256_hex(sample);

        let (title, error_message) = extract_patterns(body);
        let line_count = body.lines().count();
        let word_count = body.split_whitespace().count();
        let html_tag_count = count_html_tags(body);

        Self {
            size,
            sha256,
            status_code,
            title,
            error_message,
            headers: headers.clone(),
            line_count,
            word_count,
            html_tag_count,
        }
    }
}
/// Computes the SHA256 hash of a string and returns it as a hex string.
fn sha256_hex(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Extracts common patterns (like title and error messages) from an HTML body.
fn extract_patterns(html: &str) -> (Option<String>, Option<String>) {
    // --- Optimization ---
    // Replaced slow DOM parser with a fast regex for title extraction.
    let title = TITLE_REGEX
        .captures(html)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().trim().to_string()));

    let known_errors = [
        "404 Not Found",
        "403 Forbidden",
        "500 Internal Server Error",
        "Access Denied",
        "Not Found",
        "Forbidden",
    ];

    let error_message = known_errors
        .iter()
        .find(|&msg| html.contains(msg))
        .map(|s| s.to_string());

    (title, error_message)
}

/// Counts the number of HTML tags in a string.
fn count_html_tags(html: &str) -> usize {
    // --- Optimization ---
    // Use the pre-compiled regex for a minor performance improvement.
    HTML_TAG_REGEX.find_iter(html).count()
}

/// Builds a `WildcardProfile` by sending requests to known non-existent paths.
///
/// This function is called at the beginning of a scan to establish a baseline
/// for what a "not found" response looks like on the target server.
pub async fn build_wildcard_profile(
    client: &reqwest::Client,
    config: &ScanConfig,
) -> WildcardProfile {
    let mut profile = WildcardProfile::new();

    let test_paths = vec![
        "does_not_exist_12345",
        "nonexistent_wildcard_test",
        "zzzzzzzzzzzzzzzzzzzz",
        "wildcard_probe_path",
    ];

    for path in test_paths {
        let url = format!("{}/{}", config.base_url.trim_end_matches('/'), path);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            let headers = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            if let Ok(body) = resp.text().await {
                let sample = WildcardSample::from_response(&body, status, &headers);
                profile.add_sample(&sample);
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }

    println!("Built wildcard profile with:");
    println!("  - {} size ranges", profile.size_ranges.len());
    println!("  - {} known hashes", profile.sha256_hashes.len());
    println!("  - {} header keys", profile.header_patterns.len());

    profile
}
