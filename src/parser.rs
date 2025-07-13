//! This module contains various parsing functions used throughout the application.
//! It handles parsing of wordlists, user-agent files, custom headers, and filter strings.

use crate::buster::{DetailedResponse, ScanConfig};
use std::collections::HashMap;
use std::fs::read_to_string;

/// Parses a wordlist file into a vector of strings.
///
/// Each line in the file is treated as a separate word. Empty lines are ignored.
pub fn parse_word_list(wl_arg: &str) -> Result<Vec<String>, std::io::Error> {
    let content = read_to_string(wl_arg)?;
    let words: Vec<String> = content
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    Ok(words)
}

/// Parses a user-agents file into a vector of strings.
///
/// If the provided path is empty, it returns a default list of common user agents.
/// Otherwise, it reads the file, treating each line as a separate user agent.
pub fn parse_user_agents(ua_arg: &str) -> Result<Vec<String>, std::io::Error> {
    if ua_arg.is_empty() {
        return Ok(vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/114".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537".to_string(),
            "Mozilla/5.0 (X11; Linux x86_64) Firefox/108".to_string(),
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2) Mobile".to_string(),
            "dirbuster-rs/1.0 (+https://github.com/ConeDjordjic/dirbuster-rs)".to_string(),
        ]);
    }

    let content = read_to_string(ua_arg)?;
    let user_agents: Vec<String> = content
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();

    Ok(user_agents)
}

/// Parses a vector of custom header strings into a HashMap.
///
/// Each string is expected to be in "key:value" format.
pub fn parse_custom_headers(headers: &[String]) -> HashMap<String, String> {
    let mut header_map = HashMap::new();
    for header in headers {
        if let Some((key, value)) = header.split_once(':') {
            header_map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    header_map
}

/// Parses a size filter string (e.g., "100-500" or "404") into a min/max tuple.
pub fn parse_size_filter(filter: &str) -> Option<(u64, u64)> {
    if let Some((min, max)) = filter.split_once('-') {
        let min_val = min.parse().ok()?;
        let max_val = max.parse().ok()?;
        Some((min_val, max_val))
    } else {
        let val = filter.parse().ok()?;
        Some((val, val))
    }
}

/// Parses a word count filter string (e.g., "50-200" or "10") into a min/max tuple.
pub fn parse_word_filter(filter: &str) -> Option<(usize, usize)> {
    if let Some((min, max)) = filter.split_once('-') {
        let min_val = min.parse().ok()?;
        let max_val = max.parse().ok()?;
        Some((min_val, max_val))
    } else {
        let val = filter.parse().ok()?;
        Some((val, val))
    }
}

/// Determines if a response should be filtered based on the scan configuration.
///
/// Checks against status codes, content length, response time, and word count filters.
pub fn should_filter_response(response: &DetailedResponse, config: &ScanConfig) -> bool {
    // Filter by status code
    if config.filter_codes.contains(&response.status) {
        return true;
    }

    // Filter by content length
    if let (Some(content_length), Some((min, max))) = (response.content_length, config.filter_size)
    {
        if content_length < min || content_length > max {
            return true;
        }
    }

    // Filter by response time
    if let Some(max_time) = config.filter_time {
        if response.response_time.as_millis() > max_time as u128 {
            return true;
        }
    }

    // Filter by word count
    if let (Some(word_count), Some((min, max))) = (response.word_count, config.filter_words) {
        if word_count < min || word_count > max {
            return true;
        }
    }

    false
}
