//! This module handles all output-related functionality.
//! It is responsible for formatting results for display in the console,
//! saving results to files in various formats (JSON, CSV, XML, text),
//! and managing the saving and loading of scan progress for resume functionality.

use crate::buster::{BustResult, ScanConfig};
use colored::Colorize;
use std::fs::write;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A struct that represents the full scan report for serialization, primarily for JSON output.
#[derive(serde::Serialize)]
pub struct ScanReport {
    target: String,
    start_time: String,
    end_time: String,
    duration: f64,
    total_requests: usize,
    success_count: usize,
    error_count: usize,
    filtered_count: usize,
    rate: f64,
    results: Vec<ReportEntry>,
}

/// A struct that represents a single entry in the scan report.
#[derive(serde::Serialize)]
pub struct ReportEntry {
    word: String,
    status: u16,
    content_length: Option<u64>,
    response_time_ms: u64,
    word_count: Option<usize>,
    url: String,
}

/// Formats a `BustResult` into a colorized string for console output.
pub fn format_output(result: &BustResult, config: &ScanConfig) -> String {
    match result {
        BustResult::Success(resp) => {
            let mut output = format!(
                "{word}: {status}",
                word = resp.word.green().bold(),
                status = resp.status.to_string().green()
            );

            if config.show_content_length {
                if let Some(len) = resp.content_length {
                    output.push_str(&format!(" [{len}B]").cyan().to_string());
                }
            }

            if config.show_response_time {
                output.push_str(
                    &format!(" [{}ms]", resp.response_time.as_millis())
                        .yellow()
                        .to_string(),
                );
            }

            output.push_str(&format!(" {}", "✓".green().bold()));
            output
        }
        BustResult::NotFound(resp) => {
            let mut output = format!(
                "{word}: {status}",
                word = resp.word.dimmed(),
                status = resp.status.to_string().red()
            );

            if config.show_content_length {
                if let Some(len) = resp.content_length {
                    output.push_str(&format!(" [{len}B]").cyan().to_string());
                }
            }

            if config.show_response_time {
                output.push_str(
                    &format!(" [{}ms]", resp.response_time.as_millis())
                        .yellow()
                        .to_string(),
                );
            }

            output
        }
        BustResult::Error(word, error) => {
            format!(
                "{word}: {error_type} - {err_msg}",
                word = word.red().bold(),
                error_type = "ERROR".red().bold(),
                err_msg = error.red()
            )
        }
        BustResult::Filtered(resp) => {
            format!(
                "{word}: {status} {tag}",
                word = resp.word.yellow().bold(),
                status = resp.status.to_string().yellow(),
                tag = "[FILTERED]".yellow().italic()
            )
        }
    }
}

/// Saves the collected scan results to a file in the specified format.
#[allow(clippy::too_many_arguments)] // TODO: refactor later by grouping args into a struct
pub async fn save_results(
    results: Arc<Mutex<Vec<BustResult>>>,
    config: &ScanConfig,
    output_file: &str,
    format: &str,
    scan_duration: f64,
    total_count: usize,
    found_count: usize,
    error_count: usize,
    filtered_count: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let unlocked_results = results.lock().await;

    match format {
        "json" => {
            let report_entries: Vec<ReportEntry> = unlocked_results
                .iter()
                .filter_map(|r| match r {
                    BustResult::Success(resp) | BustResult::NotFound(resp) => Some(ReportEntry {
                        word: resp.word.clone(),
                        status: resp.status,
                        content_length: resp.content_length,
                        response_time_ms: resp.response_time.as_millis() as u64,
                        word_count: resp.word_count,
                        url: format!("{}/{}", config.base_url.trim_end_matches('/'), resp.word),
                    }),
                    _ => None,
                })
                .collect();

            let report = ScanReport {
                target: config.base_url.clone(),
                start_time: chrono::Utc::now().to_rfc3339(),
                end_time: chrono::Utc::now().to_rfc3339(),
                duration: scan_duration,
                total_requests: total_count,
                success_count: found_count,
                error_count,
                filtered_count,
                rate: total_count as f64 / scan_duration,
                results: report_entries,
            };

            let json_output = serde_json::to_string_pretty(&report)?;
            write(output_file, json_output)?;
        }
        "csv" => {
            let mut csv_content =
                String::from("Word,Status,Content-Length,Response-Time-MS,Word-Count,URL\n");
            for result in unlocked_results.iter() {
                if let BustResult::Success(resp) | BustResult::NotFound(resp) = result {
                    csv_content.push_str(&format!(
                        "{},{},{},{},{},{}/{}\n",
                        resp.word,
                        resp.status,
                        resp.content_length.unwrap_or(0),
                        resp.response_time.as_millis(),
                        resp.word_count.unwrap_or(0),
                        config.base_url.trim_end_matches('/'),
                        resp.word
                    ));
                }
            }
            write(output_file, csv_content)?;
        }
        "xml" => {
            let mut xml_content =
                String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<scan_results>\n");
            for result in unlocked_results.iter() {
                if let BustResult::Success(resp) | BustResult::NotFound(resp) = result {
                    xml_content.push_str(&format!(
                        "  <result>\n    <word>{}</word>\n    <status>{}</status>\n    <content_length>{}</content_length>\n    <response_time_ms>{}</response_time_ms>\n    <url>{}/{}</url>\n  </result>\n",
                        resp.word,
                        resp.status,
                        resp.content_length.unwrap_or(0),
                        resp.response_time.as_millis(),
                        config.base_url.trim_end_matches('/'),
                        resp.word
                    ));
                }
            }
            xml_content.push_str("</scan_results>\n");
            write(output_file, xml_content)?;
        }
        _ => {
            // Default to plain text format
            let mut text_content = String::new();
            for result in unlocked_results.iter() {
                text_content.push_str(&format!("{}\n", format_output(result, config)));
            }
            write(output_file, text_content)?;
        }
    }
    Ok(())
}
