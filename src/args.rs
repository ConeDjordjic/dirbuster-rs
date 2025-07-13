//! This module defines the command-line arguments for the application.
//! It uses the `clap` crate to parse and validate user input.

use clap::Parser;

/// A fast, concurrent, and feature-rich directory and file buster.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// The base URL to scan.
    #[arg(short, long)]
    pub url: String,

    /// The number of concurrent threads to use for scanning.
    #[arg(short, long, default_value_t = 20)]
    pub threads: usize,

    /// Path to the wordlist file.
    #[arg(short, long)]
    pub word_list: String,

    /// Timeout in seconds for each HTTP request.
    #[arg(long, default_value_t = 5)]
    pub timeout: u64,

    /// Display only successful results (status codes 200-299).
    #[arg(long)]
    pub only_success: bool,

    /// Hide the progress bar during the scan.
    #[arg(long)]
    pub no_progress: bool,

    /// Minimum time in milliseconds to delay between requests.
    #[arg(long, default_value_t = 0)]
    pub delay_min: u64,

    /// Maximum time in milliseconds to delay between requests.
    #[arg(long, default_value_t = 0)]
    pub delay_max: u64,

    /// Number of times to retry a failed request.
    #[arg(long, default_value_t = 2)]
    pub retries: usize,

    /// Rotate User-Agent for each request from the user agents file or through pre-set defaults.
    #[arg(long)]
    pub rotate_user_agent: bool,

    /// Rotate IP-related headers (e.g., X-Forwarded-For) for each request.
    #[arg(long)]
    pub rotate_ip_headers: bool,

    /// Path to a file containing User-Agent strings, one per line.
    #[arg(long, default_value = "")]
    pub user_agents: String,

    /// HTTP proxy to use for requests (e.g., http://127.0.0.1:8080).
    #[arg(long)]
    pub proxy: Option<String>,

    /// Enable the reqwest cookie store to persist cookies between requests.
    #[arg(long, default_value_t = false)]
    pub cookie_jar: bool,

    /// Format for the output file (text, json, xml, csv).
    #[arg(long, default_value = "text")]
    pub output_format: String,

    /// Path to save the final scan results.
    #[arg(long)]
    pub output_file: Option<String>,

    /// Custom Authorization header to send with each request.
    #[arg(long)]
    pub auth_header: Option<String>,

    /// Basic authentication credentials in username:password format.
    #[arg(long)]
    pub basic_auth: Option<String>,

    /// Bearer token for authentication.
    #[arg(long)]
    pub bearer_token: Option<String>,

    /// Custom headers to send with each request, in key:value format.
    #[arg(long)]
    pub headers: Vec<String>,

    /// Filter out responses with these status codes.
    #[arg(long)]
    pub filter_codes: Vec<u16>,

    /// Filter responses by content size range (e.g., "100-500" or "404").
    #[arg(long)]
    pub filter_size: Option<String>,

    /// Filter responses that take longer than this time in milliseconds.
    #[arg(long)]
    pub filter_time: Option<u64>,

    /// Filter responses by word count range (e.g., "50-200").
    #[arg(long)]
    pub filter_words: Option<String>,

    /// Show the content length of the response in the output.
    #[arg(long)]
    pub show_content_length: bool,

    /// Show the response time in milliseconds in the output.
    #[arg(long)]
    pub show_response_time: bool,

    /// Enable automatic detection and filtering of wildcard responses.
    #[arg(long)]
    pub detect_wildcards: bool,

    /// Similarity threshold (0-100) for wildcard detection. Higher is stricter.
    #[arg(long)]
    pub wildcard_threshold: Option<u32>,
}
