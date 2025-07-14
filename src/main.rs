//! This is the main entry point for the dirbuster-rs application.
//! It handles the entire scanning process, including:
//! - Parsing command-line arguments.
//! - Reading wordlists and user-agent files.
//! - Setting up the HTTP client and concurrency controls.
//! - Building the wildcard detection profile.
//! - Running the scan concurrently using Tokio and futures streams.
//! - Handling graceful shutdown on Ctrl+C.
//! - Displaying results and a final summary.
//! - Saving results and scan state to files.

use buster::{BustResult, ScanConfig, ScanState};
use clap::Parser;
use colored::*;
use futures::{StreamExt, stream};
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::signal;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::Instant;

mod args;
mod buster;
mod output;
mod parser;
mod wildcard;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = args::Args::parse();

    let word_list = parser::parse_word_list(&args.word_list)?;
    let user_agents = parser::parse_user_agents(&args.user_agents)?;

    let wl_len = word_list.len();
    if wl_len == 0 {
        println!("No words to process!");
        return Ok(());
    }

    // Set up shared configuration
    let config = Arc::new(ScanConfig {
        base_url: args.url.clone(),
        retries: args.retries,
        delay_min: args.delay_min,
        delay_max: args.delay_max,
        rotate_user_agent: args.rotate_user_agent,
        rotate_ip_headers: args.rotate_ip_headers,
        user_agents,
        auth_header: args.auth_header,
        basic_auth: args.basic_auth,
        bearer_token: args.bearer_token,
        custom_headers: parser::parse_custom_headers(&args.headers),
        filter_codes: args.filter_codes,
        filter_size: args
            .filter_size
            .as_ref()
            .and_then(|s| parser::parse_size_filter(s)),
        filter_time: args.filter_time,
        filter_words: args
            .filter_words
            .as_ref()
            .and_then(|s| parser::parse_word_filter(s)),
        show_content_length: args.show_content_length,
        show_response_time: args.show_response_time,
        detect_wildcards: args.detect_wildcards,
    });

    // Semaphore to limit concurrency
    let semaphore = Arc::new(Semaphore::new(args.threads));

    // Configure the HTTP client
    let mut client_builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .connect_timeout(Duration::from_secs(10))
        .tcp_keepalive(Duration::from_secs(60))
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(args.threads.min(25))
        .user_agent("dirbuster-rs/1.0 (+https://github.com/ConeDjordjic/dirbuster-rs)");

    if args.cookie_jar {
        client_builder = client_builder.cookie_store(true);
    }

    if let Some(proxy_url) = &args.proxy {
        client_builder = client_builder.proxy(reqwest::Proxy::all(proxy_url)?);
    }

    let client = Arc::new(client_builder.build()?);

    // Set up the progress bar
    let progress_bar = if args.no_progress {
        None
    } else {
        let pb = ProgressBar::new(wl_len as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}) {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );
        pb.set_message("Scanning...");
        Some(pb)
    };

    // Build the wildcard detection profile
    let wildcard_profile = wildcard::build_wildcard_profile(&client, &config).await;

    // Set up shared state
    let state = Arc::new(ScanState {
        global_delay: AtomicU64::new(0),
        found_count: AtomicUsize::new(0),
        error_count: AtomicUsize::new(0),
        filtered_count: AtomicUsize::new(0),
        should_stop: AtomicBool::new(false),
        wildcard_profile,
    });

    // Handle Ctrl+C for graceful shutdown
    let state_clone = state.clone();
    tokio::spawn(async move {
        if signal::ctrl_c().await.is_ok() {
            println!("\nReceived Ctrl+C, stopping scan gracefully...");
            state_clone.should_stop.store(true, Ordering::Relaxed);
        }
    });

    let start = Instant::now();
    let all_results: Arc<Mutex<Vec<BustResult>>> = Arc::new(Mutex::new(Vec::new()));

    // Create a stream of tasks to be executed concurrently
    let word_stream = stream::iter(word_list.into_iter().map(|word| {
        let sem = semaphore.clone();
        let client = client.clone();
        let config = config.clone();
        let state = state.clone();
        let pb = progress_bar.clone();
        let all_results_clone = all_results.clone();

        async move {
            let _permit = sem.acquire().await.expect("Semaphore error");
            let result = buster::bust_url_with_retry(&client, word.clone(), &config, &state).await;

            if let Some(ref pb) = pb {
                pb.inc(1);
            }

            let result_clone = result.clone();
            let mut unlocked_all_results_clone = all_results_clone.lock().await;

            // Update counters based on the result
            match &result {
                BustResult::Success(_resp) => {
                    state.found_count.fetch_add(1, Ordering::Relaxed);
                    unlocked_all_results_clone.push(result_clone);
                }
                BustResult::NotFound(_resp) => {
                    unlocked_all_results_clone.push(result_clone);
                }
                BustResult::Error(_, _) => {
                    let errors = state.error_count.fetch_add(1, Ordering::Relaxed) + 1;
                    if let Some(ref pb) = pb {
                        pb.set_message(format!("Scanning... Errors: {errors}"));
                    }
                    unlocked_all_results_clone.push(result_clone);
                }
                BustResult::Filtered(_resp) => {
                    state.filtered_count.fetch_add(1, Ordering::Relaxed);
                    unlocked_all_results_clone.push(result_clone);
                }
            }

            result
        }
    }));

    // Buffer the stream to control the level of concurrency
    let buffered_stream = word_stream.buffer_unordered(args.threads);

    // Process the results as they come in
    buffered_stream
        .for_each(|result| {
            let pb = progress_bar.clone();
            let config_clone = config.clone();

            async move {
                match result {
                    BustResult::Success(_) => {
                        let output = output::format_output(&result, &config_clone);
                        if let Some(ref pb) = pb {
                            pb.suspend(|| println!("{output}"));
                        } else {
                            println!("{output}");
                        }
                    }
                    BustResult::NotFound(_) => {
                        if !args.only_success {
                            let output = output::format_output(&result, &config_clone);
                            if let Some(ref pb) = pb {
                                pb.suspend(|| println!("{output}"));
                            } else {
                                println!("{output}");
                            }
                        }
                    }
                    BustResult::Error(_, _) => {
                        if !args.only_success {
                            let output = output::format_output(&result, &config_clone);
                            if let Some(ref pb) = pb {
                                pb.suspend(|| println!("{output}"));
                            } else {
                                println!("{output}");
                            }
                        }
                    }
                    BustResult::Filtered(_) => {
                        // Do not print filtered results to the console
                    }
                }
            }
        })
        .await;

    if let Some(ref pb) = progress_bar {
        pb.finish_with_message("Scan complete!");
    }

    let elapsed = start.elapsed();
    let final_found = state.found_count.load(Ordering::Relaxed);
    let final_errors = state.error_count.load(Ordering::Relaxed);
    let final_filtered = state.filtered_count.load(Ordering::Relaxed);

    // Save final results to a file if specified
    if let Some(output_file) = &args.output_file {
        output::save_results(
            all_results,
            &config,
            output_file,
            &args.output_format,
            elapsed.as_secs_f64(),
            wl_len,
            final_found,
            final_errors,
            final_filtered,
        )
        .await?;
        println!("Results saved to: {output_file}");
    }

    // Print the final summary
    println!("\n{}", "Summary:".bold().underline().blue());
    println!(
        "{:<15}{}",
        "Total words:".bold(),
        wl_len.to_string().white()
    );
    println!("{:<15}{}", "Found:".bold(), final_found.to_string().green());
    println!("{:<15}{}", "Errors:".bold(), final_errors.to_string().red());
    println!(
        "{:<15}{}",
        "Filtered:".bold(),
        final_filtered.to_string().yellow()
    );
    println!("{:<15}{:?}", "Elapsed:".bold(), elapsed);
    println!(
        "{:<15}{:.2} req/sec",
        "Rate:".bold(),
        wl_len as f64 / elapsed.as_secs_f64()
    );

    Ok(())
}

#[cfg(test)]
mod tests;
