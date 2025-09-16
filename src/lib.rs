/// # Modules Overview
///
/// This crate contains modules for analyzing blockchain transactions, detecting
/// anomalies and business patterns, configuring the scanner, and exporting data to CSV files.

/// `analize`
///
/// Contains functions for detecting transaction anomalies (e.g., large transactions,
/// high frequency, structuring, high fees) and business patterns (e.g., regular payments,
/// batch payments, DEX trading, NFT activity, liquidity providers, whales, active traders, arbitrage).
/// These functions operate on shared transaction storage (`SharedTxStorage`) and return
/// structured results as `Anomaly` or `BusinessPattern` enums.
///
/// Example usage:
/// ```rust,ignore
/// let anomalies = analize::detect_large_tx(&storage).await;
/// let patterns = analize::detect_regular_payments(&storage).await;
/// ```
pub mod analize;


pub mod config;

/// `csv`
///
/// Contains utilities to export detected anomalies and business patterns to CSV files.
/// Provides structures `AnomalyCsv` and `BusinessPatternCsv` to convert internal enums
/// into CSV-compatible formats, along with helper functions `export_anomalies_csv`
/// and `export_patterns_csv`.
///
/// Example usage:
/// ```rust,ignore
/// csv::export_anomalies_csv(&anomalies, "anomalies.csv")?;
/// csv::export_patterns_csv(&patterns, "patterns.csv")?;
/// ```
pub mod csv;

/// `models`
///
/// Defines core data structures used in the scanner and analyzers:
/// * `TransactionRecord` – Represents a blockchain transaction.
/// * `TxStorage` and `SharedTxStorage` – In-memory storage of transactions, organized by sender, receiver, and overall list.
/// * `Anomaly` and `BusinessPattern` – Enums representing detected anomalies and business patterns.
/// * `Severity` – Enum representing the strength of anomalies (Weak or Strong).
///
/// Example usage:
/// ```rust,ignore
/// let tx = models::TransactionRecord { hash: "...", from: "...", to: Some("...".to_string()), value: 1.0, ... };
/// ```
pub mod models;

/// `scanner`
///
/// Contains functions to scan blockchain data, retrieve blocks and transactions,
/// and populate `TxStorage`. This module interfaces with a blockchain provider
/// (implementing the `Middleware` trait from `ethers`) and supports asynchronous
/// fetching and processing of blocks.
///
/// Example usage:
/// ```rust,ignore
/// scanner::scan_block(&provider, start_block, end_block, &storage).await?;
/// ```
pub mod scanner;
