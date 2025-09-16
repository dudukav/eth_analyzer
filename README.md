# Blockchain Transaction Analyzer

A Rust-based asynchronous tool for analyzing blockchain transactions, detecting anomalies, and identifying business patterns. The project provides utilities for scanning blocks, storing transactions, analyzing patterns, and exporting results in CSV format.

---

## Features

- **Anomaly Detection**
  - Large transactions
  - High-frequency transactions
  - Structuring and burst activity
  - High fees
  - Unusual operations
  - Transactions at unusual times
  - Blacklisted addresses

- **Business Pattern Detection**
  - Regular payments
  - Batch payments
  - DEX trading
  - NFT activity
  - Liquidity provision
  - Whales (high-value accounts)
  - Active traders
  - Arbitrage transactions

- **CSV Export**
  - Export anomalies and business patterns for further analysis

- **Blockchain Scanning**
  - Scan blocks asynchronously
  - Fetch and store transactions efficiently
  - Support for multiple DEXs and NFT contracts

---

## Modules

### `analize`

Contains functions to detect anomalies and business patterns from stored transactions. Operates on `SharedTxStorage` and returns structured results as `Anomaly` or `BusinessPattern` enums.

### `config`

Provides configuration constants and thresholds for anomaly and pattern detection. Includes parameters such as local/global thresholds, batch intervals, and others.

### `csv`

Utilities for exporting anomalies and business patterns to CSV files. Includes:

- `AnomalyCsv` and `BusinessPatternCsv` structures for CSV serialization.
- Functions `export_anomalies_csv` and `export_patterns_csv`.

### `models`

Core data structures for transaction analysis:

- `TransactionRecord` – Represents a blockchain transaction.
- `TxStorage` and `SharedTxStorage` – In-memory storage of transactions, organized by sender, receiver, and overall list.
- `Anomaly` and `BusinessPattern` – Enums for detected anomalies and patterns.
- `Severity` – Enum representing Weak or Strong severity levels.

### `scanner`

Functions to scan blockchain blocks, fetch transactions, and populate `TxStorage`. Interfaces with blockchain providers implementing the `Middleware` trait from `ethers-rs`.

---
