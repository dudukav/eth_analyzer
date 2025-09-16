use crate::{
    config::{K_LOCAL, K_LOCAL_FEE, PERC, THRESHOLD_TIME},
    models::{Anomaly, BusinessPattern, Severity, SharedTxStorage, TransactionRecord},
    scanner::fetch_sanctioned_addresses,
};
use chrono::{DateTime, Duration, Timelike, Utc};
use ethers::prelude::*;
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;

abigen!(
    UniswapV2Factory,
    r#"[
        function allPairsLength() external view returns (uint256)
        function allPairs(uint256) external view returns (address)
    ]"#
);

static FLAGGED_HASHES: Lazy<RwLock<HashSet<String>>> = Lazy::new(|| RwLock::new(HashSet::new()));

/// Scans all stored transactions and flags unusually large transfers as anomalies.
/// # Overview
/// This function inspects every transaction in [`SharedTxStorage`] and determines
/// whether it is significantly larger than typical activity, based on two criteria:
///
/// * **Local threshold:** Compares the transaction value against the historical mean
///   transaction value for the same sender (`local_mean`). If the value is more than
///   `K_LOCAL * local_mean`, it is considered anomalous.
/// * **Global threshold:** Compares the transaction value against a global threshold
///   derived from all transactions (`global_threshold`). If the value exceeds it,
///   it is considered anomalous.
/// If either the local or global condition is triggered, an [`Anomaly::LargeTx`]
/// is created and added to the result vector. If both conditions are triggered,
/// the anomaly is marked with a higher severity (`Severity::Strong`).
/// # Parameters
/// * `storage` — A shared transaction storage that provides read access to all
///   recorded transactions via an asynchronous `RwLock`.
/// # Returns
/// A `Vec<Anomaly>` containing one [`Anomaly::LargeTx`] entry for each flagged
/// transaction. If no transactions exceed either threshold, an empty vector is returned.
/// # Side Effects
/// * Each flagged transaction hash is inserted into the global `FLAGGED_HASHES` set
///   to prevent duplicate flagging in subsequent analyses.
/// # Behavior
/// * **Strong severity:** Both local and global thresholds are exceeded.
/// * **Weak severity:** Only one of the thresholds is exceeded.
/// * Non-anomalous transactions are ignored and do not appear in the result.
/// # Panics
/// This function does **not panic** on invalid timestamps — it falls back to
/// `Utc::now()` if the timestamp cannot be parsed from RFC 3339 format.
/// /// # Example
///
/// ```rust,ignore
/// // Given a populated `SharedTxStorage`
/// let anomalies = detect_large_tx(&storage).await;
/// for anomaly in anomalies {
///     match anomaly {
///         Anomaly::LargeTx { tx_hash, severity, .. } => {
///             println!("Detected large tx {} with severity {:?}", tx_hash, severity);
///         }
///         _ => {}
///     }
/// }
/// ```
pub async fn detect_large_tx(storage: &SharedTxStorage) -> Vec<Anomaly> {
    let mut anomalies: Vec<Anomaly> = Vec::new();
    let all_txs = storage.all_txs.read().await;
    let global_thershold = global_threshold(storage).await;
    for tx in all_txs.iter() {
        let sender = tx.from.clone();
        let local_mean = local_mean(storage, &sender);

        let local_flag = local_mean > 0.0 && tx.value > K_LOCAL * local_mean;
        let global_flag = tx.value > global_thershold;

        let timestamp = DateTime::parse_from_rfc3339(&tx.timestamp)
            .unwrap_or_else(|_| Utc::now().into())
            .with_timezone(&Utc);
        match (local_flag, global_flag) {
            (true, true) => {
                anomalies.push(Anomaly::LargeTx {
                    tx_hash: tx.hash.clone(),
                    severity: Severity::Strong,
                    reasons: vec![format!("Suspiciously large transaction: {}", &tx.value)],
                    timestamp: timestamp,
                });
                let mut hashes = FLAGGED_HASHES.write().await;
                hashes.insert(tx.hash.clone());
            }
            (true, false) | (false, true) => {
                anomalies.push(Anomaly::LargeTx {
                    tx_hash: tx.hash.clone(),
                    severity: Severity::Weak,
                    reasons: vec![format!("Suspiciously large transaction: {}", &tx.value)],
                    timestamp: timestamp,
                });
                let mut hashes = FLAGGED_HASHES.write().await;
                hashes.insert(tx.hash.clone());
            }
            (false, false) => {}
        };
    }

    anomalies
}

/// Detects accounts that perform an unusually high number of transactions
/// within a fixed time window and flags them as anomalies.
///
/// # Overview
///
/// This function analyzes transactions grouped by sender address (using
/// `storage.by_sender`) and counts how many transactions each sender
/// has submitted within the **last hour**.  
/// If the count exceeds [`THRESHOLD_TIME`], an [`Anomaly::HighFrequency`]
/// is created for that sender and added to the results.
///
/// # Parameters
///
/// * `storage` – A shared transaction storage containing a mapping from
///   sender addresses to their corresponding list of transactions (`by_sender`).
///
/// # Returns
///
/// Returns a `Vec<Anomaly>` where each element represents a sender that
/// exceeded the transaction frequency threshold in the last hour.
///
/// # Behavior
///
/// * Uses `Utc::now()` as the end of the interval and checks transactions
///   that occurred between `start_interval = now - 1 hour` and `end_interval = now`.
/// * If a sender's transaction count exceeds [`THRESHOLD_TIME`], a
///   [`HighFrequency`] anomaly is generated with:
///   * `sender` — the offending account address as a string
///   * `count` — number of transactions in the interval
///   * `reasons` — human-readable message describing the anomaly
/// * All transactions from that sender are also inserted into the global
///   [`FLAGGED_HASHES`] set to mark them as already flagged.
///
/// # Side Effects
///
/// * Modifies the global `FLAGGED_HASHES` to include all hashes of
///   transactions belonging to flagged senders. This prevents re-flagging
///   the same transactions in subsequent runs.
///
/// # Panics
///
/// This function does not panic under normal circumstances.  
/// It assumes that `tx.timestamp` values are already valid and comparable.
///
/// # Example
///
/// ```rust,ignore
/// let anomalies = detect_high_frequency(&storage).await;
/// for anomaly in anomalies {
///     match anomaly {
///         Anomaly::HighFrequency { sender, count, .. } => {
///             println!("Sender {} made {} txs in the last hour!", sender, count);
///         }
///         _ => {}
///     }
/// }
/// ```
pub async fn detect_high_frequency(storage: &SharedTxStorage) -> Vec<Anomaly> {
    let end_interval = Utc::now();
    let start_interval = end_interval - Duration::hours(1);

    let by_senders = &storage.by_sender;
    let mut anomalies: Vec<Anomaly> = Vec::new();
    for entry in by_senders.iter_mut() {
        let sender = entry.key();
        let txs = entry.value();

        let count = txs_in_interval(txs, start_interval, end_interval)
            .iter()
            .count();

        if count > THRESHOLD_TIME {
            anomalies.push(Anomaly::HighFrequency {
                sender: sender.to_string(),
                count: count,
                reasons: vec![format!("Too many transactions per hour: {}", &count)],
            });
            let mut hashes = FLAGGED_HASHES.write().await;
            for tx in txs.iter() {
                hashes.insert(tx.hash.clone());
            }
        }
    }

    anomalies
}


/// Detects potential structuring behavior in account transactions.
///
/// # Overview
///
/// Structuring (or "smurfing") refers to splitting large transactions into
/// multiple smaller transactions to avoid detection thresholds.  
/// This function analyzes transactions grouped by sender (`storage.by_sender`)
/// over the **last hour** and flags accounts that may be performing structuring.
///
/// For each sender, the function calculates:
/// * `count` – number of transactions in the interval
/// * `txs_sum` – total sum of transactions in the interval
/// * `local_mean` – sender-specific average transaction sum
/// * `global_threshold` – global average transaction threshold
///
/// Three flags are checked:
/// 1. `local_flag` – triggered if `txs_sum > K_LOCAL * local_mean`
/// 2. `global_flag` – triggered if `txs_sum > global_threshold`
/// 3. `count_flag` – triggered if `count > 10`
///
/// An anomaly is marked:
/// * `Severity::Strong` if all three flags are true
/// * `Severity::Weak` if only some of the flags are triggered
///
/// # Parameters
///
/// * `storage` – Shared transaction storage containing a mapping from sender addresses
///   to their corresponding list of transactions (`by_sender`).
///
/// # Returns
///
/// Returns a `Vec<Anomaly>` containing `Anomaly::Structuring` entries for senders
/// suspected of structuring behavior. Each anomaly includes:
/// * `sender` – the account address
/// * `count` – number of transactions in the interval
/// * `severity` – `Weak` or `Strong` depending on flags
/// * `reasons` – human-readable message describing why the sender was flagged
///
/// # Side Effects
///
/// * All transactions for flagged senders are added to the global
///   `FLAGGED_HASHES` set to prevent duplicate flagging in future analyses.
///
/// # Behavior
///
/// * Evaluates transactions within a 1-hour rolling window (from `Utc::now() - 1h` to `Utc::now()`).
/// * Uses `local_mean` and `global_threshold` to identify anomalous sums.
/// * Accounts that exceed only some thresholds are still flagged but with `Weak` severity.
/// * Accounts that exceed all thresholds are flagged with `Strong` severity.
///
/// # Example
///
/// ```rust,ignore
/// let anomalies = detect_structuring(&storage).await;
/// for anomaly in anomalies {
///     match anomaly {
///         Anomaly::Structuring { sender, count, severity, reasons } => {
///             println!(
///                 "Sender {} flagged with {} severity: {} transactions",
///                 sender, format!("{:?}", severity), count
///             );
///             for reason in reasons {
///                 println!("Reason: {}", reason);
///             }
///         }
///         _ => {}
///     }
/// }
/// ```
pub async fn detect_structuring(storage: &SharedTxStorage) -> Vec<Anomaly> {
    let end_interval = Utc::now();
    let start_interval = end_interval - Duration::hours(1);

    let by_senders = &storage.by_sender;
    let mut anomalies: Vec<Anomaly> = Vec::new();
    for entry in by_senders.iter() {
        let sender = entry.key();
        let txs = entry.value();

        let count = txs_in_interval(txs, start_interval, end_interval)
            .iter()
            .count();

        let txs_sum = txs_in_interval(txs, start_interval, end_interval)
            .iter()
            .map(|tx| tx.value)
            .sum::<f64>();

        let local_mean = local_mean(storage, sender);
        let global_thershold = global_threshold(storage).await;

        let local_flag = local_mean > 0.0 && txs_sum > K_LOCAL * local_mean;
        let global_flag = txs_sum > global_thershold;
        let count_flag = count > 10;

        match (local_flag, global_flag, count_flag) {
            (true, true, true) => {
                anomalies.push(Anomaly::Structuring {
                    sender: sender.to_string(),
                    count: count,
                    severity: Severity::Strong,
                    reasons: vec![format!(
                        "Suspected structuring\n Transations count: {},\n Transations sum: {}",
                        &count, &txs_sum
                    )],
                });
                let mut hashes = FLAGGED_HASHES.write().await;
                for tx in txs.iter() {
                    hashes.insert(tx.hash.clone());
                }
            }
            (false, false, false) => {}
            _ => {
                anomalies.push(Anomaly::Structuring {
                    sender: sender.to_string(),
                    count: count,
                    severity: Severity::Weak,
                    reasons: vec![format!(
                        "Suspected structuring\n Transations count: {},\n Transations sum: {}",
                        &count, &txs_sum
                    )],
                });
                let mut hashes = FLAGGED_HASHES.write().await;
                for tx in txs.iter() {
                    hashes.insert(tx.hash.clone());
                }
            }
        };
    }

    anomalies
}

/// Detects transactions with unusually high fees.
///
/// This asynchronous function analyzes all transactions in the provided
/// [`SharedTxStorage`] and identifies transactions with suspiciously high fees
/// compared to both the sender's typical transaction fees (local mean)
/// and a global threshold (e.g., percentile of all fees).
///
/// # Parameters
///
/// * `storage` – Shared transaction storage (`SharedTxStorage`) containing all transactions to analyze.
///
/// # Returns
///
/// Returns a `Vec<Anomaly>` containing detected high-fee anomalies:
/// * Each anomaly includes the transaction hash, calculated fee in ETH,
///   severity (`Strong` or `Weak`), reasons for detection, and timestamp.
///
/// # Detection Logic
///
/// 1. **Fee Calculation** – Transaction fee is computed as:
///    `fee_eth = gas_price_gwei * gas / 1e9`.
/// 2. **Local Comparison** – Compares fee against the sender's historical mean fee
///    multiplied by `K_LOCAL_FEE`.
/// 3. **Global Comparison** – Compares fee against a global percentile threshold of all fees.
/// 4. **Severity Assignment**:
///    * `Strong` if both local and global thresholds are exceeded.
///    * `Weak` if only one threshold is exceeded.
/// 5. **Flagging** – Transaction hashes of detected anomalies are added to
///    the global `FLAGGED_HASHES` set.
///
/// # Example
///
/// ```rust,ignore
/// let anomalies: Vec<Anomaly> = detect_high_fee(&storage).await;
/// for anomaly in anomalies {
///     println!("{:?}", anomaly);
/// }
/// ```
///
/// # Notes
///
/// * Timestamps are parsed from RFC 3339 strings in the transactions.
/// * Fees are expressed in ETH for clarity.
/// * The function is asynchronous due to read access to the shared storage.
pub async fn detect_high_fee(storage: &SharedTxStorage) -> Vec<Anomaly> {
    let all_txs = storage.all_txs.read().await;
    let all_fees: Vec<f64> = all_txs
        .iter()
        .map(|tx| tx.gas_price_gwei * tx.gas as f64 / 1e9)
        .collect();
    let global_threshold = percentile(&all_fees);

    let mut anomalies: Vec<Anomaly> = Vec::new();
    for tx in all_txs.iter() {
        let sender = &tx.from;
        let fee_eth = tx.gas_price_gwei * tx.gas as f64 / 1e9;
        let local_mean = local_mean_fee(storage, sender);

        let local_flag = local_mean > 0.0 && fee_eth > K_LOCAL_FEE * local_mean;
        let global_flag = fee_eth > global_threshold;

        let timestamp = DateTime::parse_from_rfc3339(&tx.timestamp)
            .unwrap_or_else(|_| Utc::now().into())
            .with_timezone(&Utc);
        match (local_flag, global_flag) {
            (true, true) => {
                anomalies.push(Anomaly::HighFee {
                    tx_hash: tx.hash.clone(),
                    fee_eth: fee_eth,
                    severity: Severity::Strong,
                    reasons: vec![format!("Suspiciously high fee: {}", fee_eth)],
                    timestamp: timestamp,
                });
                let mut hashes = FLAGGED_HASHES.write().await;
                hashes.insert(tx.hash.clone());
            }
            (true, false) | (false, true) => {
                anomalies.push(Anomaly::HighFee {
                    tx_hash: tx.hash.clone(),
                    fee_eth: fee_eth,
                    severity: Severity::Weak,
                    reasons: vec![format!("Suspiciously high fee: {}", fee_eth)],
                    timestamp: timestamp,
                });
                let mut hashes = FLAGGED_HASHES.write().await;
                hashes.insert(tx.hash.clone());
            }
            (false, false) => {}
        }
    }
    anomalies
}

pub async fn detect_blacklist_adresses(storage: &SharedTxStorage) -> Vec<Anomaly> {
    let blacklist: HashSet<String> = match fetch_sanctioned_addresses().await {
        Ok(set) => set,
        Err(_) => {
            eprintln!("⚠️ Не удалось загрузить санкционные адреса");
            HashSet::new()
        }
    };

    let all_txs = storage.all_txs.read().await;
    let mut anomalies = Vec::new();

    for tx in all_txs.iter() {
        let timestamp = DateTime::parse_from_rfc3339(&tx.timestamp)
            .unwrap_or_else(|_| Utc::now().into())
            .with_timezone(&Utc);
        if blacklist.contains(&tx.from) {
            anomalies.push(Anomaly::BlacklistedAddress {
                tx_hash: tx.hash.clone(),
                addres: tx.from.clone(),
                reasons: vec![format!(
                    "Transactions from a sanctioned address: {}",
                    &tx.from
                )],
                timestamp: timestamp,
            });
            let mut hashes = FLAGGED_HASHES.write().await;
            hashes.insert(tx.hash.clone());
        }

        if let Some(to) = &tx.to {
            if blacklist.contains(to) {
                anomalies.push(Anomaly::BlacklistedAddress {
                    tx_hash: tx.hash.clone(),
                    addres: to.clone(),
                    reasons: vec![format!("Transactions to a sanctioned address: {}", to)],
                    timestamp: timestamp,
                });
                let mut hashes = FLAGGED_HASHES.write().await;
                hashes.insert(tx.hash.clone());
            }
        }
    }

    anomalies
}

/// Detects transactions with unusual operational characteristics.
///
/// This asynchronous function analyzes all transactions in the provided
/// [`SharedTxStorage`] and flags transactions that deviate significantly
/// from typical values or exhibit unusual input data.
///
/// # Parameters
/// * `storage` – Shared transaction storage (`SharedTxStorage`) containing all transactions to analyze.
///
/// # Returns
/// Returns a `Vec<Anomaly>` containing detected unusual operation anomalies:
/// * Each anomaly includes the transaction hash, severity (`Strong` or `Weak`),
///   reasons for detection, and timestamp.
///
/// # Detection Logic
/// 1. **Value Threshold** – Compares transaction value against a global percentile threshold of all transaction values.
/// 2. **Gas Price Threshold** – Compares transaction gas price against a global percentile threshold of all gas prices.
/// 3. **Input Data Check** – Flags transactions with input not starting with `"0x"` or unusually long input (>100 characters).
/// 4. **Skip Already Flagged** – Transactions already present in `FLAGGED_HASHES` are skipped.
/// 5. **Severity Assignment**:
///    * `Strong` if transaction value or gas price is unusual.
///    * `Weak` if only the input data is unusual.
///
/// # Example
/// ```rust,ignore
/// let anomalies: Vec<Anomaly> = detect_unusual_op(&storage).await;
/// for anomaly in anomalies {
///     println!("{:?}", anomaly);
/// }
/// ```
///
/// # Notes
/// * Timestamps are parsed from RFC 3339 strings in the transactions.
/// * Transactions with unusual values or gas prices are considered more severe than those
///   with only unusual input data.
/// * The function is asynchronous due to read access to the shared storage.
pub async fn detect_unusual_op(storage: &SharedTxStorage) -> Vec<Anomaly> {
    let all_txs = storage.all_txs.read().await;
    let mut anomalies = Vec::new();

    let values = all_txs.iter().map(|tx| tx.value).collect();
    let gas_prices = all_txs.iter().map(|tx| tx.gas_price_gwei).collect();

    let value_threshold = percentile(&values);
    let gas_threshold = percentile(&gas_prices);

    for tx in all_txs.iter() {
        let flagged_hashes = FLAGGED_HASHES.read().await;
        if flagged_hashes.contains(&tx.hash) {
            continue;
        }

        let unusual_value = tx.value > value_threshold;
        let unusual_gas = tx.gas_price_gwei > gas_threshold;
        let unusual_input = !tx.input.starts_with("0x") || tx.input.len() > 100;

        if unusual_value || unusual_gas || unusual_input {
            let timestamp = DateTime::parse_from_rfc3339(&tx.timestamp)
                .unwrap_or_else(|_| Utc::now().into())
                .with_timezone(&Utc);
            anomalies.push(Anomaly::UnusualOp {
                tx_hash: tx.hash.clone(),
                severity: if unusual_value || unusual_gas {
                    Severity::Strong
                } else {
                    Severity::Weak
                },
                reasons: vec![format!(
                    "Unusual operation: value={}, gas={}, input_len={}",
                    tx.value,
                    tx.gas_price_gwei,
                    tx.input.len()
                )],
                timestamp: timestamp,
            });
        }
    }

    anomalies
}

/// Detects time-based anomalies in transactions.
///
/// This asynchronous function analyzes all transactions in the provided
/// [`SharedTxStorage`] and identifies transactions that occur at unusual times
/// (e.g., very early hours) or as part of burst activity within short intervals.
///
/// # Parameters
///
/// * `storage` – Shared transaction storage (`SharedTxStorage`) containing all transactions to analyze.
///
/// # Returns
/// Returns a `Vec<Anomaly>` containing detected time anomalies:
/// * `TimeAnomaly` – Transactions occurring at unusual times (before 6 AM UTC), marked as `Weak`.
/// * `BurstActivity` – Senders performing multiple transactions in a short interval (≥5 transactions within 10 minutes).
///
/// # Detection Logic
///
/// 1. **Unusual Time Detection** – Flags transactions occurring between 00:00 and 06:00 UTC as `TimeAnomaly`.
/// 2. **Burst Activity Detection** – Groups transactions by sender and sorts them by timestamp.  
///    Counts consecutive transactions within a 10-minute window:
///    * If ≥5 transactions occur in this interval, a `BurstActivity` anomaly is recorded for the sender.
/// 3. **Severity Assignment** – Time anomalies are marked as `Weak`. Burst activity severity is not explicitly assigned.
///
/// # Example
/// ```rust,ignore
/// let anomalies: Vec<Anomaly> = detect_time_anomalies(&storage).await;
/// for anomaly in anomalies {
///     println!("{:?}", anomaly);
/// }
/// ```
///
/// # Notes
/// * Timestamps are expected in RFC 3339 format in the transaction records.
/// * The function is asynchronous due to read access to the shared storage.
/// * Burst activity detection considers only transactions per sender and a sliding 10-minute window.
pub async fn detect_time_anomalies(storage: &SharedTxStorage) -> Vec<Anomaly> {
    let all_txs = storage.all_txs.read().await;
    let mut anomalies: Vec<Anomaly> = Vec::new();

    let burst_interval = chrono::Duration::minutes(10);

    let mut tx_times: HashMap<String, Vec<chrono::DateTime<chrono::Utc>>> = HashMap::new();

    for tx in all_txs.iter() {
        let ts: chrono::DateTime<chrono::Utc> = tx.timestamp.parse().unwrap();
        let hour = ts.hour();

        if hour <= 6 {
            let timestamp = DateTime::parse_from_rfc3339(&tx.timestamp)
                .unwrap_or_else(|_| Utc::now().into())
                .with_timezone(&Utc);
            anomalies.push(Anomaly::TimeAnomaly {
                tx_hash: tx.hash.clone(),
                severity: Severity::Weak,
                reasons: vec!["Transaction in unusual time".to_string()],
                timestamp: timestamp,
            });
        }

        tx_times.entry(tx.from.clone()).or_default().push(ts);
    }

    for (sender, times) in tx_times.iter() {
        let mut sorted_times = times.clone();
        sorted_times.sort();

        for i in 0..sorted_times.len() {
            let mut count = 1;
            let start = sorted_times[i];
            for j in i + 1..sorted_times.len() {
                if sorted_times[j] - start <= burst_interval {
                    count += 1;
                } else {
                    break;
                }
            }
            if count >= 5 {
                anomalies.push(Anomaly::BurstActivity {
                    sender: sender.to_string(),
                    reasons: vec![format!("Detected Burst activity from: {}", sender.clone())],
                });
                break;
            }
        }
    }

    anomalies
}

/// Detects regular (recurring) payment patterns from transaction history.
/// This asynchronous function analyzes all transactions in the provided
/// [`SharedTxStorage`] grouped by sender and receiver. It identifies senders
/// who make repeated payments with relatively consistent amounts, suggesting
/// a regular payment pattern (e.g., subscriptions, salaries, or automated transfers).
///
/// # Parameters
/// * `storage` – Shared transaction storage (`SharedTxStorage`) containing all transactions to analyze.
///
/// # Returns
///
/// Returns a `Vec<BusinessPattern>` containing detected regular payment patterns:
/// * `RegularPayments` – Includes the sender and a descriptive message.
///
/// # Detection Logic
/// 1. **Group by Sender and Receiver** – Transactions are grouped by the sender
///    and the optional receiver address (`tx.to`).
/// 2. **Filter Small Groups** – Only groups with 2 or more transactions are considered.
/// 3. **Sort by Timestamp** – Transactions within each group are sorted chronologically.
/// 4. **Calculate Value Consistency** – Computes the average transaction value and
///    average deviation from the mean.  
///    * If the deviation is within 10% of the average value, the pattern is considered regular.
/// 5. **Record Pattern** – Adds a `BusinessPattern::RegularPayments` entry for the sender.
///
/// # Example
/// ```rust,ignore
/// let patterns: Vec<BusinessPattern> = detect_regular_payments(&storage).await;
/// for pattern in patterns {
///     println!("{:?}", pattern);
/// }
/// ```
///
/// # Notes
///
/// * Timestamps are expected in RFC 3339 format in the transaction records.
/// * The function is asynchronous due to read access to the shared storage.
/// * Only the amount consistency is considered; timing regularity is not strictly enforced.
pub async fn detect_regular_payments(storage: &SharedTxStorage) -> Vec<BusinessPattern> {
    let by_sender = &storage.by_sender;

    let mut patterns: Vec<BusinessPattern> = Vec::new();
    for entry in by_sender {
        let sender = entry.key();
        let txs = entry.value();

        let mut groups: HashMap<Option<String>, Vec<&TransactionRecord>> = HashMap::new();
        for tx in txs {
            groups.entry(tx.to.clone()).or_default().push(tx);
        }

        for (_to, group) in groups {
            if group.len() < 2 {
                continue;
            }

            let mut sorted: Vec<&TransactionRecord> = group.clone();
            sorted.sort_by_key(|tx| tx.timestamp.clone());

            let mut intervals: Vec<i64> = vec![];
            for i in 1..sorted.len() {
                let prev: DateTime<Utc> = sorted[i - 1].timestamp.parse().unwrap();
                let curr: DateTime<Utc> = sorted[i].timestamp.parse().unwrap();
                intervals.push((curr - prev).num_seconds());
            }

            if intervals.len() > 0 {
                let mut sum_deviation = 0.0;
                let total: f64 = sorted.iter().map(|tx| tx.value).fold(0.0, |acc, x| acc + x);
                let avg_value = total / sorted.len() as f64;
                for tx in sorted.iter() {
                    sum_deviation += (tx.value - avg_value).abs();
                }
                let sum_deviation_avg: f64 = sum_deviation / (sorted.len() as f64);
                let threshold: f64 = avg_value * 0.1;

                if sum_deviation_avg < threshold {
                    patterns.push(BusinessPattern::RegularPayments {
                        sender: sender.to_string(),
                        message: format!("Detected regular payments from {}", sender),
                    });
                }
            }
        }
    }

    patterns
}

/// Detects batch payments made by senders within short time intervals.
///
/// This asynchronous function analyzes all transactions in the provided
/// [`SharedTxStorage`] and identifies senders performing multiple transactions
/// within a short period, suggesting batch payments (e.g., mass payouts or automated transfers).
///
/// # Parameters
/// * `storage` – Shared transaction storage (`SharedTxStorage`) containing all transactions to analyze.
///
/// # Returns
/// Returns a `Vec<BusinessPattern>` containing detected batch payment patterns:
/// * `BatchPayments` – Includes the sender, number of transactions in the batch, and a descriptive message.
///
/// # Detection Logic
/// 1. **Sort Transactions** – Transactions for each sender are sorted by timestamp.
/// 2. **Sliding Window** – Counts consecutive transactions within a 5-minute window.
/// 3. **Threshold Check** – If at least 5 transactions occur within this interval, a `BatchPayments` pattern is recorded.
///
/// # Example
/// ```rust,ignore
/// let patterns: Vec<BusinessPattern> = detect_batch_payments(&storage).await;
/// for pattern in patterns {
///     println!("{:?}", pattern);
/// }
/// ```
///
/// # Notes
/// * Timestamps are expected in RFC 3339 format.
/// * The function is asynchronous due to read access to the shared storage.
/// * Only timing of transactions is considered; values are not analyzed.
pub async fn detect_batch_payments(storage: &SharedTxStorage) -> Vec<BusinessPattern> {
    let mut patterns: Vec<BusinessPattern> = Vec::new();

    let batch_interval = Duration::minutes(5);
    let batch_threshold = 5;

    let by_sender = &storage.by_sender;

    for entry in by_sender {
        let txs = entry.value();

        let mut sorted: Vec<TransactionRecord> = txs.clone();
        sorted.sort_by_key(|tx| tx.timestamp.clone());

        let mut i = 0;
        while i < sorted.len() {
            let start: DateTime<Utc> = sorted[i].timestamp.parse().unwrap();
            let mut batch_count = 1;
            for j in i + 1..sorted.len() {
                let ts: DateTime<Utc> = sorted[j].timestamp.parse().unwrap();
                if ts - start <= batch_interval {
                    batch_count += 1;
                } else {
                    break;
                }
            }

            if batch_count >= batch_threshold {
                patterns.push(BusinessPattern::BatchPayments {
                    sender: entry.key().clone(),
                    count: batch_count.clone(),
                    message: format!(
                        "Detected batch payments from {}:\n Payments count: {}",
                        entry.key().clone(),
                        batch_count.clone()
                    ),
                });
                i += batch_count;
            } else {
                i += 1;
            }
        }
    }

    patterns
}

/// Detects transactions sent to known decentralized exchange (DEX) contracts.
///
/// This asynchronous function scans all transactions stored in the provided
/// [`SharedTxStorage`] and identifies those whose recipient (`to` address)
/// matches a known DEX contract. Each detected transaction is recorded as a
/// `BusinessPattern::DEXTrade`.
///
/// # Parameters
/// * `storage` – Shared transaction storage (`SharedTxStorage`) containing all transactions to analyze.
/// * `dex_contracts` – A `HashSet` of known DEX contract addresses (`H160`) to check against.
///
/// # Returns
/// Returns a `Vec<BusinessPattern>` containing detected DEX trade patterns:
/// * `DEXTrade` – Includes the DEX address as a string and a descriptive message.
///
/// # Detection Logic
/// 1. **Iterate All Transactions** – Each transaction in `storage.all_txs` is checked.
/// 2. **Address Parsing** – If the transaction has a `to` address, it is parsed as `H160`.
///    * Panics if the address is invalid.
/// 3. **DEX Check** – If the parsed address is in the `dex_contracts` set, a
///    `BusinessPattern::DEXTrade` pattern is created with the DEX address and a message.
///
/// # Example
/// ```rust,ignore
/// let dex_contracts: HashSet<H160> = get_known_dex_contracts();
/// let patterns: Vec<BusinessPattern> = detect_dex_trade(&storage, &dex_contracts).await;
/// for pattern in patterns {
///     println!("{:?}", pattern);
/// }
/// ```
///
/// # Notes
/// * The function panics if a `to` address cannot be parsed as a valid `H160`.
/// * Use a sanitized and verified list of DEX contract addresses to avoid panics.
pub async fn detect_dex_trade(
    storage: &SharedTxStorage,
    dex_contracts: &HashSet<H160>,
) -> Vec<BusinessPattern> {
    let all_txs = storage.all_txs.read().await;
    let mut patterns: Vec<BusinessPattern> = Vec::new();

    for tx in all_txs.iter() {
        if let Some(to) = &tx.to {
            let to_addres: H160 = to.parse().expect("Invalid address");
            if dex_contracts.contains(&to_addres) {
                patterns.push(BusinessPattern::DEXTrade {
                    dex: to_addres.to_string(),
                    message: format!("Detected trading with DEX: {}", to_addres.to_string()),
                });
            }
        }
    }

    patterns
}

/// Detects NFT-related transactions based on known ERC721/ERC1155 method selectors.
///
/// This asynchronous function scans all transactions in the provided
/// [`SharedTxStorage`] and identifies those likely related to NFT activity.
/// It checks the transaction `input` data for known NFT method selectors:
/// * `0x80ac58cd` — ERC721 `safeTransferFrom`
/// * `0xd9b67a26` — ERC1155 `safeTransferFrom`
///
/// # Parameters
///
/// * `storage` – Shared transaction storage (`SharedTxStorage`) containing all transactions to analyze.
///
/// # Returns
/// Returns a `Vec<BusinessPattern>` containing detected NFT activity patterns:
/// * `NFTActivity` – Includes the transaction hash and a descriptive message.
///
/// # Detection Logic
/// 1. **Iterate All Transactions** – Each transaction in `storage.all_txs` is checked.
/// 2. **Input Data Check** – The first 10 characters of the `input` field are compared
///    against known NFT method selectors.
/// 3. **Pattern Creation** – If a match is found, a `BusinessPattern::NFTActivity` entry
///    is created with the transaction hash and a message.
///
/// # Example
/// ```rust,ignore
/// let patterns: Vec<BusinessPattern> = detect_nft_activity(&storage).await;
/// for pattern in patterns {
///     println!("{:?}", pattern);
/// }
/// ```
///
/// # Notes
/// * Only ERC721 and ERC1155 transfer methods are detected. Other NFT interactions
///   may not be captured.
/// * The function is asynchronous due to read access to the shared storage.
pub async fn detect_nft_activity(storage: &SharedTxStorage) -> Vec<BusinessPattern> {
    let mut patterns: Vec<BusinessPattern> = Vec::new();
    let all_txs = storage.all_txs.read().await;
    for tx in all_txs.iter() {
        if let Some(selector) = tx.input.get(0..10) {
            if selector == "0x80ac58cd" || selector == "0xd9b67a26" {
                patterns.push(BusinessPattern::NFTActivity {
                    tx_hash: tx.hash.clone(),
                    message: format!("Detected NFT activity: {}", tx.hash.clone()),
                });
            }
        }
    }

    patterns
}

/// Detects liquidity provider transactions on known decentralized exchanges (DEXs).
///
/// This asynchronous function scans all transactions in the provided
/// [`SharedTxStorage`] and identifies transactions likely related to providing liquidity
/// on DEX contracts. It checks both the recipient address and the transaction input data.
///
/// # Parameters
/// * `storage` – Shared transaction storage (`SharedTxStorage`) containing all transactions to analyze.
/// * `dex_contracts` – A `HashSet` of known DEX contract addresses (`H160`) to check against.
///
/// # Returns
/// Returns a `Vec<BusinessPattern>` containing detected liquidity provider patterns:
/// * `LiquidityProvider` – A pattern indicating that a transaction represents liquidity provisioning.
///
/// # Detection Logic
/// 1. **Iterate All Transactions** – Each transaction in `storage.all_txs` is checked.
/// 2. **DEX Address Check** – Transactions whose `to` address matches a DEX contract are considered further.
/// 3. **Input Data Check** – The first 10 characters of the transaction `input` are compared against known liquidity provision method selectors:
///    * `"0xe8e33700"` — Example selector for adding liquidity (depends on the specific DEX)
///    * `"0xf305d719"` — Another known selector for adding liquidity
/// 4. **Pattern Creation** – If both conditions are met, a `BusinessPattern::LiquidityProvider` entry is added.
///
/// # Example
/// ```rust,ignore
/// let dex_contracts: HashSet<H160> = get_known_dex_contracts();
/// let patterns: Vec<BusinessPattern> = detect_liquid_provider(&storage, &dex_contracts).await;
/// for pattern in patterns {
///     println!("{:?}", pattern);
/// }
/// ```
///
/// # Notes
/// * The function panics if a `to` address cannot be parsed as a valid `H160`.
/// * Only transactions with known liquidity provision selectors are detected.
/// * The function is asynchronous due to read access to the shared storage.
pub async fn detect_liquid_provider(
    storage: &SharedTxStorage,
    dex_contracts: &HashSet<H160>,
) -> Vec<BusinessPattern> {
    let all_txs = storage.all_txs.read().await;
    let mut patterns: Vec<BusinessPattern> = Vec::new();

    for tx in all_txs.iter() {
        if let Some(to) = &tx.to {
            let to_addres: H160 = to.parse().expect("Invalid address");
            if dex_contracts.contains(&to_addres) {
                if let Some(selector) = &tx.input.get(0..10) {
                    if selector.to_string() == "0xe8e33700" || selector.to_string() == "0xf305d719"
                    {
                        patterns.push(BusinessPattern::LiquidityProvider);
                    }
                }
            }
        }
    }

    patterns
}

/// Detects "whale" accounts based on transaction activity.
///
/// This asynchronous function analyzes all senders in the provided
/// [`SharedTxStorage`] and identifies accounts whose average transaction
/// value (`local_mean`) exceeds the global transaction value threshold.  
/// Such accounts are considered "whales" — users with unusually high transaction amounts.
///
/// # Parameters
/// * `storage` – Shared transaction storage (`SharedTxStorage`) containing all transactions to analyze.
///
/// # Returns
/// Returns a `Vec<BusinessPattern>` containing detected whale patterns:
/// * `Whales` – Includes the sender address of the account exceeding global transaction thresholds.
///
/// # Detection Logic
/// 1. **Iterate Senders** – For each sender in `storage.by_sender`:
///    * Compute the sender's average transaction value (`local_mean`).
///    * Compare it to the global threshold (`global_threshold`).
/// 2. **Pattern Creation** – If the local mean exceeds the global threshold, a `BusinessPattern::Whales` entry is added.
///
/// # Example
/// ```rust,ignore
/// let patterns: Vec<BusinessPattern> = detect_whales(&storage).await;
/// for pattern in patterns {
///     println!("{:?}", pattern);
/// }
/// ```
///
/// # Notes
/// * The function is asynchronous because it reads from shared transaction storage.
/// * `local_mean` and `global_threshold` are assumed to be implemented elsewhere.
/// * Only the sender's average transaction value is considered; transaction frequency is not analyzed.
pub async fn detect_whales(storage: &SharedTxStorage) -> Vec<BusinessPattern> {
    let mut patterns: Vec<BusinessPattern> = Vec::new();
    for entry in storage.by_sender.iter() {
        let sender = entry.key();
        let global_threshold = global_threshold(&storage).await;
        let local_mean = local_mean(&storage, &sender);

        if local_mean > global_threshold {
            patterns.push(BusinessPattern::Whales {
                sender: sender.clone(),
            });
        }
    }

    patterns
}

/// Detects active traders interacting with known decentralized exchanges (DEXs).
///
/// This asynchronous function scans all transactions in the provided
/// [`SharedTxStorage`] and identifies senders who have made a high number of
/// transactions to known DEX contracts. Accounts exceeding a transaction
/// count threshold are considered "active traders".
///
/// # Parameters
/// * `storage` – Shared transaction storage (`SharedTxStorage`) containing all transactions to analyze.
/// * `dex_contracts` – A `HashSet` of known DEX contract addresses (`H160`) to check against.
///
/// # Returns
/// Returns a `Vec<BusinessPattern>` containing detected active trader patterns:
/// * `ActiveTraders` – Includes the sender address and a descriptive message.
///
/// # Detection Logic
/// 1. **Iterate All Transactions** – For each transaction in `storage.all_txs`:
///    * Parse the `to` address as `H160`.
///    * If the address is in the `dex_contracts` set, increment the sender's counter.
/// 2. **Threshold Check** – Senders with more than 10 transactions to DEXs are flagged.
/// 3. **Pattern Creation** – For each flagged sender, a `BusinessPattern::ActiveTraders` entry is added.
///
/// # Example
/// ```rust,ignore
/// let dex_contracts: HashSet<H160> = get_known_dex_contracts();
/// let patterns: Vec<BusinessPattern> = detect_active_traders(&storage, &dex_contracts).await;
/// for pattern in patterns {
///     println!("{:?}", pattern);
/// }
/// ```
///
/// # Notes
/// * The function panics if a `to` address cannot be parsed as a valid `H160`.
/// * The function is asynchronous due to read access to the shared storage.
/// * The threshold of 10 transactions is hardcoded but can be adjusted as needed.
pub async fn detect_active_traders(
    storage: &SharedTxStorage,
    dex_contracts: &HashSet<H160>,
) -> Vec<BusinessPattern> {
    let all_txs = storage.all_txs.read().await;
    let mut patterns: Vec<BusinessPattern> = Vec::new();

    let mut counter = HashMap::new();
    for tx in all_txs.iter() {
        if let Some(to) = &tx.to {
            let to_addres: H160 = to.parse().expect("Invalid address");
            if dex_contracts.contains(&to_addres) {
                *counter.entry(&tx.from).or_insert(0) += 1;
            }
        }
    }

    for (address, count) in counter.iter() {
        if *count > 10 {
            patterns.push(BusinessPattern::ActiveTraders {
                sender: address.to_string(),
                message: format!("Detected active trader: {}", address),
            });
        }
    }

    patterns
}

/// Detects potential arbitrage transactions on known decentralized exchanges (DEXs).
///
/// This asynchronous function scans all transactions in the provided
/// [`SharedTxStorage`] and identifies transactions that interact with known DEX contracts
/// using common arbitrage-related operations, such as multi-call or token swaps.
///
/// # Parameters
/// * `storage` – Shared transaction storage (`SharedTxStorage`) containing all transactions to analyze.
/// * `dex_contracts` – A `HashSet` of known DEX contract addresses (`H160`) to check against.
///
/// # Returns
/// Returns a `Vec<BusinessPattern>` containing detected arbitrage patterns:
/// * `Arbitrage` – Includes the sender address and a descriptive message.
///
/// # Detection Logic
/// 1. **Iterate All Transactions** – For each transaction in `storage.all_txs`:
///    * Parse the `to` address as `H160`.
///    * Check if the address is in the `dex_contracts` set.
/// 2. **Arbitrage Operation Check** – Inspect the transaction `input` string for common arbitrage-related functions:
///    * `"multicall"`
///    * `"swapExactTokensForTokens"`
/// 3. **Pattern Creation** – If a match is found, a `BusinessPattern::Arbitrage` entry is added with the sender and a descriptive message.
///
/// # Example
/// ```rust,ignore
/// let dex_contracts: HashSet<H160> = get_known_dex_contracts();
/// let patterns: Vec<BusinessPattern> = detect_arbitrage(&storage, &dex_contracts).await;
/// for pattern in patterns {
///     println!("{:?}", pattern);
/// }
/// ```
///
/// # Notes
/// * The function panics if a `to` address cannot be parsed as a valid `H160`.
/// * The function is asynchronous due to read access to the shared storage.
/// * Detection is based on simple substring matching in the transaction `input`; some arbitrage transactions may not be detected if they use uncommon patterns.
pub async fn detect_arbitrage(
    storage: &SharedTxStorage,
    dex_contracts: &HashSet<H160>,
) -> Vec<BusinessPattern> {
    let all_txs = storage.all_txs.read().await;
    let mut patterns: Vec<BusinessPattern> = Vec::new();
    for tx in all_txs.iter() {
        if let Some(to) = &tx.to {
            let to_addres: H160 = to.parse().expect("Invalid address");
            if dex_contracts.contains(&to_addres) {
                if tx.input.contains("multicall") || tx.input.contains("swapExactTokensForTokens") {
                    patterns.push(BusinessPattern::Arbitrage {
                        sender: tx.from.to_string(),
                        message: format!("Detected possible arbtrage from: {}", tx.from.clone()),
                    });
                }
            }
        }
    }

    patterns
}

fn percentile(values: &Vec<f64>) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let mut sorted: Vec<f64> = values.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((PERC / 100.0) * (sorted.len() as f64 - 1.0)) as usize;
    sorted[idx]
}

fn local_mean(storage: &SharedTxStorage, sender: &String) -> f64 {
    let local_values: Vec<f64> = storage
        .by_sender
        .get(sender)
        .map(|vec| vec.iter().map(|t| t.value).collect())
        .unwrap_or_else(|| vec![]);

    let local_mean = if local_values.is_empty() {
        0.0
    } else {
        local_values.iter().sum::<f64>() / local_values.len() as f64
    };

    local_mean
}

async fn global_threshold(storage: &SharedTxStorage) -> f64 {
    let all_txs = storage.all_txs.read().await;
    let all_values: Vec<f64> = all_txs.iter().map(|tx| tx.value).collect();
    let global_thershold = percentile(&all_values);

    global_thershold
}

fn txs_in_interval(
    txs: &Vec<TransactionRecord>,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Vec<&TransactionRecord> {
    txs.iter()
        .filter(|tx| {
            let ts: DateTime<Utc> = tx.timestamp.parse().unwrap();
            start <= ts && ts <= end
        })
        .collect()
}

fn local_mean_fee(storage: &SharedTxStorage, sender: &str) -> f64 {
    storage
        .by_sender
        .get(sender)
        .map(|txs| {
            let fees: Vec<f64> = txs
                .iter()
                .map(|tx| tx.gas_price_gwei * tx.gas as f64 / 1e9)
                .collect();
            if fees.is_empty() {
                0.0
            } else {
                fees.iter().sum::<f64>() / fees.len() as f64
            }
        })
        .unwrap_or(0.0)
}
