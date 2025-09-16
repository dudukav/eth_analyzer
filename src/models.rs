use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;


/// Represents a blockchain transaction with relevant metadata.
/// This structure is used to store information about a single transaction,
/// typically for analysis, monitoring, or anomaly detection.
/// # Fields
///
/// * `hash` – The unique transaction hash (identifier) as a hexadecimal string.
/// * `from` – The sender's address of the transaction.
/// * `to` – Optional recipient address. `None` indicates a contract creation or unknown recipient.
/// * `value` – The amount transferred in the transaction, typically in the blockchain's native currency.
/// * `gas` – The amount of gas used by the transaction.
/// * `gas_price_gwei` – The gas price in Gwei (1 Gwei = 10⁹ Wei) used to execute the transaction.
/// * `block_number` – The block number in which the transaction was included.
/// * `timestamp` – The UTC timestamp of when the transaction was mined, stored as an RFC 3339 string.
/// * `input` – The raw input data of the transaction, often containing contract call data or payload.
///
/// # Example
///
/// ```rust,ignore
/// let tx = TransactionRecord {
///     hash: "0x123abc...".to_string(),
///     from: "0xabc123...".to_string(),
///     to: Some("0xdef456...".to_string()),
///     value: 10.5,
///     gas: 21000,
///     gas_price_gwei: 50.0,
///     block_number: 12345678,
///     timestamp: "2025-09-16T12:00:00Z".to_string(),
///     input: "".to_string(),
/// };
/// println!("Transaction from {} to {:?}", tx.from, tx.to);
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct TransactionRecord {
    pub hash: String,
    pub from: String,
    pub to: Option<String>,
    pub value: f64,
    pub gas: u64,
    pub gas_price_gwei: f64,
    pub block_number: u64,
    pub timestamp: String,
    pub input: String,
}

/// A shared in-memory storage for blockchain transactions, organized for
/// efficient querying by sender, receiver, or globally.
///
/// This structure is used in analytics and anomaly detection systems to
/// store and access transactions safely in a concurrent environment.
///
/// # Fields
/// * `by_sender` – A concurrent map (`DashMap`) from sender addresses (`String`)
///   to vectors of [`TransactionRecord`]. Allows fast lookup of all transactions
///   sent by a specific account.
///
/// * `by_reciever` – A concurrent map (`DashMap`) from receiver addresses (`String`)
///   to vectors of [`TransactionRecord`]. Allows fast lookup of all transactions
///   received by a specific account.
///
/// * `all_txs` – A thread-safe global list (`RwLock<Vec<TransactionRecord>>`) 
///   containing all transactions. Useful for operations that need to iterate
///   over the entire dataset, e.g., global anomaly detection.
///
/// # Type Aliases
/// * `SharedTxStorage` – An [`Arc`] around [`TxStorage`] for convenient shared ownership
///   and thread-safe access across tasks.
///
/// # Example
/// ```rust,ignore
/// use std::sync::Arc;
/// use dashmap::DashMap;
/// use tokio::sync::RwLock;
///
/// // Create a new shared transaction storage
/// let storage: SharedTxStorage = Arc::new(TxStorage::new());
///
/// // Insert a transaction
/// let tx = TransactionRecord {
///     hash: "0x123abc...".to_string(),
///     from: "0xabc123...".to_string(),
///     to: Some("0xdef456...".to_string()),
///     value: 10.5,
///     gas: 21000,
///     gas_price_gwei: 50.0,
///     block_number: 12345678,
///     timestamp: "2025-09-16T12:00:00Z".to_string(),
///     input: "".to_string(),
/// };
///
/// storage.by_sender.entry(tx.from.clone()).or_default().push(tx.clone());
/// storage.by_reciever.entry(tx.to.clone().unwrap()).or_default().push(tx.clone());
/// storage.all_txs.write().await.push(tx);
/// ```
///
/// # Notes
/// * `DashMap` allows concurrent reads and writes without locking the entire map.
/// * `RwLock` allows multiple concurrent readers or one writer for `all_txs`.
/// * `SharedTxStorage` (Arc) enables safe sharing across async tasks and threads.
pub struct TxStorage {
    pub by_sender: DashMap<String, Vec<TransactionRecord>>,
    pub by_reciever: DashMap<String, Vec<TransactionRecord>>,
    pub all_txs: RwLock<Vec<TransactionRecord>>,
}

/// Shared ownership of `TxStorage` using an atomic reference count.
///
/// This type alias allows multiple async tasks or threads to share
/// the same transaction storage safely.
pub type SharedTxStorage = Arc<TxStorage>;

impl TxStorage {
    /// Creates a new, empty `TxStorage` instance.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let storage = TxStorage::new();
    /// assert!(storage.by_sender.is_empty());
    /// assert!(storage.by_reciever.is_empty());
    /// ```
    pub fn new() -> Self {
        TxStorage {
            by_sender: DashMap::new(),
            by_reciever: DashMap::new(),
            all_txs: RwLock::new(Vec::new()),
        }
    }
}

/// Represents the severity level of a detected anomaly.
///
/// This enum is used in anomaly detection systems to classify the impact
/// or importance of a flagged event, such as suspicious transactions.
///
/// # Variants
/// * `Strong` – Indicates a **high-severity anomaly**.  
///   Typically used when multiple detection criteria are met, suggesting
///   a very likely or critical issue.
///
/// * `Weak` – Indicates a **low-severity anomaly**.  
///   Typically used when only one criterion is triggered, suggesting a
///   potential issue that may require monitoring or further investigation.
///
/// # Example
/// ```rust,ignore
/// let severity = Severity::Strong;
/// match severity {
///     Severity::Strong => println!("Critical anomaly detected!"),
///     Severity::Weak => println!("Minor anomaly detected."),
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Severity {
    Strong,
    Weak,
}

/// Represents various types of anomalies detected in blockchain transactions.
///
/// This enum is used to classify different kinds of suspicious activity
/// in transaction analysis systems. Each variant contains relevant metadata
/// about the anomaly, such as affected addresses, transaction hashes,
/// severity, timestamps, and descriptive reasons.
///
/// # Variants
/// * `LargeTx` – A single transaction whose value is unusually large.
///   Fields:
///   - `tx_hash`: The hash of the transaction.
///   - `severity`: [`Severity`] of the anomaly (`Strong` or `Weak`).
///   - `reasons`: List of human-readable explanations.
///   - `timestamp`: When the transaction was observed.
///
/// * `HighFrequency` – An account has submitted too many transactions in a short time.
///   Fields:
///   - `sender`: The account address sending the transactions.
///   - `count`: Number of transactions in the monitored interval.
///   - `reasons`: Explanations why this is flagged.
///
/// * `BurstActivity` – Sudden burst of transactions from a sender, indicating unusual activity.
///   Fields:
///   - `sender`: The account address.
///   - `reasons`: Descriptions of the anomaly.
///
/// * `Structuring` – Multiple smaller transactions possibly splitting a large amount
///   to avoid detection thresholds.
///   Fields:
///   - `sender`: The account address.
///   - `count`: Number of transactions in the interval.
///   - `severity`: [`Severity`] of the anomaly.
///   - `reasons`: Explanations of why it was flagged.
///
/// * `HighFee` – A transaction with unusually high fees.
///   Fields:
///   - `tx_hash`: Transaction hash.
///   - `fee_eth`: Fee in ETH.
///   - `severity`: [`Severity`] of the anomaly.
///   - `reasons`: Explanations.
///   - `timestamp`: When the transaction was observed.
///
/// * `BlacklistedAddress` – Interaction with a known blacklisted address.
///   Fields:
///   - `tx_hash`: Transaction hash.
///   - `addres`: The blacklisted address involved.
///   - `reasons`: Explanations.
///   - `timestamp`: When the transaction occurred.
///
/// * `UnusualOp` – A transaction performing an unusual operation (e.g., rare contract call).
///   Fields:
///   - `tx_hash`: Transaction hash.
///   - `severity`: [`Severity`] of the anomaly.
///   - `reasons`: Descriptions of why it was flagged.
///   - `timestamp`: When the transaction occurred.
///
/// * `TimeAnomaly` – Transactions with unusual timestamps (e.g., out-of-order blocks or
///   suspicious time gaps).
///   Fields:
///   - `tx_hash`: Transaction hash.
///   - `severity`: [`Severity`] of the anomaly.
///   - `reasons`: Explanations.
///   - `timestamp`: When the transaction occurred.
///
/// # Example
///
/// ```rust,ignore
/// let anomaly = Anomaly::LargeTx {
///     tx_hash: "0x123abc...".to_string(),
///     severity: Severity::Strong,
///     reasons: vec!["Transaction exceeds local and global thresholds".to_string()],
///     timestamp: Utc::now(),
/// };
///
/// match anomaly {
///     Anomaly::LargeTx { tx_hash, severity, .. } => {
///         println!("Large transaction {} detected with severity {:?}", tx_hash, severity);
///     }
///     _ => {}
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Anomaly {
    LargeTx {
        tx_hash: String,
        severity: Severity,
        reasons: Vec<String>,
        timestamp: DateTime<Utc>,
    },
    HighFrequency {
        sender: String,
        count: usize,
        // timestamps: Vec<DateTime<Utc>>,
        // recievers: Vec<String>,
        reasons: Vec<String>,
    },
    BurstActivity {
        sender: String,
        reasons: Vec<String>,
    },
    Structuring {
        sender: String,
        count: usize,
        severity: Severity,
        reasons: Vec<String>,
    },
    HighFee {
        tx_hash: String,
        fee_eth: f64,
        severity: Severity,
        reasons: Vec<String>,
        timestamp: DateTime<Utc>,
    },
    BlacklistedAddress {
        tx_hash: String,
        addres: String,
        reasons: Vec<String>,
        timestamp: DateTime<Utc>,
    },
    UnusualOp {
        tx_hash: String,
        severity: Severity,
        reasons: Vec<String>,
        timestamp: DateTime<Utc>,
    },
    TimeAnomaly {
        tx_hash: String,
        severity: Severity,
        reasons: Vec<String>,
        timestamp: DateTime<Utc>,
    },
}
 
/// Represents detected business patterns in blockchain transactions.
///
/// This enum is used to categorize transaction behaviors that correspond
/// to regular financial activity, trading, or specific operational patterns.
///
/// # Variants
///
/// * `RegularPayments` – Indicates normal, recurring payments from a sender.
///   Fields:
///   - `sender`: The account performing the payments.
///   - `message`: Human-readable description of the detected pattern.
///
/// * `BatchPayments` – Multiple payments sent in a batch by a sender.
///   Fields:
///   - `sender`: The account sending multiple transactions.
///   - `count`: Number of transactions in the batch.
///   - `message`: Description of the pattern.
///
/// * `DEXTrade` – Transactions interacting with a decentralized exchange (DEX).
///   Fields:
///   - `dex`: Address of the DEX contract.
///   - `message`: Description of the detected trading activity.
///
/// * `NFTActivity` – A transaction related to NFT transfers or trading.
///   Fields:
///   - `tx_hash`: Transaction hash of the NFT-related operation.
///   - `message`: Description of the activity.
///
/// * `LiquidityProvider` – Indicates a user acting as a liquidity provider in a pool.
///   No additional fields.
///
/// * `Whales` – Large holders performing significant transactions.
///   Fields:
///   - `sender`: The whale account address.
///
/// * `ActiveTraders` – Accounts identified as frequent or active traders.
///   Fields:
///   - `sender`: The account address.
///   - `message`: Description of trading activity.
///
/// * `Arbitrage` – Accounts performing arbitrage operations.
///   Fields:
///   - `sender`: The account address.
///   - `message`: Explanation of the arbitrage pattern.
///
/// # Example
///
/// ```rust,ignore
/// let pattern = BusinessPattern::DEXTrade {
///     dex: "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f".to_string(),
///     message: "Detected trading with Uniswap V2".to_string(),
/// };
///
/// match pattern {
///     BusinessPattern::DEXTrade { dex, message } => {
///         println!("DEX Trade detected with {}: {}", dex, message);
///     }
///     _ => {}
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum BusinessPattern {
    RegularPayments {
        sender: String,
        message: String,
    },
    BatchPayments {
        sender: String,
        count: usize,
        message: String,
    },
    DEXTrade {
        dex: String,
        message: String,
    },
    NFTActivity {
        tx_hash: String,
        message: String,
    },
    LiquidityProvider,
    Whales {
        sender: String,
    },
    ActiveTraders {
        sender: String,
        message: String,
    },
    Arbitrage {
        sender: String,
        message: String,
    },
}


/// A CSV-friendly representation of an [`Anomaly`] for exporting or reporting.
///
/// This structure flattens the fields of the [`Anomaly`] enum into optional,
/// serializable fields suitable for CSV or spreadsheet output.  
/// Each field corresponds to a possible property of the different anomaly types.
///
/// # Fields
/// * `type_name` – The name of the anomaly type (e.g., "LargeTx", "HighFrequency").
/// * `tx_hash` – Optional transaction hash associated with the anomaly.
/// * `sender` – Optional account address responsible for the anomaly.
/// * `addres` – Optional address involved in the anomaly (e.g., blacklisted address).
/// * `count` – Optional number of transactions (used for frequency or structuring anomalies).
/// * `fee_eth` – Optional transaction fee in ETH (used for `HighFee` anomalies).
/// * `severity` – Optional severity level as a string ("Strong" or "Weak").
/// * `reasons` – Optional human-readable explanation(s) of why the anomaly was flagged,
///   concatenated into a single string separated by `; `.
/// * `timestamp` – Optional timestamp of the transaction, if applicable.
///
/// # Conversion from [`Anomaly`]
///
/// Implements `From<&Anomaly>` to convert any `Anomaly` variant into an `AnomalyCsv`.
/// Fields that are not relevant for a particular anomaly type are set to `None`.
///
/// # Example
///
/// ```rust,ignore
/// let anomaly = Anomaly::LargeTx {
///     tx_hash: "0x123abc...".to_string(),
///     severity: Severity::Strong,
///     reasons: vec!["Exceeded global threshold".to_string()],
///     timestamp: Utc::now(),
/// };
///
/// let csv_record: AnomalyCsv = AnomalyCsv::from(&anomaly);
/// println!("CSV record: {:?}", csv_record);
/// ```
///
/// # Notes
/// * Useful for exporting anomalies to CSV files or other tabular formats.
/// * Fields are mostly `Option` to handle differences between anomaly variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyCsv {
    pub type_name: String,
    pub tx_hash: Option<String>,
    pub sender: Option<String>,
    pub addres: Option<String>,
    pub count: Option<usize>,
    pub fee_eth: Option<f64>,
    pub severity: Option<String>,
    pub reasons: Option<String>,
    pub timestamp: Option<DateTime<Utc>>,
}

impl From<&Anomaly> for AnomalyCsv {
    fn from(a: &Anomaly) -> Self {
        match a {
            Anomaly::LargeTx {
                tx_hash,
                severity,
                reasons,
                timestamp,
            } => Self {
                type_name: "LargeTx".into(),
                tx_hash: Some(tx_hash.clone()),
                sender: None,
                addres: None,
                count: None,
                fee_eth: None,
                severity: Some(format!("{:?}", severity)),
                reasons: Some(reasons.join("; ")),
                timestamp: Some(timestamp.clone()),
            },
            Anomaly::HighFrequency {
                sender,
                count,
                reasons,
            } => Self {
                type_name: "HighFrequency".into(),
                tx_hash: None,
                sender: Some(sender.clone()),
                addres: None,
                count: Some(*count),
                fee_eth: None,
                severity: None,
                reasons: Some(reasons.join("; ")),
                timestamp: None,
            },
            Anomaly::BurstActivity { sender, reasons } => Self {
                type_name: "BurstActivity".into(),
                tx_hash: None,
                sender: Some(sender.clone()),
                addres: None,
                count: None,
                fee_eth: None,
                severity: None,
                reasons: Some(reasons.join("; ")),
                timestamp: None,
            },
            Anomaly::Structuring {
                sender,
                count,
                severity,
                reasons,
            } => Self {
                type_name: "Structuring".into(),
                tx_hash: None,
                sender: Some(sender.clone()),
                addres: None,
                count: Some(*count),
                fee_eth: None,
                severity: Some(format!("{:?}", severity)),
                reasons: Some(reasons.join("; ")),
                timestamp: None,
            },
            Anomaly::HighFee {
                tx_hash,
                fee_eth,
                severity,
                reasons,
                timestamp,
            } => Self {
                type_name: "HighFee".into(),
                tx_hash: Some(tx_hash.clone()),
                sender: None,
                addres: None,
                count: None,
                fee_eth: Some(*fee_eth),
                severity: Some(format!("{:?}", severity)),
                reasons: Some(reasons.join("; ")),
                timestamp: Some(timestamp.clone()),
            },
            Anomaly::BlacklistedAddress {
                tx_hash,
                addres,
                reasons,
                timestamp,
            } => Self {
                type_name: "BlacklistedAddress".into(),
                tx_hash: Some(tx_hash.clone()),
                sender: None,
                addres: Some(addres.clone()),
                count: None,
                fee_eth: None,
                severity: None,
                reasons: Some(reasons.join("; ")),
                timestamp: Some(timestamp.clone()),
            },
            Anomaly::UnusualOp {
                tx_hash,
                severity,
                reasons,
                timestamp,
            } => Self {
                type_name: "UnusualOp".into(),
                tx_hash: Some(tx_hash.clone()),
                sender: None,
                addres: None,
                count: None,
                fee_eth: None,
                severity: Some(format!("{:?}", severity)),
                reasons: Some(reasons.join("; ")),
                timestamp: Some(timestamp.clone()),
            },
            Anomaly::TimeAnomaly {
                tx_hash,
                severity,
                reasons,
                timestamp,
            } => Self {
                type_name: "UnusualOp".into(),
                tx_hash: Some(tx_hash.clone()),
                sender: None,
                addres: None,
                count: None,
                fee_eth: None,
                severity: Some(format!("{:?}", severity)),
                reasons: Some(reasons.join("; ")),
                timestamp: Some(timestamp.clone()),
            },
        }
    }
}


/// A CSV-friendly representation of a [`BusinessPattern`] for exporting or reporting.
///
/// This structure flattens the different variants of [`BusinessPattern`] into
/// optional fields suitable for CSV or tabular formats. Fields that are not
/// relevant for a particular business pattern variant are set to `None`.
///
/// # Fields
/// * `type_name` – Name of the business pattern variant (e.g., "DEXTrade", "BatchPayments").
/// * `sender` – Optional account address responsible for the pattern, if applicable.
/// * `tx_hash` – Optional transaction hash associated with the pattern (e.g., NFT activity).
/// * `count` – Optional number of transactions, used for batch payments or other multi-tx patterns.
/// * `message` – Optional human-readable description of the detected pattern.
///
/// # Conversion from [`BusinessPattern`]
///
/// Implements `From<&BusinessPattern>` to convert any variant of `BusinessPattern`
/// into a `BusinessPatternCsv`. Only relevant fields for each variant are populated,
/// while others remain `None`.
///
/// # Example
///
/// ```rust,ignore
/// let pattern = BusinessPattern::DEXTrade {
///     dex: "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f".to_string(),
///     message: "Detected trading with Uniswap V2".to_string(),
/// };
///
/// let csv_record: BusinessPatternCsv = BusinessPatternCsv::from(&pattern);
/// println!("CSV record: {:?}", csv_record);
/// ```
///
/// # Notes
/// * Useful for exporting business patterns to CSV files or spreadsheets.
/// * Fields are mostly `Option` to handle differences between pattern variants.
/// * This structure is primarily intended for reporting and analytics purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessPatternCsv {
    pub type_name: String,
    pub sender: Option<String>,
    pub tx_hash: Option<String>,
    pub count: Option<usize>,
    pub message: Option<String>,
}

impl From<&BusinessPattern> for BusinessPatternCsv {
    fn from(p: &BusinessPattern) -> Self {
        match p {
            BusinessPattern::RegularPayments { sender, message } => Self {
                type_name: "RegularPayments".into(),
                sender: Some(sender.clone()),
                tx_hash: None,
                count: None,
                message: Some(message.clone()),
            },
            BusinessPattern::BatchPayments {
                sender,
                count,
                message,
            } => Self {
                type_name: "BatchPayments".into(),
                sender: Some(sender.clone()),
                tx_hash: None,
                count: Some(*count),
                message: Some(message.clone()),
            },
            BusinessPattern::DEXTrade { dex: _, message } => Self {
                type_name: "DEXTrade".into(),
                sender: None,
                tx_hash: None,
                count: None,
                message: Some(message.clone()),
            },
            BusinessPattern::NFTActivity { tx_hash, message } => Self {
                type_name: "NFTActivity".into(),
                sender: None,
                tx_hash: Some(tx_hash.clone()),
                count: None,
                message: Some(message.clone()),
            },
            BusinessPattern::LiquidityProvider => Self {
                type_name: "LiquidityProvider".into(),
                sender: None,
                tx_hash: None,
                count: None,
                message: None,
            },
            BusinessPattern::Whales { sender } => Self {
                type_name: "Whales".into(),
                sender: Some(sender.clone()),
                tx_hash: None,
                count: None,
                message: None,
            },
            BusinessPattern::ActiveTraders { sender, message } => Self {
                type_name: "ActiveTraders".into(),
                sender: Some(sender.clone()),
                tx_hash: None,
                count: None,
                message: Some(message.clone()),
            },
            BusinessPattern::Arbitrage { sender, message } => Self {
                type_name: "Arbitrage".into(),
                sender: Some(sender.clone()),
                tx_hash: None,
                count: None,
                message: Some(message.clone()),
            },
        }
    }
}
