use dashmap::DashMap;
use ethers::types::Address;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};


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

pub struct TxStorage {
    pub by_sender: DashMap<String, Vec<TransactionRecord>>,
    pub by_reciever: DashMap<String, Vec<TransactionRecord>>,
    pub all_txs: RwLock<Vec<TransactionRecord>>,
}

pub type SharedTxStorage = Arc<TxStorage>;

impl TxStorage {
    pub fn new() -> Self {
        TxStorage {
            by_sender: DashMap::new(),
            by_reciever: DashMap::new(),
            all_txs: RwLock::new(Vec::new()),
        }
    }

    // pub async fn add_transaction(&self, from: Address, to: Option<Address>, tx: TransactionRecord) {
    //     let mut all_txs = self.all_txs.write().await;
    //     all_txs.push(tx.clone());

    //     self.by_sender
    //         .entry(from.to_string())
    //         .or_insert(Vec::new())
    //         .push(tx.clone());

    //     if let Some(reciever) = to {
    //         self.by_reciever
    //             .entry(reciever.to_string())
    //             .or_insert(Vec::new())
    //             .push(tx.clone());
    //     }
    // }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Severity {
    Strong,
    Weak,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Anomaly {
    LargeTx {
        tx_hash: String,
        severity: Severity,
        reasons: Vec<String>,
        timestamp: DateTime<Utc>
    },
    HighFrequency {
        sender: String,
        count: usize,
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
        timestamp: DateTime<Utc>
    },
    BlacklistedAddress {
        tx_hash: String,
        addres: String,
        reasons: Vec<String>,
        timestamp: DateTime<Utc>
    },
    UnusualOp {
        tx_hash: String,
        severity: Severity,
        reasons: Vec<String>,
        timestamp: DateTime<Utc>
    },
}

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


/// Унифицированная структура для экспорта аномалий
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
    pub timestamp: Option<DateTime<Utc>>
}

impl From<&Anomaly> for AnomalyCsv {
    fn from(a: &Anomaly) -> Self {
        match a {
            Anomaly::LargeTx { tx_hash, severity, reasons , timestamp} => Self {
                type_name: "LargeTx".into(),
                tx_hash: Some(tx_hash.clone()),
                sender: None,
                addres: None,
                count: None,
                fee_eth: None,
                severity: Some(format!("{:?}", severity)),
                reasons: Some(reasons.join("; ")),
                timestamp: Some(timestamp.clone())
            },
            Anomaly::HighFrequency { sender, count, reasons } => Self {
                type_name: "HighFrequency".into(),
                tx_hash: None,
                sender: Some(sender.clone()),
                addres: None,
                count: Some(*count),
                fee_eth: None,
                severity: None,
                reasons: Some(reasons.join("; ")),
                timestamp: None
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
                timestamp: None
            },
            Anomaly::Structuring { sender, count, severity, reasons } => Self {
                type_name: "Structuring".into(),
                tx_hash: None,
                sender: Some(sender.clone()),
                addres: None,
                count: Some(*count),
                fee_eth: None,
                severity: Some(format!("{:?}", severity)),
                reasons: Some(reasons.join("; ")),
                timestamp : None
            },
            Anomaly::HighFee { tx_hash, fee_eth, severity, reasons , timestamp} => Self {
                type_name: "HighFee".into(),
                tx_hash: Some(tx_hash.clone()),
                sender: None,
                addres: None,
                count: None,
                fee_eth: Some(*fee_eth),
                severity: Some(format!("{:?}", severity)),
                reasons: Some(reasons.join("; ")),
                timestamp: Some(timestamp.clone())
            },
            Anomaly::BlacklistedAddress { tx_hash, addres, reasons, timestamp } => Self {
                type_name: "BlacklistedAddress".into(),
                tx_hash: Some(tx_hash.clone()),
                sender: None,
                addres: Some(addres.clone()),
                count: None,
                fee_eth: None,
                severity: None,
                reasons: Some(reasons.join("; ")),
                timestamp: Some(timestamp.clone())
            },
            Anomaly::UnusualOp { tx_hash, severity, reasons, timestamp } => Self {
                type_name: "UnusualOp".into(),
                tx_hash: Some(tx_hash.clone()),
                sender: None,
                addres: None,
                count: None,
                fee_eth: None,
                severity: Some(format!("{:?}", severity)),
                reasons: Some(reasons.join("; ")),
                timestamp: Some(timestamp.clone())
            },
        }
    }
}

/// Унифицированная структура для экспорта бизнес-паттернов
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessPatternCsv {
    pub type_name: String,
    pub sender: Option<String>,
    pub tx_hash: Option<String>,
    pub dex: Option<String>,
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
                dex: None,
                count: None,
                message: Some(message.clone()),
            },
            BusinessPattern::BatchPayments { sender, count, message } => Self {
                type_name: "BatchPayments".into(),
                sender: Some(sender.clone()),
                tx_hash: None,
                dex: None,
                count: Some(*count),
                message: Some(message.clone()),
            },
            BusinessPattern::DEXTrade { dex, message } => Self {
                type_name: "DEXTrade".into(),
                sender: None,
                tx_hash: None,
                dex: Some(dex.clone()),
                count: None,
                message: Some(message.clone()),
            },
            BusinessPattern::NFTActivity { tx_hash, message } => Self {
                type_name: "NFTActivity".into(),
                sender: None,
                tx_hash: Some(tx_hash.clone()),
                dex: None,
                count: None,
                message: Some(message.clone()),
            },
            BusinessPattern::LiquidityProvider => Self {
                type_name: "LiquidityProvider".into(),
                sender: None,
                tx_hash: None,
                dex: None,
                count: None,
                message: None,
            },
            BusinessPattern::Whales { sender } => Self {
                type_name: "Whales".into(),
                sender: Some(sender.clone()),
                tx_hash: None,
                dex: None,
                count: None,
                message: None,
            },
            BusinessPattern::ActiveTraders { sender, message } => Self {
                type_name: "ActiveTraders".into(),
                sender: Some(sender.clone()),
                tx_hash: None,
                dex: None,
                count: None,
                message: Some(message.clone()),
            },
            BusinessPattern::Arbitrage { sender, message } => Self {
                type_name: "Arbitrage".into(),
                sender: Some(sender.clone()),
                tx_hash: None,
                dex: None,
                count: None,
                message: Some(message.clone()),
            },
        }
    }
}
