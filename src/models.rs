use dashmap::DashMap;
use ethers::types::Address;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;

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

    pub async fn add_transaction(&self, from: Address, to: Option<Address>, tx: TransactionRecord) {
        let mut all_txs = self.all_txs.write().await;
        all_txs.push(tx.clone());

        self.by_sender
            .entry(from.to_string())
            .or_insert(Vec::new())
            .push(tx.clone());

        if let Some(reciever) = to {
            self.by_reciever
                .entry(reciever.to_string())
                .or_insert(Vec::new())
                .push(tx.clone());
        }
    }
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
    },
    HighFrequency {
        sender: String,
        count: usize,
    },
    BurstActivity,
    Structuring {
        sender: String,
        count: usize,
        severity: Severity,
    },
    HighFee {
        tx_hash: String,
        fee_eth: f64,
        severity: Severity,
    },
    BlacklistedAddress {
        tx_hash: String,
        addres: String,
    },
    UnusualOp {
        tx_hash: String,
        reasons: Vec<String>,
        severiry: Severity,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum BusinessPattern {
    RegularPayments,
    BatchPayments,
    DEXTrade,
    NFTActivity,
    LiquidityProvider,
    Whales,
    ActiveTraders,
    Exchanges,
    Arbitrage,
}

#[derive(Debug, Serialize, Clone)]
pub struct AnalysisResult {
    pub anomalies: Vec<Anomaly>,
    pub patterns: Vec<BusinessPattern>,
}
