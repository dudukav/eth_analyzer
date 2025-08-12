use std::collections::HashMap;

use ethers::types::Address;
use serde::Serialize;

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
}

pub struct TxStorage {
    by_sender: HashMap<Address, Vec<TransactionRecord>>,
    by_reciever: HashMap<Address, Vec<TransactionRecord>>,
}

impl TxStorage {
    pub fn new() -> Self {
        TxStorage {
            by_sender: HashMap::new(),
            by_reciever: HashMap::new(),
        }
    }

    pub fn add_transaction(&mut self, from: Address, to: Option<Address>, tx: TransactionRecord) {
        self.by_sender
            .entry(from)
            .or_insert(Vec::new())
            .push(tx.clone());

        if let Some(reciever) = to {
            self.by_reciever
                .entry(reciever)
                .or_insert(Vec::new())
                .push(tx.clone());
        }
    }
}
