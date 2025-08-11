use crate::models::TransactionRecord;
use chrono::{naive, DateTime, NaiveDate, NaiveDateTime, Utc};
use ethers::core::k256::elliptic_curve::rand_core::block;
use ethers::providers::{Middleware, Provider};
use ethers::types::{BlockNumber, Transaction};
use log::{debug, error, info, warn};
use std::sync::Arc;

pub async fn scan_block<M>(
    provider: Arc<M>,
    start_block: u64,
    end_block: u64,
) -> Result<Vec<TransactionRecord>, M::Error>
where
    M: Middleware + 'static,
{
    let mut result = Vec::new();

    for block_number in start_block..end_block {
        if let Some(block) = provider.get_block_with_txs(block_number).await? {
            let naive =
                NaiveDateTime::from_timestamp_opt(block.timestamp.as_u64() as i64, 0).unwrap();
            let date_time: DateTime<Utc> = DateTime::from_utc(naive, Utc);
            let timestamp_str = date_time.to_rfc3339();

            info!(
                "Scanning block {} ({} transactions)",
                block_number,
                block.transactions.len()
            );

            for tx in block.transactions {
                let record = TransactionRecord {
                    hash: format!("{:?}", tx.hash),
                    from: format!("{:?}", tx.from),
                    to: tx.to.map(|addr| format!("{:?}", addr)),
                    value: wei_to_eth(tx.value.as_u128()),
                    gas: tx.gas.as_u64(),
                    gas_price_gwei: wei_to_gwei(tx.gas_price.unwrap_or_default().as_u128()),
                    block_number: block_number,
                    timestamp: timestamp_str.clone(),
                };
                result.push(record);
            }
        }
    }
    Ok(result)
}

fn wei_to_eth(wei: u128) -> f64 {
    wei as f64 / 1e18
}

fn wei_to_gwei(wei: u128) -> f64 {
    wei as f64 / 1e9
}
