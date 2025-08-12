use crate::models::{TransactionRecord, TxStorage};
use chrono::{DateTime, NaiveDateTime, Utc};
use ethers::providers::Middleware;
use log::{debug, error, info, warn};
use std::sync::Arc;

pub async fn scan_block<M>(
    provider: Arc<M>,
    start_block: u64,
    end_block: u64,
) -> Result<TxStorage, M::Error>
where
    M: Middleware + 'static,
{
    let mut result = TxStorage::new();

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
                result.add_transaction(tx.from, tx.to, record);
            }
        }
    }
    Ok(result)
}

// pub fn save_to_csv(records: &Vec<TransactionRecord>, path: &str) -> Result<(), Box<dyn std::error::Error>> {
//     let mut wtr = Writer::from_path(path)?;
//     for rec in records {
//         wtr.serialize(rec)?;
//     }
//     wtr.flush()?;
//     Ok(())
// }

fn wei_to_eth(wei: u128) -> f64 {
    wei as f64 / 1e18
}

fn wei_to_gwei(wei: u128) -> f64 {
    wei as f64 / 1e9
}
