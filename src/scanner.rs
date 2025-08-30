use crate::models::{SharedTxStorage, TransactionRecord};
use chrono::{DateTime, Utc};
use csv::Writer;
use ethers::{providers::Middleware, utils::hex};
use log::info;
use std::{fmt::format, sync::Arc};

pub async fn scan_block<M>(
    provider: Arc<M>,
    start_block: u64,
    end_block: u64,
    storage: SharedTxStorage,
) -> Result<(), M::Error>
where
    M: Middleware + 'static,
{
    let storage_clone = Arc::clone(&storage);
    for block_number in start_block..end_block {
        if let Some(block) = provider.get_block_with_txs(block_number).await? {
            let ts: i64 = block.timestamp.as_u64() as i64;
            let datetime: DateTime<Utc> =
                DateTime::<Utc>::from_timestamp(ts, 0).expect("invalid timestamp");
            let timestamp_str = datetime.to_rfc3339();

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
                    input: format!("0x{}", hex::encode(&tx.input)),
                };
                storage_clone.add_transaction(tx.from, tx.to, record).await;
            }
        }
    }
    Ok(())
}

pub fn save_to_csv(
    records: &Vec<TransactionRecord>,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut wtr = Writer::from_path(path)?;
    for rec in records {
        wtr.serialize(rec)?;
    }
    wtr.flush()?;
    Ok(())
}

fn wei_to_eth(wei: u128) -> f64 {
    wei as f64 / 1e18
}

fn wei_to_gwei(wei: u128) -> f64 {
    wei as f64 / 1e9
}
