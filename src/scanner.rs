use crate::models::{SharedTxStorage, TransactionRecord};
use chrono::{DateTime, Utc};
use ethers::{providers::Middleware, utils::hex};
use futures::stream::{FuturesUnordered, StreamExt};
use log::info;
use reqwest;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;

/// Scans a range of blockchain blocks and stores their transactions in `TxStorage`.
///
/// This asynchronous function iterates over blocks from `start_block` to `end_block`
/// (inclusive), retrieves all transactions in each block using the provided `provider`,
/// converts them into [`TransactionRecord`]s, and stores them in a shared
/// [`TxStorage`] instance.
///
/// Transactions are stored in three ways:
/// 1. Globally in `storage.all_txs` (protected by a `RwLock`).
/// 2. Indexed by sender in `storage.by_sender` (`DashMap`).
/// 3. Indexed by receiver in `storage.by_reciever` (`DashMap`), if a `to` address exists.
///
/// The function processes multiple blocks concurrently using `FuturesUnordered`
/// for efficient asynchronous execution.
///
/// # Parameters
/// * `provider` – A reference-counted Ethereum provider implementing [`Middleware`].
/// * `start_block` – The starting block number (inclusive) to scan.
/// * `end_block` – The ending block number (inclusive) to scan.
/// * `storage` – Shared transaction storage (`SharedTxStorage`) for storing results.
///
/// # Returns
/// Returns `Result<(), M::Error>`:
/// * `Ok(())` on success.
/// * Propagates any errors from the provider.
///
/// # Notes
/// * The block timestamp is converted to UTC and stored in RFC 3339 format in each `TransactionRecord`.
/// * Gas prices and values are converted from Wei to ETH/Gwei using helper functions (`wei_to_eth`, `wei_to_gwei`).
/// * This function clones the provider and storage references for each concurrent block scan.
/// * Transaction hashes, addresses, and input data are converted to string representations.
/// * The function uses `futures::stream::FuturesUnordered` to run multiple block fetches in parallel.
///
/// # Example
///
/// ```rust,ignore
/// let provider = Arc::new(your_provider);
/// let storage = Arc::new(TxStorage::new());
/// scan_block(&provider, 1000, 1010, &storage).await.unwrap();
/// ```
///
/// # Panics
/// * Panics if the block timestamp cannot be converted to a valid `DateTime<Utc>`.
pub async fn scan_block<M>(
    provider: &Arc<M>,
    start_block: u64,
    end_block: u64,
    storage: &SharedTxStorage,
) -> Result<(), M::Error>
where
    M: Middleware + 'static,
{
    let mut futures = FuturesUnordered::new();

    for block_number in start_block..=end_block {
        let provider = Arc::clone(provider);
        let storage = Arc::clone(storage);

        futures.push(async move {
            if let Some(block) = provider.get_block_with_txs(block_number).await? {
                let ts: i64 = block.timestamp.as_u64() as i64;
                let datetime: DateTime<Utc> =
                    DateTime::<Utc>::from_timestamp(ts, 0).expect("invalid timestamp");
                let timestamp_str = datetime.to_rfc3339();

                info!(
                    "Processing block {} ({} transactions)",
                    block_number,
                    block.transactions.len()
                );

                let mut batch: Vec<TransactionRecord> =
                    Vec::with_capacity(block.transactions.len());
                for tx in block.transactions {
                    batch.push(TransactionRecord {
                        hash: format!("{:?}", tx.hash),
                        from: format!("{:?}", tx.from),
                        to: tx.to.map(|addr| format!("{:?}", addr)),
                        value: wei_to_eth(tx.value.as_u128()),
                        gas: tx.gas.as_u64(),
                        gas_price_gwei: wei_to_gwei(tx.gas_price.unwrap_or_default().as_u128()),
                        block_number,
                        timestamp: timestamp_str.clone(),
                        input: format!("0x{}", hex::encode(&tx.input)),
                    });
                }

                {
                    let mut all_txs = storage.all_txs.write().await;
                    all_txs.extend(batch.clone());
                }

                for tx in batch {
                    storage
                        .by_sender
                        .entry(tx.from.clone())
                        .or_default()
                        .push(tx.clone());
                    if let Some(to) = &tx.to {
                        storage.by_reciever.entry(to.clone()).or_default().push(tx);
                    }
                }
            }
            Ok::<(), M::Error>(())
        });
    }

    while let Some(res) = futures.next().await {
        res?;
    }

    Ok(())
}

#[derive(Deserialize)]
struct SanctionedAddress {
    address: String,
}

pub async fn fetch_sanctioned_addresses() -> Result<HashSet<String>, reqwest::Error> {
    let url = "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_ETH.json";
    let resp = reqwest::get(url).await?;

    if resp.status().is_success() {
        let addresses: Vec<SanctionedAddress> = resp.json().await?;
        Ok(addresses.into_iter().map(|a| a.address).collect())
    } else {
        eprintln!("⚠️ Ошибка загрузки данных: {}", resp.status());
        Ok(HashSet::new())
    }
}

fn wei_to_eth(wei: u128) -> f64 {
    wei as f64 / 1e18
}

fn wei_to_gwei(wei: u128) -> f64 {
    wei as f64 / 1e9
}
