use crate::{
    config::{K_LOCAL, K_LOCAL_FEE, PERC, THRESHOLD_TIME},
    models::{
        Anomaly, BusinessPattern, Severity, SharedTxStorage, TransactionRecord,
    }, scanner::fetch_sanctioned_addresses
};
use chrono::{DateTime, Duration, Timelike, Utc};
use ethers::prelude::*;  
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use once_cell::sync::Lazy;
use tokio::sync::RwLock;

abigen!(
    UniswapV2Factory,
    r#"[
        function allPairsLength() external view returns (uint256)
        function allPairs(uint256) external view returns (address)
    ]"#
);

static FLAGGED_HASHES: Lazy<RwLock<HashSet<String>>> = Lazy::new(|| RwLock::new(HashSet::new()));

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
                        timestamp: timestamp
                    });
                    let mut hashes = FLAGGED_HASHES.write().await;
                    hashes.insert(tx.hash.clone());
            }
            (true, false) | (false, true) => {
                anomalies.push(Anomaly::LargeTx {
                    tx_hash: tx.hash.clone(),
                    severity: Severity::Weak,
                    reasons: vec![format!("Suspiciously large transaction: {}", &tx.value)],
                    timestamp: timestamp
                });
                let mut hashes = FLAGGED_HASHES.write().await;
                hashes.insert(tx.hash.clone());
            }
            (false, false) => {}
        };
    }

    anomalies
}

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
                    timestamp: timestamp
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
                    timestamp: timestamp
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
                reasons: vec![format!("Transactions from a sanctioned address: {}", &tx.from)],
                timestamp: timestamp
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
                    timestamp: timestamp
                });
                let mut hashes = FLAGGED_HASHES.write().await;
                hashes.insert(tx.hash.clone());
            }
        }
    }

    anomalies
}

pub async fn detect_unusual_op(
    storage: &SharedTxStorage
) -> Vec<Anomaly> {
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
                severity: if unusual_value || unusual_gas { Severity::Strong } else { Severity::Weak },
                reasons: vec![
                    format!(
                        "Unusual operation: value={}, gas={}, input_len={}",
                        tx.value, tx.gas_price_gwei, tx.input.len()
                    ),
                ],
                timestamp: timestamp
            });
        }
    }

    anomalies
}

pub async fn detect_time_anomalies(storage: &SharedTxStorage) -> Vec<Anomaly> {
    let all_txs = storage.all_txs.read().await;
    let mut anomalies: Vec<Anomaly> = Vec::new();

    // let now = chrono::Utc::now();
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
                timestamp: timestamp
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
