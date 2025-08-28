use crate::{
    config::{K_LOCAL, PERC, THRESHOLD_TIME},
    models::{AnalysisResult, Anomaly, Severity, SharedTxStorage, TransactionRecord},
};
use chrono::{DateTime, Duration, Utc};
// use dashmap::DashMap;
// use ethers::types::Address;
// use std::sync::Arc;

pub async fn detect_large_tx(storage: &SharedTxStorage) -> Vec<AnalysisResult> {
    let mut result: Vec<AnalysisResult> = Vec::new();

    let all_txs = storage.all_txs.write().await;
    let global_thershold = global_threshold(storage).await;
    for tx in all_txs.iter() {
        let sender = tx.from.clone();
        let local_mean = local_mean(storage, &sender);

        let local_flag = local_mean > 0.0 && tx.value > K_LOCAL * local_mean;
        let global_flag = tx.value > global_thershold;

        let mut anomalies = Vec::new();

        match (local_flag, global_flag) {
            (true, true) => anomalies.push(Anomaly::LargeTx {
                tx_hash: tx.hash.clone(),
                severity: Severity::Strong,
            }),
            (true, false) | (false, true) => anomalies.push(Anomaly::LargeTx {
                tx_hash: tx.hash.clone(),
                severity: Severity::Weak,
            }),
            (false, false) => {}
        };

        if !anomalies.is_empty() {
            result.push(AnalysisResult {
                anomalies: anomalies,
                patterns: vec![],
            });
        }
    }

    result
}

pub async fn detect_high_frequency(storage: &SharedTxStorage) -> Vec<AnalysisResult> {
    let mut result: Vec<AnalysisResult> = Vec::new();

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

        if count > THRESHOLD_TIME {
            anomalies.push(Anomaly::HighFrequency {
                sender: sender.to_string(),
                count: count,
            });
        }
    }

    result.push(AnalysisResult {
        anomalies: anomalies,
        patterns: vec![],
    });

    result
}

pub async fn detect_structuring(storage: &SharedTxStorage) -> Vec<AnalysisResult> {
    let mut result: Vec<AnalysisResult> = Vec::new();

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
            (true, true, true) => anomalies.push(Anomaly::Structuring {
                sender: sender.to_string(),
                count: count,
                severity: Severity::Strong,
            }),
            (false, false, false) => {}
            _ => anomalies.push(Anomaly::Structuring {
                sender: sender.to_string(),
                count: count,
                severity: Severity::Weak,
            }),
        };
    }

    result.push(AnalysisResult {
        anomalies: anomalies,
        patterns: vec![],
    });

    result
}

fn percentile(values: &Vec<f64>, perc: &f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let mut sorted: Vec<f64> = values.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((perc / 100.0) * (sorted.len() as f64 - 1.0)) as usize;
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
    let all_txs = storage.all_txs.write().await;
    let all_values: Vec<f64> = all_txs.iter().map(|tx| tx.value).collect();
    let global_thershold = percentile(&all_values, &PERC);

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
    storage.by_sender.get(sender)
        .map(|txs| {
            let fees: Vec<f64> = txs.iter().map(|tx| tx.gas_price_gwei * tx.gas as f64 / 1e9).collect();
            if fees.is_empty() { 0.0 } else { fees.iter().sum::<f64>() / fees.len() as f64 }
        })
        .unwrap_or(0.0)
}