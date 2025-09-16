#[cfg(test)]
mod test {
    use super::*;
    use chrono::{Duration, Utc};
    use dashmap::DashMap;
    use eth_analyzer::{
        analize::{
            detect_active_traders, detect_arbitrage, detect_dex_trade, detect_high_fee,
            detect_high_frequency, detect_large_tx, detect_liquid_provider, detect_nft_activity,
            detect_regular_payments, detect_structuring, detect_time_anomalies, detect_unusual_op,
            detect_whales,
        },
        csv::{export_anomalies_csv, export_patterns_csv},
        models::{Anomaly, BusinessPattern, Severity, TransactionRecord, TxStorage, AnomalyCsv, BusinessPatternCsv},
    };
    use ethers::types::H160;
    use once_cell::sync::Lazy;
    use std::{collections::HashSet, sync::Arc};
    use tokio::sync::RwLock;
    use tempfile::NamedTempFile;
    use std::fs;

    fn create_test_storage() -> Arc<TxStorage> {
        Arc::new(TxStorage {
            by_sender: DashMap::new(),
            by_reciever: DashMap::new(),
            all_txs: RwLock::new(vec![]),
        })
    }

    fn txs_in_interval(
        txs: &[TransactionRecord],
        start: chrono::DateTime<Utc>,
        end: chrono::DateTime<Utc>,
    ) -> Vec<TransactionRecord> {
        txs.iter()
            .filter(|tx| {
                if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&tx.timestamp) {
                    let ts_utc = ts.with_timezone(&Utc);
                    ts_utc >= start && ts_utc <= end
                } else {
                    false
                }
            })
            .cloned()
            .collect()
    }

    fn create_storage_with_txs(txs: Vec<TransactionRecord>) -> Arc<TxStorage> {
        let storage = TxStorage {
            by_sender: DashMap::new(),
            by_reciever: DashMap::new(),
            all_txs: RwLock::new(vec![]),
        };
        for tx in &txs {
            storage
                .by_sender
                .entry(tx.from.clone())
                .or_default()
                .push(tx.clone());
            if let Some(to) = &tx.to {
                storage
                    .by_reciever
                    .entry(to.clone())
                    .or_default()
                    .push(tx.clone());
            }
        }
        tokio::runtime::Handle::current().block_on(async {
            let mut all_txs = storage.all_txs.write().await;
            all_txs.extend(txs);
        });
        Arc::new(storage)
    }

    fn make_tx(
        hash: &str,
        from: &str,
        to: Option<&str>,
        value: f64,
        timestamp: String,
    ) -> TransactionRecord {
        TransactionRecord {
            hash: hash.to_string(),
            from: from.to_string(),
            to: to.map(str::to_string),
            value,
            gas: 21000,
            gas_price_gwei: 50.0,
            block_number: 1,
            timestamp,
            input: "0x".to_string(),
        }
    }

    #[tokio::test]
    async fn test_detect_large_tx() {
        let storage = create_test_storage();

        let tx1 = TransactionRecord {
            hash: "tx1".to_string(),
            from: "sender1".to_string(),
            to: Some("receiver1".to_string()),
            value: 1000.0,
            gas: 21000,
            gas_price_gwei: 50.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "".to_string(),
        };

        let tx2 = TransactionRecord {
            hash: "tx2".to_string(),
            from: "sender1".to_string(),
            to: Some("receiver1".to_string()),
            value: 1.0,
            gas: 2100,
            gas_price_gwei: 10.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "".to_string(),
        };

        let tx3 = TransactionRecord {
            hash: "tx3".to_string(),
            from: "sender1".to_string(),
            to: Some("receiver1".to_string()),
            value: 20.0,
            gas: 2100,
            gas_price_gwei: 10.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "".to_string(),
        };

        {
            let mut all_txs = storage.all_txs.write().await;
            all_txs.push(tx1);
            all_txs.push(tx2);
            all_txs.push(tx3);
        }

        let anomalies = detect_large_tx(&storage).await;

        assert_eq!(anomalies.len(), 1);
        let anomaly = &anomalies[0];
        match anomaly {
            Anomaly::LargeTx {
                severity, tx_hash, ..
            } => {
                assert_eq!(tx_hash, "tx1");
                assert_eq!(*severity, Severity::Weak);
            }
            _ => panic!("Wrong Anomaly type"),
        }
    }

    #[tokio::test]
    async fn test_detect_high_frequency() {
        let storage = create_test_storage();

        let now = Utc::now();

        let sender = "sender1".to_string();
        let mut txs = Vec::new();
        for i in 0..11 {
            txs.push(TransactionRecord {
                hash: format!("tx{}", i),
                from: sender.clone(),
                to: Some("receiver1".to_string()),
                value: 1.0,
                gas: 21000,
                gas_price_gwei: 50.0,
                block_number: 1,
                timestamp: (now - Duration::minutes(i)).to_rfc3339(),
                input: "".to_string(),
            });
        }

        storage.by_sender.insert(sender.clone(), txs);

        let anomalies = detect_high_frequency(&storage).await;

        assert_eq!(anomalies.len(), 1);
        let anomaly = &anomalies[0];
        match anomaly {
            Anomaly::HighFrequency {
                sender: s, count, ..
            } => {
                assert_eq!(s, "sender1");
                assert_eq!(*count, 11);
            }
            _ => panic!("Wrong anomaly type"),
        }
    }

    #[tokio::test]
    async fn test_detect_high_fee() {
        let storage = create_test_storage();

        let tx1 = TransactionRecord {
            hash: "tx1".to_string(),
            from: "sender1".to_string(),
            to: Some("receiver1".to_string()),
            value: 1.0,
            gas: 21,
            gas_price_gwei: 50.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "".to_string(),
        };

        let tx2 = TransactionRecord {
            hash: "tx2".to_string(),
            from: "sender1".to_string(),
            to: Some("receiver1".to_string()),
            value: 1.0,
            gas: 21,
            gas_price_gwei: 1.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "".to_string(),
        };

        let tx3 = TransactionRecord {
            hash: "tx3".to_string(),
            from: "sender1".to_string(),
            to: Some("receiver1".to_string()),
            value: 20.0,
            gas: 21,
            gas_price_gwei: 1.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "".to_string(),
        };

        {
            let mut all_txs = storage.all_txs.write().await;
            all_txs.push(tx1);
            all_txs.push(tx2);
            all_txs.push(tx3);
        }

        let anomalies = detect_high_fee(&storage).await;

        assert_eq!(anomalies.len(), 1);
        let anomaly = &anomalies[0];
        match anomaly {
            Anomaly::HighFee {
                severity, tx_hash, ..
            } => {
                assert_eq!(tx_hash, "tx1");
                assert_eq!(*severity, Severity::Weak);
            }
            _ => panic!("Wrong Anomaly type"),
        }
    }

    #[tokio::test]
    async fn test_detect_unusual_op() {
        let storage = create_test_storage();

        let tx1 = TransactionRecord {
            hash: "tx1".to_string(),
            from: "sender1".to_string(),
            to: Some("receiver1".to_string()),
            value: 1.0,
            gas: 21,
            gas_price_gwei: 500.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "0xffwhkfhk".to_string(),
        };

        let tx2 = TransactionRecord {
            hash: "tx2".to_string(),
            from: "sender1".to_string(),
            to: Some("receiver1".to_string()),
            value: 1.0,
            gas: 21,
            gas_price_gwei: 50.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "0xfddflfl".to_string(),
        };

        let tx3 = TransactionRecord {
            hash: "tx3".to_string(),
            from: "sender1".to_string(),
            to: Some("receiver1".to_string()),
            value: 1000.0,
            gas: 21,
            gas_price_gwei: 50.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "0xfpjrfpjw".to_string(),
        };

        let tx4 = TransactionRecord {
            hash: "tx4".to_string(),
            from: "sender1".to_string(),
            to: Some("receiver1".to_string()),
            value: 1.0,
            gas: 21,
            gas_price_gwei: 50.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "0xfwrhfwurhf".to_string(),
        };

        let tx5 = TransactionRecord {
            hash: "tx5".to_string(),
            from: "sender1".to_string(),
            to: Some("receiver1".to_string()),
            value: 1.0,
            gas: 21,
            gas_price_gwei: 50.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "3xgkfkjsfuwh".to_string(),
        };

        {
            let mut all_txs = storage.all_txs.write().await;
            all_txs.push(tx1);
            all_txs.push(tx2);
            all_txs.push(tx3);
            all_txs.push(tx4);
            all_txs.push(tx5);
        }

        let anomalies = detect_unusual_op(&storage).await;

        assert_eq!(anomalies.len(), 3);
    }

    #[tokio::test]
    async fn test_detect_structuring() {
        use chrono::Duration;
        use chrono::Utc;

        let storage = create_test_storage();

        let now = Utc::now();

        let mut txs = vec![];
        for i in 0..12 {
            txs.push(make_tx(
                &format!("hash{}", i),
                "sender1",
                Some("receiver1"),
                10.0, // каждая транзакция по 10
                (now - Duration::minutes(i)).to_rfc3339(),
            ));
        }

        storage.by_sender.insert("sender1".to_string(), txs.clone());

        {
            let mut all_txs = storage.all_txs.write().await;
            all_txs.extend(txs.clone());
        }

        let anomalies = detect_structuring(&storage).await;

        assert_eq!(anomalies.len(), 1);

        match &anomalies[0] {
            Anomaly::Structuring {
                sender,
                count,
                severity,
                reasons,
            } => {
                assert_eq!(sender, "sender1");
                assert_eq!(*count, 12);
                assert_eq!(*severity, Severity::Strong);
                assert!(reasons[0].contains("Transations count"));
                assert!(reasons[0].contains("Transations sum"));
            }
            _ => panic!("Ожидается Anomaly::Structuring"),
        }
    }

    #[tokio::test]
    async fn test_detect_time_anomalies() {
        use chrono::{Duration, Utc};
        let storage = create_test_storage();

        let now = Utc::now();

        let tx1 = make_tx(
            "tx1",
            "sender1",
            Some("receiver1"),
            10.0,
            (now.date().and_hms(3, 0, 0)).to_rfc3339(),
        );

        let now = Utc::now().date().and_hms(12, 0, 0); 
        let mut burst_txs = vec![];
        for i in 0..5 {
            burst_txs.push(make_tx(
                &format!("burst{}", i),
                "sender2",
                Some("receiver2"),
                1.0,
                (now + Duration::minutes(i)).to_rfc3339(),
            ));
        }

        {
            let mut all_txs = storage.all_txs.write().await;
            all_txs.push(tx1);
            all_txs.extend(burst_txs);
        }

        let anomalies = detect_time_anomalies(&storage).await;

        assert_eq!(anomalies.len(), 2);

        let mut time_anomaly_found = false;
        let mut burst_anomaly_found = false;

        for anomaly in anomalies {
            match anomaly {
                Anomaly::TimeAnomaly {
                    tx_hash, severity, ..
                } => {
                    assert_eq!(tx_hash, "tx1");
                    assert_eq!(severity, Severity::Weak);
                    time_anomaly_found = true;
                }
                Anomaly::BurstActivity { sender, reasons } => {
                    assert_eq!(sender, "sender2");
                    assert!(reasons[0].contains("Detected Burst activity"));
                    burst_anomaly_found = true;
                }
                _ => {}
            }
        }

        assert!(time_anomaly_found, "Time anomaly not detected");
        assert!(burst_anomaly_found, "Burst activity not detected");
    }

    #[tokio::test]
    async fn test_detect_regular_payments() {
        use chrono::{Duration, Utc};

        let storage = create_test_storage();

        let now = Utc::now();

        let tx1 = make_tx(
            "tx1",
            "sender1",
            Some("receiver1"),
            100.0,
            (now - Duration::hours(3)).to_rfc3339(),
        );
        let tx2 = make_tx(
            "tx2",
            "sender1",
            Some("receiver1"),
            100.0,
            (now - Duration::hours(2)).to_rfc3339(),
        );
        let tx3 = make_tx(
            "tx3",
            "sender1",
            Some("receiver1"),
            100.0,
            (now - Duration::hours(1)).to_rfc3339(),
        );

        storage
            .by_sender
            .insert("sender1".to_string(), vec![tx1, tx2, tx3]);

        let patterns = detect_regular_payments(&storage).await;

        assert_eq!(patterns.len(), 1);

        match &patterns[0] {
            BusinessPattern::RegularPayments { sender, message } => {
                assert_eq!(sender, "sender1");
                assert!(message.contains("Detected regular payments"));
            }
            _ => panic!("Ожидается BusinessPattern::RegularPayments"),
        }

        let tx4 = make_tx("tx4", "sender2", Some("receiver2"), 50.0, now.to_rfc3339());
        storage.by_sender.insert("sender2".to_string(), vec![tx4]);

        let patterns = detect_regular_payments(&storage).await;
        assert_eq!(patterns.len(), 1);
    }

    #[tokio::test]
    async fn test_detect_dex_trade() {
        let tx1 = TransactionRecord {
            hash: "tx1".to_string(),
            from: "sender1".to_string(),
            to: Some("0x1111111111111111111111111111111111111111".to_string()),
            value: 10.0,
            gas: 21,
            gas_price_gwei: 1.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "".to_string(),
        };

        let tx2 = TransactionRecord {
            hash: "tx2".to_string(),
            from: "sender2".to_string(),
            to: Some("0x2222222222222222222222222222222222222222".to_string()),
            value: 15.0,
            gas: 21,
            gas_price_gwei: 1.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "".to_string(),
        };

        let tx3 = TransactionRecord {
            hash: "tx3".to_string(),
            from: "sender3".to_string(),
            to: None,
            value: 20.0,
            gas: 21,
            gas_price_gwei: 1.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "".to_string(),
        };

        let storage = Arc::new(TxStorage {
            by_sender: DashMap::new(),
            by_reciever: DashMap::new(),
            all_txs: RwLock::new(vec![tx1, tx2, tx3]),
        });

        let dex_address: H160 = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();

        let mut dex_contracts = HashSet::new();
        dex_contracts.insert(dex_address);

        let patterns = detect_dex_trade(&storage, &dex_contracts).await;

        assert_eq!(patterns.len(), 1);
    }

    #[tokio::test]
    async fn test_nft_activity() {
        let storage = create_test_storage();

        let tx1 = TransactionRecord {
            hash: "tx1".to_string(),
            from: "sender1".to_string(),
            to: Some("receiver".to_string()),
            value: 100.0,
            gas: 21000,
            gas_price_gwei: 50.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "0x80ac58cd".to_string(),
        };

        {
            let mut all_txs = storage.all_txs.write().await;
            all_txs.push(tx1);
        }

        let patterns = detect_nft_activity(&storage).await;

        assert_eq!(patterns.len(), 1);

        match &patterns[0] {
            BusinessPattern::NFTActivity { tx_hash, .. } => {
                assert_eq!(tx_hash, "tx1");
            }
            _ => panic!("Ожидается"),
        }
    }

    #[tokio::test]
    async fn test_detect_arbitrage() {
        let tx1 = TransactionRecord {
            hash: "tx1".to_string(),
            from: "sender1".to_string(),
            to: Some("0x1111111111111111111111111111111111111111".to_string()),
            value: 10.0,
            gas: 21,
            gas_price_gwei: 1.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "multicall".to_string(),
        };

        let tx2 = TransactionRecord {
            hash: "tx2".to_string(),
            from: "sender2".to_string(),
            to: Some("0x2222222222222222222222222222222222222222".to_string()),
            value: 15.0,
            gas: 21,
            gas_price_gwei: 1.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "".to_string(),
        };

        let tx3 = TransactionRecord {
            hash: "tx3".to_string(),
            from: "sender3".to_string(),
            to: None,
            value: 20.0,
            gas: 21,
            gas_price_gwei: 1.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "".to_string(),
        };

        let storage = Arc::new(TxStorage {
            by_sender: DashMap::new(),
            by_reciever: DashMap::new(),
            all_txs: RwLock::new(vec![tx1, tx2, tx3]),
        });

        let dex_address: H160 = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();

        let mut dex_contracts = HashSet::new();
        dex_contracts.insert(dex_address);

        let patterns = detect_dex_trade(&storage, &dex_contracts).await;

    }

    #[tokio::test]
    async fn test_detect_whales() {
        let storage = create_test_storage();

        let tx1 = TransactionRecord {
            hash: "tx1".to_string(),
            from: "sender1".to_string(),
            to: Some("receiver1".to_string()),
            value: 200.0,
            gas: 21000,
            gas_price_gwei: 50.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "".to_string(),
        };

        let tx2 = TransactionRecord {
            hash: "tx2".to_string(),
            from: "sender1".to_string(),
            to: Some("receiver1".to_string()),
            value: 250.0,
            gas: 21000,
            gas_price_gwei: 50.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "".to_string(),
        };

        let tx3 = TransactionRecord {
            hash: "tx3".to_string(),
            from: "sender2".to_string(),
            to: Some("receiver2".to_string()),
            value: 10.0,
            gas: 21000,
            gas_price_gwei: 50.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "".to_string(),
        };

        let tx4 = TransactionRecord {
            hash: "tx4".to_string(),
            from: "sender2".to_string(),
            to: Some("receiver2".to_string()),
            value: 15.0,
            gas: 21000,
            gas_price_gwei: 50.0,
            block_number: 1,
            timestamp: Utc::now().to_rfc3339(),
            input: "".to_string(),
        };

        {
            let mut all_txs = storage.all_txs.write().await;
            all_txs.push(tx1.clone());
            all_txs.push(tx2.clone());
            all_txs.push(tx3.clone());
            all_txs.push(tx4.clone());
        }

        storage.by_sender.insert("sender1".to_string(), vec![tx1.clone(), tx2.clone()]);
        storage.by_sender.insert("sender2".to_string(), vec![tx3.clone(), tx4.clone()]);

        let patterns = detect_whales(&storage).await;

        assert_eq!(patterns.len(), 1);

        match &patterns[0] {
            BusinessPattern::Whales { sender } => {
                assert_eq!(sender, "sender1");
            }
            _ => panic!("Ожидается BusinessPattern::Whales"),
        }
    }

    #[test]
    fn test_export_anomalies_csv() {
        // создаём временный файл
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap().to_string();

        let anomalies = vec![
            Anomaly::Structuring {
                sender: "sender1".to_string(),
                count: 12,
                severity: Severity::Strong,
                reasons: vec!["Suspicious activity".to_string()],
            },
            Anomaly::TimeAnomaly {
                tx_hash: "tx123".to_string(),
                severity: Severity::Weak,
                reasons: vec!["Night time transaction".to_string()],
                timestamp: Utc::now(),
            },
        ];
        export_anomalies_csv(&anomalies, &path).expect("CSV export failed");

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("sender1"));
        assert!(content.contains("tx123"));
        assert!(content.contains("Strong"));
        assert!(content.contains("Weak"));
    }

    #[test]
    fn test_export_patterns_csv() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap().to_string();

        let patterns = vec![
            BusinessPattern::RegularPayments {
                sender: "userA".to_string(),
                message: "Detected regular payments from userA".to_string(),
            },
            BusinessPattern::DEXTrade {
                dex: "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f".to_string(),
                message: "Detected trading with DEX".to_string(),
            },
        ];

        export_patterns_csv(&patterns, &path).expect("CSV export failed");

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("userA"));
        assert!(content.contains("DEX"));
    }

}
