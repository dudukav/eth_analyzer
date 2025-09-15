mod analize;
mod config;
mod csv;
mod models;
mod scanner;

use analize::{
    detect_active_traders, detect_arbitrage, detect_batch_payments, detect_blacklist_adresses,
    detect_dex_trade, detect_high_fee, detect_high_frequency, detect_large_tx,
    detect_liquid_provider, detect_nft_activity, detect_regular_payments, detect_structuring,
    detect_time_anomalies, detect_unusual_op, detect_whales,
};
use csv::{export_anomalies_csv, export_patterns_csv};
use ethers::prelude::*;
use ethers::providers::{Http, Middleware, Provider};
use log::{info, error};
use models::TxStorage;
use scanner::scan_block;
use std::{collections::HashSet, env, sync::Arc};
use std::process::Command;

abigen!(
    UniswapV2Factory,
    r#"[
        function allPairsLength() external view returns (uint256)
        function allPairs(uint256) external view returns (address)
    ]"#
);

abigen!(
    ERC20,
    r#"[
        function symbol() external view returns (string)
        function decimals() external view returns (uint8)
    ]"#
);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let rpc_url = "https://mainnet.infura.io/v3/aeadc00d6e1d4e25b3ecbe34617e1165";
    let provider = Arc::new(Provider::<Http>::try_from(rpc_url)?);
    let last_block = provider.get_block_number().await?.as_u64();
    let start_block = last_block - 10;
    let end_block = last_block;
    let uniswap_v2_router: Address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D".parse()?;
    let sushiswap_router: Address = "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F".parse()?;

    let mut dex_routers = HashSet::new();
    dex_routers.insert(uniswap_v2_router);
    dex_routers.insert(sushiswap_router);

    let storage = Arc::new(TxStorage::new());
    let _records = scan_block(&provider, start_block, end_block, &storage).await;
    let all_txs = storage.all_txs.read().await;
    info!("Total transactions: {}", all_txs.len());

    let large_tx = detect_large_tx(&storage).await;
    info!("Large transactions anomaly count: {}", large_tx.len());
    let high_frequency = detect_high_frequency(&storage).await;
    info!("High Frequency anomaly count: {}", high_frequency.len());
    let structuring = detect_structuring(&storage).await;
    info!("Structuring anomaly count: {}", structuring.len());
    let high_fee = detect_high_fee(&storage).await;
    info!("High fee anomaly count: {}", high_fee.len());
    let blacklist_addresses = detect_blacklist_adresses(&storage).await;
    info!("Blacklist anomaly count: {}", blacklist_addresses.len());
    let unusual_op = detect_unusual_op(&storage).await;
    info!("Unusual operations anomaly count: {}", unusual_op.len());
    let time_anomaly = detect_time_anomalies(&storage).await;
    info!("Time anomaly count: {}", time_anomaly.len());

    let project_dir = env::current_dir().unwrap();
    let file_path = project_dir.join("anomalies.csv");
    let mut anomalies = Vec::new();
    anomalies.extend(large_tx);
    anomalies.extend(high_frequency);
    anomalies.extend(structuring);
    anomalies.extend(high_fee);
    anomalies.extend(blacklist_addresses);
    anomalies.extend(unusual_op);
    anomalies.extend(time_anomaly);

    info!("Anomaly count: {}", anomalies.len());

    if let Err(e) = export_anomalies_csv(&anomalies, file_path.to_str().unwrap()) {
        error!("Error CSV writing: {:?}", e);
    } else {
        info!("Anomalies succesfully exported to CSV");
    }
    

    let file_path = project_dir.join("patterns.csv");
    let regular_payments = detect_regular_payments(&storage).await;
    info!("Regular payments pattern count: {}", regular_payments.len());
    let batch_payments = detect_batch_payments(&storage).await;
    info!("Batch Payments pattern count: {}", batch_payments.len());
    let dex_trade = detect_dex_trade(&storage, &dex_routers).await;
    info!("DEX trade pattern count: {}", dex_trade.len());
    let nft_activity = detect_nft_activity(&storage).await;
    info!("NFT activity pattern count: {}", nft_activity.len());
    let liquiditi_provider = detect_liquid_provider(&storage, &dex_routers).await;
    info!("Liquidity provider pattern count: {}", liquiditi_provider.len());
    let active_traders = detect_active_traders(&storage, &dex_routers).await;
    info!("Active Traders pattern count: {}", active_traders.len());
    let arbitrage = detect_arbitrage(&storage, &dex_routers).await;
    info!("Arbitrage pattern count: {}", arbitrage.len());
    let whales = detect_whales(&storage).await;
    info!("Whales pattern count: {}", whales.len());

    let mut patterns = Vec::new();
    patterns.extend(regular_payments);
    patterns.extend(batch_payments);
    patterns.extend(dex_trade);
    patterns.extend(nft_activity);
    patterns.extend(liquiditi_provider);
    patterns.extend(active_traders);
    patterns.extend(arbitrage);
    patterns.extend(whales);

    info!("Pattern count: {}", patterns.len());

    if let Err(e) = export_patterns_csv(&patterns, file_path.to_str().unwrap()) {
        error!("Error CSV writing: {:?}", e);
    } else {
        info!("Patterns succesfully exported to CSV");
    }

    let project_dir = env::current_dir()?;
    let anomalies_path = project_dir.join("anomalies.csv");
    let patterns_path = project_dir.join("patterns.csv");

    let viz_path = project_dir.join("src/viz.py");
    let _python_path = project_dir.join("venv/bin/python3");
    let status = Command::new("python3")
        .arg(viz_path.to_str().unwrap())
        .arg(anomalies_path.to_str().unwrap())
        .arg(patterns_path.to_str().unwrap())
        .status()?;

    match status.success() {
        true => info!("Plotter succesfully created!"),
        false => error!("Error")
    }

    Ok(())
}
