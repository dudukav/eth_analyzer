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
    // let client = Arc::new(&provider);
    let last_block = provider.get_block_number().await?.as_u64();
    let start_block = last_block - 10;
    let end_block = last_block;

    // let uniswap_v2_factory_addr: Address = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f".parse()?;
    let uniswap_v2_router: Address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D".parse()?;
    // let uniswap_v2_factory = UniswapV2Factory::new(uniswap_v2_factory_addr, Arc::clone(&client));

    // let sushiswap_factory_addr: Address = "0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac".parse()?;
    let sushiswap_router: Address = "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F".parse()?;
    // et sushiswap_factory = UniswapV2Factory::new(sushiswap_factory_addr, Arc::clone(&client));

    let mut dex_routers = HashSet::new();
    dex_routers.insert(uniswap_v2_router);
    dex_routers.insert(sushiswap_router);

    let storage = Arc::new(TxStorage::new());
    let _records = scan_block(&provider, start_block, end_block, &storage).await;
    let all_txs = storage.all_txs.read().await;
    println!("Всего транзакций: {}", all_txs.len());
    // for tx in all_txs.iter().take(5) { // показываем первые 5
    //     println!("TX: {} from {} to {:?}", tx.hash, tx.from, tx.to);
    // }

    let large_tx = detect_large_tx(&storage).await;
    // println!("Аномалилй с большой суммой: {}", large_tx.len());
    let high_frequency = detect_high_frequency(&storage).await;
    // println!("Аномалилй большого количества транзакций: {}", high_frequency.len());
    let structuring = detect_structuring(&storage).await;
    //println!("Аномалилй с дроблением: {}", structuring.len());
    let high_fee = detect_high_fee(&storage).await;
    //println!("Аномалилй с большой комиссией: {}", high_fee.len());
    let blacklist_addresses = detect_blacklist_adresses(&storage).await;
    let unusual_op = detect_unusual_op(&storage).await;
    //println!("Аномалилй с необычными операциями: {}", unusual_op.len());
    let time_anomaly = detect_time_anomalies(&storage).await;
    //println!("Аномалилй по времени: {}", time_anomaly.len());

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

    println!("Количество аномалий: {}", anomalies.len());

    let _ = export_anomalies_csv(&anomalies, file_path.to_str().unwrap()).map_err(|e| println!("Ошибка записи CSV: {:?}", e))
    .ok();
    

    let file_path = project_dir.join("patterns.csv");
    let regular_payments = detect_regular_payments(&storage).await;
    let batch_payments = detect_batch_payments(&storage).await;
    let dex_trade = detect_dex_trade(&storage, &dex_routers).await;
    let nft_activity = detect_nft_activity(&storage).await;
    let liquiditi_provider = detect_liquid_provider(&storage, &dex_routers).await;
    let active_traders = detect_active_traders(&storage, &dex_routers).await;
    let arbitrage = detect_arbitrage(&storage, &dex_routers).await;
    let whales = detect_whales(&storage).await;

    let mut patterns = Vec::new();
    patterns.extend(regular_payments);
    patterns.extend(batch_payments);
    patterns.extend(dex_trade);
    patterns.extend(nft_activity);
    patterns.extend(liquiditi_provider);
    patterns.extend(active_traders);
    patterns.extend(arbitrage);
    patterns.extend(whales);

    println!("Количество паттернов: {}", patterns.len());

    let _ = export_patterns_csv(&patterns, file_path.to_str().unwrap()).map_err(|e| println!("Ошибка записи CSV: {:?}", e))
    .ok();

    let project_dir = env::current_dir()?;
    let anomalies_path = project_dir.join("anomalies.csv");
    let patterns_path = project_dir.join("patterns.csv");

    // Вызов Python скрипта
    let viz_path = project_dir.join("src/viz.py"); // путь к Python скрипту
    let _python_path = project_dir.join("venv/bin/python3");
    let status = Command::new("python3")
        .arg(viz_path.to_str().unwrap())
        .arg(anomalies_path.to_str().unwrap())
        .arg(patterns_path.to_str().unwrap())
        .status()?;

    if !status.success() {
        eprintln!("Ошибка при запуске визуализации!");
    } else {
        println!("Графики успешно созданы!");
    }

    Ok(())
}
