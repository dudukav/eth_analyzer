mod analize;
mod config;
mod models;
mod scanner;
mod viz;

use ethers::providers::{Http, Middleware, Provider};
use models::TxStorage;
use scanner::scan_block;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let rpc_url = "https://mainnet.infura.io/v3/aeadc00d6e1d4e25b3ecbe34617e1165";
    let provider = Arc::new(Provider::<Http>::try_from(rpc_url)?);
    let last_block = provider.get_block_number().await?.as_u64();
    let start_block = last_block - 10;
    let end_block = last_block;

    let storage = Arc::new(TxStorage::new());
    let records = scan_block(provider, start_block, end_block, storage);

    Ok(())
}
