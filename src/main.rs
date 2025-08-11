mod scanner;

use ethers::providers::{Provider, Http};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let rpc_url = "https://mainnet.infura.io/v3/aeadc00d6e1d4e25b3ecbe34617e1165";
    let provider = Arc::new(Provider::<Http>::try_from(rpc_url)?);

    Ok(())

}
