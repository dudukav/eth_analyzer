use ethers::providers::{Provider, Middleware};
use ethers::types::{BlockNumber, Transaction};
use std::sync::Arc;

pub async fn scan_block<M>(provider: Arc<M>) -> Result<(), M::Error>
where M: Middleware + 'static
{
    let block_number = provider.get_block_number().await?;
    let block = provider.get_block_with_txs(block_number).await?;

    Ok(())
}