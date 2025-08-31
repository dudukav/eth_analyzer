use crate::models::{Anomaly, BusinessPattern};
use csv::Writer;

pub async fn export_anomalies_csv(anomalies: &Vec<Anomaly>, path: &str) -> csv::Result<()> {
    let mut wtr = Writer::from_path(path)?;
    for a in anomalies {
        wtr.serialize(a)?;
    }
    wtr.flush()?;
    Ok(())
}

pub async fn export_patterns_csv(patterns: &Vec<BusinessPattern>, path: &str) -> csv::Result<()> {
    let mut wtr = Writer::from_path(path)?;
    for p in patterns {
        wtr.serialize(p)?;
    }
    wtr.flush()?;
    Ok(())
}
