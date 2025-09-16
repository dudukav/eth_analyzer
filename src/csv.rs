use crate::models::{Anomaly, AnomalyCsv, BusinessPattern, BusinessPatternCsv};

/// Exports a list of anomalies to a CSV file.
///
/// Converts each [`Anomaly`] into its CSV-friendly representation [`AnomalyCsv`]
/// and writes all records to the file specified by `path`.
///
/// # Parameters
///
/// * `anomalies` – A reference to a vector of [`Anomaly`] instances to be exported.
/// * `path` – The file path where the CSV will be written.
///
/// # Returns
///
/// Returns `csv::Result<()>`:
/// * `Ok(())` on success.
/// * Propagates any CSV writing errors, e.g., file I/O errors or serialization errors.
///
/// # Notes
///
/// * Each `Anomaly` is converted into an `AnomalyCsv` before writing.
/// * Existing files at `path` will be overwritten.
/// * Use UTF-8 compatible paths and ensure the directory exists.
///
/// # Example
///
/// ```rust,ignore
/// let anomalies: Vec<Anomaly> = detect_anomalies(&storage).await;
/// export_anomalies_csv(&anomalies, "anomalies.csv").unwrap();
/// println!("Anomalies exported to anomalies.csv");
/// ```
pub fn export_anomalies_csv(anomalies: &Vec<Anomaly>, path: &str) -> csv::Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;
    for a in anomalies {
        let row: AnomalyCsv = a.into();
        wtr.serialize(row)?;
    }
    wtr.flush()?;
    Ok(())
}

/// Exports a list of business patterns to a CSV file.
///
/// Converts each [`BusinessPattern`] into its CSV-friendly representation [`BusinessPatternCsv`]
/// and writes all records to the file specified by `path`.
///
/// # Parameters
///
/// * `patterns` – A reference to a vector of [`BusinessPattern`] instances to be exported.
/// * `path` – The file path where the CSV will be written.
///
/// # Returns
///
/// Returns `csv::Result<()>`:
/// * `Ok(())` on success.
/// * Propagates any CSV writing errors, such as file I/O or serialization errors.
///
/// # Notes
///
/// * Each `BusinessPattern` is converted into a `BusinessPatternCsv` before writing.
/// * Existing files at `path` will be overwritten.
/// * Ensure that the directory exists and the path is UTF-8 compatible.
///
/// # Example
///
/// ```rust,ignore
/// let patterns: Vec<BusinessPattern> = detect_business_patterns(&storage).await;
/// export_patterns_csv(&patterns, "patterns.csv").unwrap();
/// println!("Business patterns exported to patterns.csv");
/// ```
pub fn export_patterns_csv(patterns: &Vec<BusinessPattern>, path: &str) -> csv::Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;
    for p in patterns {
        let row: BusinessPatternCsv = p.into();
        wtr.serialize(row)?;
    }
    wtr.flush()?;
    Ok(())
}
