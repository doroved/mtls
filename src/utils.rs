use std::{fs::File, io::Write};

pub fn save_cert_and_key(
    cert_key: &rcgen::CertifiedKey,
    cert_filename: &str,
    key_filename: &str,
    ca_path: &str,
) -> std::io::Result<()> {
    // Create directory for certificates if it doesn't exist
    if let Err(e) = std::fs::create_dir_all(ca_path) {
        eprintln!("Ошибка при создании директории {}: {}", ca_path, e);
        std::process::exit(1);
    }

    // Save certificate to file
    let mut cert_file = File::create(format!("{ca_path}/{cert_filename}"))?;
    cert_file.write_all(cert_key.cert.pem().as_bytes())?;

    // Save private key to file
    let mut key_file = File::create(format!("{ca_path}/{key_filename}"))?;
    key_file.write_all(cert_key.key_pair.serialize_pem().as_bytes())?;

    Ok(())
}
