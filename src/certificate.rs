use chrono::Local;
use clap::Parser;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, DnValue, IsCa, KeyPair, KeyUsagePurpose,
};
use std::time::SystemTime;

use crate::options::Opt;

// Function for creating a key pair based on options
fn create_key_pair(ecdsa: bool) -> KeyPair {
    if ecdsa {
        KeyPair::generate().unwrap()
    } else {
        KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap()
    }
}

// Function for setting the validity period of a certificate
fn set_certificate_validity(params: &mut CertificateParams, days: Option<u64>) {
    if let Some(days) = days {
        let now = SystemTime::now();
        params.not_before = now.into();
        params.not_after = (now + std::time::Duration::from_secs(days * 24 * 60 * 60)).into();
    }
}

// Generate a root CA certificate
pub fn make_root_cert() -> rcgen::CertifiedKey {
    let options = Opt::parse();

    let now = Local::now().format("%d %b %Y").to_string();
    let ca_name = if let Some(ca_name) = options.ca_name {
        format!("{ca_name} CA ({now})")
    } else {
        format!("mTLS CA ({now})")
    };

    let mut param = CertificateParams::default();
    set_certificate_validity(&mut param, options.ca_days);

    param.distinguished_name = DistinguishedName::new();
    param
        .distinguished_name
        .push(DnType::CommonName, DnValue::Utf8String(ca_name));
    param.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    param.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let key_pair = create_key_pair(options.ecdsa);
    let cert = param.self_signed(&key_pair).unwrap();

    rcgen::CertifiedKey { cert, key_pair }
}

// Generate client/server certificates signed by root CA
pub fn generate_cert(host: String, root_cert: &rcgen::CertifiedKey) -> rcgen::CertifiedKey {
    let options = Opt::parse();

    let mut param = CertificateParams::new(vec![host.clone()]).unwrap();
    set_certificate_validity(&mut param, options.crt_days);

    param.key_usages.push(KeyUsagePurpose::DigitalSignature);
    param
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    param
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    param.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        dn
    };

    let key_pair = create_key_pair(options.ecdsa);
    let cert = param
        .signed_by(&key_pair, &root_cert.cert, &root_cert.key_pair)
        .unwrap();

    rcgen::CertifiedKey { cert, key_pair }
}
