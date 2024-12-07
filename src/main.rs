mod certificate;
mod options;
mod utils;

use certificate::{generate_cert, make_root_cert};
use clap::Parser;
use options::Opt;
use utils::save_cert_and_key;

#[derive(Debug, Clone)]
pub struct CertifiedKeyDer {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

fn main() {
    let options = Opt::parse();

    // 1. Generate root certificate
    let root_cert = make_root_cert();
    let _ = save_cert_and_key(&root_cert, "rootCA.pem", "rootCA-key.pem", &options.ca_path);

    // 2. Generate server certificate
    let server_host = options.server.to_lowercase();
    let server_cert = generate_cert(server_host.clone(), &root_cert);

    if options.nohost {
        let _ = save_cert_and_key(
            &server_cert,
            "server.pem",
            "server-key.pem",
            &options.ca_path,
        );
    } else {
        let _ = save_cert_and_key(
            &server_cert,
            format!("{}.pem", server_host).as_str(),
            format!("{}-key.pem", server_host).as_str(),
            &options.ca_path,
        );
    }

    // 3. Generate client certificate
    let client_host = options.client.to_lowercase();
    let client_cert = generate_cert(client_host.clone(), &root_cert);

    if options.nohost {
        let _ = save_cert_and_key(
            &client_cert,
            "client.pem",
            "client-key.pem",
            &options.ca_path,
        );
    } else {
        let _ = save_cert_and_key(
            &client_cert,
            format!("{}-client.pem", client_host).as_str(),
            format!("{}-client-key.pem", client_host).as_str(),
            &options.ca_path,
        );
    }

    println!(
        "Certificates and keys have been generated and saved in directory: {}/",
        options.ca_path
    );
}
