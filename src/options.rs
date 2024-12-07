use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
pub struct Opt {
    #[clap(long, value_name = "string", help = "Set the server host name.")]
    pub server: String,

    #[clap(long, value_name = "string", help = "Set the client host name.")]
    pub client: String,

    #[clap(
        long,
        value_name = "string",
        help = "Set the name of the CA. Default is \"mTLS CA (current_date)\"."
    )]
    pub ca_name: Option<String>,

    #[clap(
        long,
        value_name = "PATH",
        help = "Directory path for storing keys and certificates. Default is current directory.",
        default_value = "."
    )]
    pub output_dir: String,

    #[clap(
        long,
        value_name = "u64",
        help = "Specify the CA certificate validity in days. Default: max. period."
    )]
    pub ca_days: Option<u64>,

    #[clap(
        long,
        value_name = "u64",
        help = "Specify the certificate validity in days. Default: max. period."
    )]
    pub crt_days: Option<u64>,

    #[clap(
        long,
        default_value_t = false,
        help = "Use ECDSA algorithm for certificates. Default is RSA."
    )]
    pub ecdsa: bool,

    #[clap(
        long,
        default_value_t = false,
        help = "Disable the use of hostnames for certificate file names."
    )]
    pub nohost: bool,
}
