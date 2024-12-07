```bash
cargo run -- --help
```

```
Generate self-signed certificates for mutual TLS authentication

Usage: mtls [OPTIONS] --server <string> --client <string>

Options:
      --server <string>   Set the server host name.
      --client <string>   Set the client host name.
      --ca-name <string>  Set the name of the CA. Default is "mTLS CA (current_date)".
      --output_dir <PATH>    Directory path for storing keys and certificates. Default is current directory. [default: .]
      --ca-days <u64>     Specify the CA certificate validity in days. Default: max. period.
      --crt-days <u64>    Specify toot certificate validity in days. Default: max. period.
      --ecdsa             Use ECDSA algorithm instead of RSA. Default is RSA.
      --nohost            Disable the use of hostnames for certificate file names.
  -h, --help              Print help
  -V, --version           Print version
```

## How to use

Create self-signed certificates for server 203.0.113.99 and client1, and save keys and certificates in the current directory:

```bash
cargo run -- --server 203.0.113.99 --client client1
```

Create self-signed certificates for server 203.0.113.99 and client2, and save keys and certificates in the `certs` folder:

```bash
cargo run -- --server 203.0.113.99 --client client2 --output_dir './certs'
```

## Ho to build

```bash
cargo build --release
```

```bash
./target/release/mtls --help
```
