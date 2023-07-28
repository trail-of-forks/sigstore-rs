//
// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// CLI implemented to specification:
// https://github.com/sigstore/sigstore-conformance/blob/main/docs/cli_protocol.md

extern crate tracing_subscriber;
use clap::{Parser, Subcommand};
use std::fs;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use sigstore::cosign::client::Client;
use sigstore::cosign::CosignCapabilities;
use sigstore::registry::ClientConfig;

#[derive(Parser, Debug)]
struct Cli {
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Sign(Sign),
    SignBundle(SignBundle),
    Verify(Verify),
    VerifyBundle(VerifyBundle),
}

#[derive(Parser, Debug)]
struct Sign {
    // The OIDC identity token to use
    #[clap(long)]
    identity_token: String,

    // The path to write the signature to
    #[clap(long)]
    signature: String,

    // The path to write the signing certificate to
    #[clap(long)]
    certificate: String,

    // The artifact to sign
    artifact: String,
}

#[derive(Parser, Debug)]
struct SignBundle {
    // The OIDC identity token to use
    #[clap(long)]
    identity_token: String,

    // The path to write the bundle to
    #[clap(long)]
    bundle: String,

    // The artifact to sign
    artifact: String,
}

#[derive(Parser, Debug)]
struct Verify {
    // The path to the signature to verify
    #[clap(long)]
    signature: String,

    // The path to the signing certificate to verify
    #[clap(long)]
    certificate: String,

    // The expected identity in the signing certificate's SAN extension
    #[clap(long)]
    certificate_identity: String,

    // The expected OIDC issuer for the signing certificate
    #[clap(long)]
    certificate_oidc_issuer: String,

    // The path to the artifact to verify
    artifact: String,
}

#[derive(Parser, Debug)]
struct VerifyBundle {
    // The path to the Sigstore bundle to verify
    #[clap(long)]
    bundle: String,

    // The expected identity in the signing certificate's SAN extension
    #[clap(long)]
    certificate_identity: String,

    // The expected OIDC issuer for the signing certificate
    #[clap(long)]
    certificate_oidc_issuer: String,

    // The path to the artifact to verify
    artifact: String,
}

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let level_filter = if cli.verbose { "debug" } else { "info" };
    let filter_layer = EnvFilter::new(level_filter);
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();

    let auth = &sigstore::registry::Auth::Anonymous;
    let mut oci_client_config = ClientConfig::default();

    match &cli.command {
        Commands::Sign(Sign {
            identity_token,
            signature,
            certificate,
            artifact,
        }) => (),
        Commands::Verify(Verify {
            signature,
            certificate,
            certificate_identity,
            certificate_oidc_issuer,
            artifact,
        }) => {
            let certificate = fs::read_to_string(certificate)?;
            let signature = fs::read_to_string(signature)?;
            let artifact = fs::read(artifact)?;

            Client::verify_blob(&certificate, &signature, &artifact)?;
        }
        _ => (),
        /*
               SignBundle(SignBundle { .. }) => panic!(),
               VerifyBundle(VerifyBundle { .. }) => panic!(),
        */
    }

    /*
    let mut client_builder =
        sigstore::cosign::ClientBuilder::default().with_oci_client_config(oci_client_config).with_rekor_pub_key;
    */

    Ok(())
}
