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

use std::{
    io::{self, Read},
    str::FromStr,
};

use crate::{
    bundle::Version as BundleVersion,
    crypto::certificate::{is_leaf, is_root_ca},
};

use crate::Bundle;
use pkcs8::der::Decode;
use sha2::{Digest, Sha256};
use sigstore_protobuf_specs::dev::sigstore::{
    bundle::v1::{bundle, verification_material},
    rekor::v1::{InclusionProof, TransparencyLogEntry},
};
use thiserror::Error;
use tracing::debug;
use x509_cert::Certificate;

#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("Certificate expired before time of signing")]
    CertificateExpired,

    #[error("Certificate malformed")]
    CertificateMalformed,

    #[error("Failed to verify certificate")]
    CertificateVerificationFailure,

    #[error("Certificate cannot be used for verification: {0}")]
    CertificateTypeError(String),

    #[error("Failed to verify that the signature corresponds to the input")]
    SignatureVerificationFailure,

    #[error("{0}")]
    PolicyFailure(String),
}
pub type VerificationResult = Result<(), VerificationError>;

pub struct VerificationMaterials {
    pub input_digest: Vec<u8>,
    pub certificate: Certificate,
    pub signature: Vec<u8>,
    rekor_entry: Option<TransparencyLogEntry>,
}

impl VerificationMaterials {
    pub fn new<R: Read>(
        input: &mut R,
        certificate: Certificate,
        signature: Vec<u8>,
        offline: bool,
        rekor_entry: Option<TransparencyLogEntry>,
    ) -> Option<VerificationMaterials> {
        let mut hasher = Sha256::new();
        io::copy(input, &mut hasher).ok()?;

        if offline && rekor_entry.is_none() {
            // offline verification requires a Rekor entry
            return None;
        }

        Some(Self {
            input_digest: hasher.finalize().to_vec(),
            rekor_entry,
            certificate,
            signature,
        })
    }

    /// Constructs a VerificationMaterials from the given Bundle.
    ///
    /// For details on bundle semantics, please refer to [VerificationMaterial].
    ///
    /// [VerificationMaterial]: sigstore_protobuf_specs::dev::sigstore::bundle::v1::VerificationMaterial
    ///
    pub fn from_bundle<R: Read>(input: &mut R, bundle: Bundle, offline: bool) -> Option<Self> {
        let (content, mut tlog_entries) = match bundle.verification_material {
            Some(m) => (m.content, m.tlog_entries),
            _ => todo!("missing VerificationMaterial"),
        };

        // Parse the certificates. The first entry in the chain MUST be a leaf certificate, and the
        // rest of the chain MUST NOT include a root CA or any intermediate CAs that appear in an
        // independent root of trust.
        let certs = match content {
            Some(verification_material::Content::X509CertificateChain(ch)) => ch.certificates,
            Some(verification_material::Content::Certificate(cert)) => {
                vec![cert]
            }
            _ => todo!("unsupported VerificationMaterial Content"),
        };
        let certs = certs
            .iter()
            .map(|c| c.raw_bytes.as_slice())
            .map(Certificate::from_der)
            .collect::<Result<Vec<_>, _>>()
            .ok()?;

        let [leaf_cert, chain_certs @ ..] = &certs[..] else {
            return None;
        };

        if is_leaf(leaf_cert).is_err() {
            return None;
        }

        for chain_cert in chain_certs {
            if is_root_ca(chain_cert).is_ok() {
                return None;
            }
        }

        let signature = match bundle.content? {
            bundle::Content::MessageSignature(s) => s.signature,
            _ => todo!("DSSE signatures in bundles"),
        };

        if tlog_entries.len() != 1 {
            // Expected exactly one tlog entry.
            return None;
        }
        let tlog_entry = tlog_entries.remove(0);

        let (inclusion_promise, inclusion_proof) =
            (&tlog_entry.inclusion_promise, &tlog_entry.inclusion_proof);

        // `inclusion_proof` is now a required field in the protobuf spec,
        // but older versions of Rekor didn't provide inclusion proofs.
        //
        // https://github.com/sigstore/sigstore-python/pull/634#discussion_r1182769140
        match BundleVersion::from_str(&bundle.media_type) {
            Ok(BundleVersion::Bundle0_1) => {
                if inclusion_promise.is_none() {
                    todo!("bundle must contain inclusion promise")
                }

                if matches!(
                    inclusion_proof,
                    Some(InclusionProof {
                        checkpoint: None,
                        ..
                    })
                ) {
                    debug!("bundle contains inclusion proof without checkpoint");
                }
            }
            Ok(BundleVersion::Bundle0_2) => {
                if inclusion_proof.is_none() {
                    todo!("bundle must contain inclusion proof")
                }

                if matches!(
                    inclusion_proof,
                    Some(InclusionProof {
                        checkpoint: None,
                        ..
                    })
                ) {
                    todo!("bundle must contain checkpoint");
                }
            }
            Err(_) => {
                todo!("unknown bundle version")
            }
        }

        Self::new(
            input,
            leaf_cert.clone(),
            signature,
            offline,
            Some(tlog_entry),
        )
    }

    /// Retrieves the [LogEntry] for the materials.
    pub fn rekor_entry(&self) -> &TransparencyLogEntry {
        // TODO(tnytown): Fetch online Rekor entry and confirm consistency here.
        #[allow(clippy::unwrap_used)]
        self.rekor_entry.as_ref().unwrap()
    }
}
