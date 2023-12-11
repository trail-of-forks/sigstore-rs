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

//! Types for Certificate Transparency validation.

use const_oid::ObjectIdentifier;
use digest::Digest;
use tls_codec::{SerializeBytes, Size, TlsByteVecU16, TlsSerializeBytes, TlsSize};
use x509_cert::{
    der,
    der::Encode,
    ext::pkix::{
        sct::Version, BasicConstraints, ExtendedKeyUsage, SignedCertificateTimestamp,
        SignedCertificateTimestampList,
    },
    Certificate,
};

use crate::fulcio::models::SigningCertificateDetachedSCT;

use super::keyring::{Keyring, KeyringError};

/*
          digitally-signed struct {
              Version sct_version;
              SignatureType signature_type = certificate_timestamp;
              uint64 timestamp;
              LogEntryType entry_type;
              select(entry_type) {
                  case x509_entry: ASN.1Cert;
                  case precert_entry: PreCert;
              } signed_entry;
             CtExtensions extensions;
          };
*/

// TODO(tnytown): Migrate to const-oid's CT_PRECERT_SCTS when a new release is cut.
const CT_PRECERT_SCTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.2");
const PRECERTIFICATE_SIGNING_CERTIFICATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.4");

fn cert_is_preissuer(cert: &Certificate) -> bool {
    let eku: ExtendedKeyUsage = match cert.tbs_certificate.get() {
        Ok(Some((_, ext))) => ext,
        _ => return false,
    };

    eku.0.contains(&PRECERTIFICATE_SIGNING_CERTIFICATE)
}

// <https://github.com/sigstore/sigstore-python/blob/main/sigstore/_internal/sct.py>
// TODO(tnytown): verify that this approach is correct.
fn find_issuer_cert(chain: &[Certificate]) -> Option<&Certificate> {
    let cert = if cert_is_preissuer(&chain[0]) {
        &chain[1]
    } else {
        &chain[0]
    };

    let basic_constraints: BasicConstraints = match cert.tbs_certificate.get() {
        Ok(Some((_, ext))) => ext,
        _ => return None,
    };

    // TODO(tnytown): verify that cert is either ECDSA or RSA?

    if basic_constraints.ca {
        Some(cert)
    } else {
        None
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SCTError {
    #[error("invalid or missing SignedCertificateTimestampList extension")]
    SCTListMalformed,

    #[error("cannot decode SCT")]
    SCTMalformed,

    #[error("failed to verify SCT: {0}")]
    VerificationFailed(&'static str),

    #[error(transparent)]
    Other(#[from] der::Error),
}

impl From<KeyringError> for SCTError {
    fn from(_value: KeyringError) -> Self {
        Self::VerificationFailed("invalid signature")
    }
}

impl From<x509_cert::ext::pkix::Error> for SCTError {
    fn from(_value: x509_cert::ext::pkix::Error) -> Self {
        SCTError::SCTMalformed
    }
}

#[derive(Eq, PartialEq, Debug)]
struct TlsByteVecU24 {
    vec: Vec<u8>,
}

impl From<&[u8]> for TlsByteVecU24 {
    fn from(value: &[u8]) -> Self {
        Self {
            vec: Vec::from(value),
        }
    }
}

impl Size for TlsByteVecU24 {
    fn tls_serialized_len(&self) -> usize {
        self.vec.len() + 3
    }
}

impl SerializeBytes for TlsByteVecU24 {
    fn tls_serialize(&self) -> Result<Vec<u8>, tls_codec::Error> {
        let (tls_serialized_len, byte_len) = (self.tls_serialized_len(), self.vec.len());
        let max_len = (1 << 24) as usize;
        if self.vec.len() > max_len {
            return Err(tls_codec::Error::InvalidVectorLength);
        }

        let mut vec = Vec::with_capacity(tls_serialized_len);

        // write the 3 least significant bytes.
        let len_bytes = byte_len.to_be_bytes();
        vec.extend(&len_bytes[5..]);

        // write the content bytes.
        vec.extend_from_slice(&self.vec);

        Ok(vec)
    }
}

#[derive(PartialEq, Debug, TlsSerializeBytes, TlsSize)]
#[repr(u8)]
enum SignatureType {
    CertificateTimestamp = 0,
    TreeHash = 1,
}

#[derive(PartialEq, Debug)]
#[repr(u16)]
enum LogEntryType {
    X509Entry = 0,
    PrecertEntry = 1,
}

#[derive(PartialEq, Debug, TlsSerializeBytes, TlsSize)]
struct PreCert {
    // opaque issuer_key_hash[32];
    issuer_key_hash: [u8; 32],
    // opaque TBSCertificate<1..2^24-1>;
    tbs_certificate: TlsByteVecU24,
}

#[derive(PartialEq, Debug, TlsSerializeBytes, TlsSize)]
#[repr(u16)]
enum SignedEntry {
    // opaque ASN.1Cert<1..2^24-1>;
    #[tls_codec(discriminant = "LogEntryType::X509Entry")]
    X509Entry(TlsByteVecU24),
    #[tls_codec(discriminant = "LogEntryType::PrecertEntry")]
    PrecertEntry(PreCert),
}

#[derive(PartialEq, Debug, TlsSerializeBytes, TlsSize)]
pub struct DigitallySigned {
    version: Version,
    signature_type: SignatureType,
    timestamp: u64,
    signed_entry: SignedEntry,
    // opaque CtExtensions<0..2^16-1>;
    extensions: TlsByteVecU16,

    // HACK(tnytown): pass in some useful extra context.
    #[tls_codec(skip)]
    log_id: [u8; 32],
    #[tls_codec(skip)]
    signature: Vec<u8>,
}

#[derive(Debug)]
pub struct CertificateEmbeddedSCT {
    cert: Certificate,
    sct: SignedCertificateTimestamp,
    issuer_id: [u8; 32],
}

impl CertificateEmbeddedSCT {
    pub fn new(cert: Certificate, chain: &[Certificate]) -> Result<Self, SCTError> {
        let scts: SignedCertificateTimestampList = match cert.tbs_certificate.get() {
            Ok(Some((_, ext))) => ext,
            _ => return Err(SCTError::SCTListMalformed),
        };

        let sct = match scts
            .parse_timestamps()
            .or(Err(SCTError::SCTListMalformed))?
            .as_slice()
        {
            [e] => e,
            _ => return Err(SCTError::SCTListMalformed),
        }
        .parse_timestamp()?;

        let issuer = find_issuer_cert(chain);
        let issuer_id = {
            let mut hasher = sha2::Sha256::new();
            issuer
                .ok_or(SCTError::SCTMalformed)?
                .tbs_certificate
                .subject_public_key_info
                .encode(&mut hasher)
                .expect("failed to hash key!");
            hasher.finalize().into()
        };

        Ok(Self {
            cert,
            sct,
            issuer_id,
        })
    }
}

impl From<&CertificateEmbeddedSCT> for DigitallySigned {
    fn from(value: &CertificateEmbeddedSCT) -> Self {
        // Construct the precert by filtering out the SCT extension.
        let mut tbs_precert = value.cert.tbs_certificate.clone();
        tbs_precert.extensions = tbs_precert.extensions.map(|exts| {
            exts.iter()
                .filter(|v| v.extn_id != CT_PRECERT_SCTS)
                .cloned()
                .collect()
        });

        // TODO(tnytown): we may want to impl TryFrom instead and pass this error through.
        // when will we fail to encode a certificate with a modified extensions list?
        let mut tbs_precert_der = Vec::new();
        tbs_precert
            .encode_to_vec(&mut tbs_precert_der)
            .expect("failed to re-encode Precertificate!");

        DigitallySigned {
            // TODO(tnytown): Why does this not implement Copy?
            version: match value.sct.version {
                Version::V1 => Version::V1,
            },
            signature_type: SignatureType::CertificateTimestamp,
            timestamp: value.sct.timestamp,
            signed_entry: SignedEntry::PrecertEntry(PreCert {
                issuer_key_hash: value.issuer_id,
                tbs_certificate: tbs_precert_der.as_slice().into(),
            }),
            extensions: value.sct.extensions.clone().into(),

            log_id: value.sct.log_id.key_id,
            signature: value.sct.signature.signature.clone().into(),
        }
    }
}

impl From<&SigningCertificateDetachedSCT> for DigitallySigned {
    fn from(value: &SigningCertificateDetachedSCT) -> Self {
        let sct = &value.signed_certificate_timestamp;

        DigitallySigned {
            version: Version::V1,
            signature_type: SignatureType::CertificateTimestamp,
            timestamp: sct.timestamp,
            signed_entry: SignedEntry::X509Entry(value.chain.certificates[0].contents().into()),
            extensions: sct.extensions.clone().into(),

            log_id: sct.id,
            signature: sct.signature.clone(),
        }
    }
}

pub fn verify_sct(
    sct: impl Into<DigitallySigned>,
    // cert: x509_cert::Certificate,
    // chain: impl IntoIterator<Item = x509_cert::Certificate>,
    keyring: &Keyring,
) -> Result<(), SCTError> {
    let sct: DigitallySigned = sct.into();
    let serialized = sct.tls_serialize().or(Err(SCTError::VerificationFailed(
        "unable to reconstruct SCT for signing",
    )))?;

    keyring.verify(&sct.log_id, &sct.signature, &serialized)?;

    Ok(())
}
