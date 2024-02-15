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
use tls_codec::{SerializeBytes, TlsByteVecU16, TlsByteVecU24, TlsSerializeBytes, TlsSize};
use x509_cert::{
    der,
    der::Encode,
    ext::pkix::{
        sct::Version, BasicConstraints, ExtendedKeyUsage, SignedCertificateTimestamp,
        SignedCertificateTimestampList,
    },
    Certificate,
};

use super::keyring::{Keyring, KeyringError};
use crate::fulcio::SigningCertificateDetachedSCT;

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

    // TODO(tnytown): do we need to sanity-check the algo of the certificate here?

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

    // XX(tnytown): pass in some useful context. These fields will not be encoded into the
    // TLS DigitallySigned blob, but we need them to properly verify the reconstructed
    // message.
    #[tls_codec(skip)]
    log_id: [u8; 32],
    #[tls_codec(skip)]
    signature: Vec<u8>,
}

#[derive(Debug)]
pub struct CertificateEmbeddedSCT<'a> {
    cert: &'a Certificate,
    sct: SignedCertificateTimestamp,
    issuer_id: [u8; 32],
}

impl<'a> CertificateEmbeddedSCT<'a> {
    pub fn new(cert: &'a Certificate, chain: &'a [Certificate]) -> Result<Self, SCTError> {
        // Traverse chain to find the issuer we're verifying against.
        let issuer = find_issuer_cert(chain).ok_or(SCTError::SCTMalformed)?;
        let spki = issuer
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .or(Err(SCTError::SCTMalformed))?;

        Self::new_with_issuer_spki(cert, &spki)
    }

    pub fn new_with_issuer_spki(cert: &'a Certificate, spki: &[u8]) -> Result<Self, SCTError> {
        let scts: SignedCertificateTimestampList = match cert.tbs_certificate.get() {
            Ok(Some((_, ext))) => ext,
            _ => return Err(SCTError::SCTListMalformed),
        };

        // Parse SCT structures.
        let sct = match scts
            .parse_timestamps()
            .or(Err(SCTError::SCTListMalformed))?
            .as_slice()
        {
            [e] => e,
            // We expect exactly one element here. Fail if there are more or less.
            _ => return Err(SCTError::SCTListMalformed),
        }
        .parse_timestamp()?;

        let issuer_id = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(spki);
            hasher.finalize().into()
        };

        Ok(Self {
            cert,
            sct,
            issuer_id,
        })
    }
}

impl From<&CertificateEmbeddedSCT<'_>> for DigitallySigned {
    fn from(value: &CertificateEmbeddedSCT) -> Self {
        // Construct the precert by filtering out the SCT extension.
        let mut tbs_precert = value.cert.tbs_certificate.clone();
        tbs_precert.extensions = tbs_precert.extensions.map(|exts| {
            exts.iter()
                .filter(|v| v.extn_id != CT_PRECERT_SCTS)
                .cloned()
                .collect()
        });

        // TODO(tnytown): Instead of `expect` on `encode_to_vec`, we may want to implement
        // `TryFrom` and pass this error through. When will we fail to encode a certificate
        // with a modified extensions list?
        let mut tbs_precert_der = Vec::new();
        tbs_precert
            .encode_to_vec(&mut tbs_precert_der)
            .expect("failed to re-encode Precertificate!");

        DigitallySigned {
            // XX(tnytown): This match is needed because `sct::Version` does not implement Copy.
            version: match value.sct.version {
                Version::V1 => Version::V1,
            },
            signature_type: SignatureType::CertificateTimestamp,
            timestamp: value.sct.timestamp,
            signed_entry: SignedEntry::PrecertEntry(PreCert {
                issuer_key_hash: value.issuer_id,
                tbs_certificate: tbs_precert_der.as_slice().into(),
            }),
            extensions: value.sct.extensions.clone(),

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

/// Verifies a given signing certificate's Signed Certificate Timestamp.
///
/// SCT verification as defined by [RFC 6962] guarantees that a given certificate has been submitted
/// to a Certificate Transparency log. Verification should be performed on the signing certificate
/// in Sigstore verify and sign flows. Certificates that fail SCT verification are misissued and
/// MUST NOT be trusted.
///
/// For more information on Certificate Transparency and the guarantees it provides, see <https://certificate.transparency.dev/howctworks/>.
///
/// [RFC 6962]: https://datatracker.ietf.org/doc/html/rfc6962
pub fn verify_sct(sct: impl Into<DigitallySigned>, keyring: &Keyring) -> Result<(), SCTError> {
    let sct: DigitallySigned = sct.into();
    let serialized = sct.tls_serialize().or(Err(SCTError::VerificationFailed(
        "unable to reconstruct SCT for signing",
    )))?;

    keyring.verify(&sct.log_id, &sct.signature, &serialized)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{verify_sct, CertificateEmbeddedSCT};
    use crate::crypto::keyring::Keyring;
    use crate::fulcio::SigningCertificateDetachedSCT;
    use p256::ecdsa::VerifyingKey;
    use std::str::FromStr;
    use x509_cert::der::DecodePem;
    use x509_cert::spki::EncodePublicKey;
    use x509_cert::Certificate;

    #[test]
    fn verify_embedded_sct() {
        let cert_pem = r#"-----BEGIN CERTIFICATE-----
MIICzDCCAlGgAwIBAgIUF96OLbM9/tDVHKCJliXLTFvnfjAwCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjMxMjEzMDU1MDU1WhcNMjMxMjEzMDYwMDU1WjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEmir+Lah2291zCsLkmREQNLzf99z571BNB+fa
rerSLGzcwLFK7GRLTGYcO0oStxCYavxRQPMo3JvB8vGtZbn/76OCAXAwggFsMA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU8U9M
t9GMrRm8+gifPtc63nlP3OIwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y
ZD8wGwYDVR0RAQH/BBEwD4ENYXNjQHRldHN1by5zaDAsBgorBgEEAYO/MAEBBB5o
dHRwczovL2dpdGh1Yi5jb20vbG9naW4vb2F1dGgwLgYKKwYBBAGDvzABCAQgDB5o
dHRwczovL2dpdGh1Yi5jb20vbG9naW4vb2F1dGgwgYkGCisGAQQB1nkCBAIEewR5
AHcAdQDdPTBqxscRMmMZHhyZZzcCokpeuN48rf+HinKALynujgAAAYxhumYsAAAE
AwBGMEQCIHRRe20lRrNM4xd07mpjTtgaE6FGS3jjF++zW8ZMnth3AiAd6LVAAeVW
hSW4T0XJRw9lGU6/EK9+ELZpEjrY03dJ1zAKBggqhkjOPQQDAwNpADBmAjEAiHqK
W9PQ/5h7VROVIWPaxUo3LhrL2sZanw4bzTDBDY0dRR19ZFzjtAph1RzpQqppAjEA
plAvxwkAIR2jurboJZ4Zm9rNAx8KvA+A5yQFzNkGgKDLjTJrKmSKoIcWV3j7WfdL
-----END CERTIFICATE-----"#;

        let chain_pem = [
            r#"-----BEGIN CERTIFICATE-----
MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV7
7LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS
0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYB
BQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjp
KFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZI
zj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJR
nZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsP
mygUY7Ii2zbdCdliiow=
-----END CERTIFICATE-----"#,
            r#"-----BEGIN CERTIFICATE-----
MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7
XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex
X69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j
YzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY
wB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ
KsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM
WP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9
TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ
-----END CERTIFICATE-----"#,
        ];

        let ctfe_pem = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiPSlFi0CmFTfEjCUqF9HuCEcYXNK
AaYalIJmBZ8yyezPjTqhxrKBpMnaocVtLJBI1eM3uXnQzQGAJdJ4gs9Fyw==
-----END PUBLIC KEY-----"#;

        let cert = Certificate::from_pem(&cert_pem).unwrap();
        let chain = chain_pem.map(|c| Certificate::from_pem(&c).unwrap());
        let sct = CertificateEmbeddedSCT::new(cert, &chain).unwrap();
        let ctfe_key: VerifyingKey = VerifyingKey::from_str(&ctfe_pem).unwrap();
        let keyring = Keyring::new([ctfe_key.to_public_key_der().unwrap().as_bytes()]).unwrap();

        assert!(verify_sct(&sct, &keyring).is_ok());
    }

    #[test]
    fn verify_detached_sct() {
        let sct_json = r#"{"chain": {"certificates": ["-----BEGIN CERTIFICATE-----\nMIICUTCCAfigAwIBAgIUAafXe40Q5jthWJMo+JsJJCq09IAwCgYIKoZIzj0EAwIw\naDEMMAoGA1UEBhMDVVNBMQswCQYDVQQIEwJXQTERMA8GA1UEBxMIS2lya2xhbmQx\nFTATBgNVBAkTDDc2NyA2dGggU3QgUzEOMAwGA1UEERMFOTgwMzMxETAPBgNVBAoT\nCHNpZ3N0b3JlMB4XDTIzMTIxNDA3MDkzMFoXDTIzMTIxNDA3MTkzMFowADBZMBMG\nByqGSM49AgEGCCqGSM49AwEHA0IABDQT+qfW/VnHts0GSqI3kOc2z1lygSUWia3y\nIOx5qyWpXS1PwVcTbJnkcQEy1mnAES76NyfN5LsHHW2m53hF4WGjgecwgeQwDgYD\nVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBRpKUIe\nAqDxiw/GzKGRLFAvbaCnujAfBgNVHSMEGDAWgBTjGF7/fiITblnp3yIv3G1DETbS\ncTAbBgNVHREBAf8EETAPgQ1hc2NAdGV0c3VvLnNoMC4GCisGAQQBg78wAQEEIGh0\ndHBzOi8vb2F1dGgyLnNpZ3N0b3JlLmRldi9hdXRoMDAGCisGAQQBg78wAQgEIgwg\naHR0cHM6Ly9vYXV0aDIuc2lnc3RvcmUuZGV2L2F1dGgwCgYIKoZIzj0EAwIDRwAw\nRAIgOW+tCrt44rjWDCMSWhwC0zJRWpqH/qWRgSw2ndK7w3ICIGz0DDAXhvl6JFAz\nQp+40dnoUGKr+y0MF1zVaDOb1y+q\n-----END CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\nMIICFzCCAb2gAwIBAgIUbPNC2sKGpw8cOQfpv8yJii7c7TEwCgYIKoZIzj0EAwIw\naDEMMAoGA1UEBhMDVVNBMQswCQYDVQQIEwJXQTERMA8GA1UEBxMIS2lya2xhbmQx\nFTATBgNVBAkTDDc2NyA2dGggU3QgUzEOMAwGA1UEERMFOTgwMzMxETAPBgNVBAoT\nCHNpZ3N0b3JlMB4XDTIzMTIxNDA2NDIzNloXDTMzMTIxNDA2NDIzNlowaDEMMAoG\nA1UEBhMDVVNBMQswCQYDVQQIEwJXQTERMA8GA1UEBxMIS2lya2xhbmQxFTATBgNV\nBAkTDDc2NyA2dGggU3QgUzEOMAwGA1UEERMFOTgwMzMxETAPBgNVBAoTCHNpZ3N0\nb3JlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfe1ZllZHky68F3jRhY4Hxx7o\nPBoBaD1i9UJtyE8xfIYGVpD1+jSHctZRmiv2ZsDEE6WN3k5lc2O2GyemHJwULqNF\nMEMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYE\nFOMYXv9+IhNuWenfIi/cbUMRNtJxMAoGCCqGSM49BAMCA0gAMEUCIDj5wbYN3ym8\nwY+Uy+FkKASpBQodXdgF+JR9tWhNDlc/AiEAwqMTyLa6Yr+5t1DvnUsR4lQNoXD7\nz8XmxcUnJTenEh4=\n-----END CERTIFICATE-----"]}, "signedCertificateTimestamp": "eyJzY3RfdmVyc2lvbiI6MCwiaWQiOiJla0ppei9acEcrVUVuNXcvR2FJcjYrYXdJK1JLZmtwdC9WOVRldTd2YTFrPSIsInRpbWVzdGFtcCI6MTcwMjUzNzc3MDQyNiwiZXh0ZW5zaW9ucyI6IiIsInNpZ25hdHVyZSI6IkJBTUFSakJFQWlBT28vdDZ4RDY0RkV2TWpGcGFsMUhVVkZxQU5nOXJ3ZEttd3NQU2wxNm5FZ0lnZmFNTlJHMTBxQVY1Z280MzU1WkxVNVVvdHRvWTAwK0l0YXhZYjRkZmV0Zz0ifQ=="}"#;

        let ctfe_pem = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbbQiLx6GKy6ivhc11wJGbQjc2VX/
mnuk5d670MTXR3p+LIAcxd5MhqIHpLmyYJ5mDKLEoZ/pC0nPuje3JueBcA==
-----END PUBLIC KEY-----"#;

        let sct: SigningCertificateDetachedSCT = serde_json::from_str(sct_json).unwrap();
        let ctfe_key: VerifyingKey = VerifyingKey::from_str(&ctfe_pem).unwrap();
        let keyring = Keyring::new([ctfe_key.to_public_key_der().unwrap().as_bytes()]).unwrap();

        assert!(verify_sct(&sct, &keyring).is_ok());
    }
}
