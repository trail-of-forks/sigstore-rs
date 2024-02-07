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

use std::cell::OnceCell;

use const_oid::db::rfc5280::ID_KP_CODE_SIGNING;
use tracing::debug;
use webpki::{
    types::{CertificateDer, UnixTime},
    EndEntityCert,
};

use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::{ExtendedKeyUsage, KeyUsage};

use crate::{
    crypto::{
        keyring::Keyring,
        transparency::{verify_sct, CertificateEmbeddedSCT},
        CertificatePool, CosignVerificationKey, Signature,
    },
    errors::Result as SigstoreResult,
    rekor::apis::configuration::Configuration as RekorConfiguration,
    tuf::{Repository, SigstoreRepository},
    verify::VerificationError,
};

use super::{models::VerificationMaterials, policy::VerificationPolicy, VerificationResult};

pub struct Verifier<'a, R: Repository> {
    #[allow(dead_code)]
    rekor_config: RekorConfiguration,
    trust_repo: R,
    cert_pool: OnceCell<CertificatePool<'a>>,
    ctfe_keyring: Keyring,
}

impl<'a, R: Repository> Verifier<'a, R> {
    pub fn new(rekor_config: RekorConfiguration, trust_repo: R) -> SigstoreResult<Self> {
        let ctfe_keyring = Keyring::new(trust_repo.ctfe_keys()?)?;
        Ok(Self {
            rekor_config,
            cert_pool: Default::default(),
            trust_repo,
            ctfe_keyring,
        })
    }

    fn cert_pool(&'a self) -> SigstoreResult<&CertificatePool<'a>> {
        let init_cert_pool = || {
            let certs = self.trust_repo.fulcio_certs()?;
            CertificatePool::from_certificates(certs, [])
        };

        let cert_pool = init_cert_pool()?;
        Ok(self.cert_pool.get_or_init(|| cert_pool))
    }

    pub fn verify(
        &'a self,
        materials: VerificationMaterials,
        policy: &impl VerificationPolicy,
    ) -> VerificationResult {
        let store = self
            .cert_pool()
            .expect("Failed to construct certificate pool");

        // In order to verify an artifact, we need to achieve the following:
        //
        // 1) Verify that the signing certificate is signed by the certificate
        //    chain and that the signing certificate was valid at the time
        //    of signing.
        // a) Verify the signing certificate's Signed Certificate Timestamp.
        // 2) Verify that the signing certificate belongs to the signer.
        // 3) Verify that the artifact signature was signed by the public key in the
        //    signing certificate.
        // 4) Verify that the Rekor entry is consistent with the other signing
        //    materials (preventing CVE-2022-36056)
        // 5) Verify the inclusion proof supplied by Rekor for this artifact,
        //    if we're doing online verification.
        // 6) Verify the Signed Entry Timestamp (SET) supplied by Rekor for this
        //    artifact.
        // 7) Verify that the signing certificate was valid at the time of
        //    signing by comparing the expiry against the integrated timestamp.

        // 1) Verify that the signing certificate is signed by the certificate
        //    chain and that the signing certificate was valid at the time
        //    of signing.
        let tbs_certificate = &materials.certificate.tbs_certificate;
        let issued_at = tbs_certificate.validity.not_before.to_unix_duration();
        let cert_der: CertificateDer = (&materials.certificate)
            .to_der()
            .expect("failed to DER-encode constructed Certificate!")
            .into();
        let ee_cert: EndEntityCert = (&cert_der).try_into().expect("TODO");

        let Ok(trusted_chain) =
            store.verify_cert_with_time(&ee_cert, UnixTime::since_unix_epoch(issued_at))
        else {
            return Err(VerificationError::CertificateVerificationFailure);
        };

        debug!("signing certificate chains back to trusted root");

        // 1a) Verify the signing certificate's Signed Certificate Timestamp.
        let issuer_spki = if let Some(issuer) = trusted_chain.intermediate_certificates().next() {
            debug!("sct: an intermediate certificate is our issuer");
            let Ok(issuer) = x509_cert::Certificate::from_der(&issuer.der()) else {
                return Err(VerificationError::CertificateMalformed);
            };

            let Ok(bytes) = issuer.tbs_certificate.subject_public_key_info.to_der() else {
                return Err(VerificationError::CertificateMalformed);
            };

            bytes
        } else {
            debug!("sct: the anchor is our issuer");

            // Prefix the SPKI with the ASN.1 SEQUENCE tag and a blank short definite-form length.
            let mut spki_sequence = vec![0x30u8, 0x00u8];
            spki_sequence.extend(trusted_chain.anchor().subject_public_key_info.iter());
            // Check if the body of the sequence, which we just appended, has a representable length.
            let spki_len = spki_sequence.len() - 2;
            if spki_len > (2 << 7) - 1 {
                return Err(VerificationError::CertificateMalformed);
            }
            // Update the placeholder length.
            spki_sequence[1] = spki_len as u8;

            spki_sequence
        };
        debug!("sct: SPKI={}", hex::encode(&issuer_spki));

        let Ok(sct) =
            CertificateEmbeddedSCT::new_with_issuer_spki(&materials.certificate, &issuer_spki)
        else {
            return Err(VerificationError::CertificateMalformed);
        };

        if verify_sct(&sct, &self.ctfe_keyring).is_err() {
            return Err(VerificationError::CertificateVerificationFailure);
        }
        debug!("SCT verified");

        // 2) Verify that the signing certificate belongs to the signer.

        let Ok(Some((_, key_usage_ext))) = tbs_certificate.get::<KeyUsage>() else {
            return Err(VerificationError::CertificateMalformed);
        };

        if !key_usage_ext.digital_signature() {
            return Err(VerificationError::CertificateTypeError(
                "Key usage is not of type `digital signature`".into(),
            ));
        }

        let Ok(Some((_, extended_key_usage_ext))) = tbs_certificate.get::<ExtendedKeyUsage>()
        else {
            return Err(VerificationError::CertificateMalformed);
        };

        if !extended_key_usage_ext.0.contains(&ID_KP_CODE_SIGNING) {
            return Err(VerificationError::CertificateTypeError(
                "Extended key usage does not contain `code signing`".into(),
            ));
        }

        if let Some(err) = policy.verify(&materials.certificate) {
            return Err(err)?;
        }
        debug!("signing certificate conforms to policy");

        // 3) Verify that the signature was signed by the public key in the signing certificate
        let Ok(signing_key): SigstoreResult<CosignVerificationKey> =
            (&tbs_certificate.subject_public_key_info).try_into()
        else {
            return Err(VerificationError::CertificateMalformed);
        };

        let verify_sig = signing_key.verify_prehash(
            Signature::Raw(&materials.signature),
            &materials.input_digest,
        );
        if verify_sig.is_err() {
            return Err(VerificationError::SignatureVerificationFailure);
        }
        debug!("signature corresponds to public key");

        // 4) Verify that the Rekor entry is consistent with the other signing
        //    materials
        let log_entry = materials.rekor_entry();
        debug!("log entry is consistent with other materials");

        // 5) Verify the inclusion proof supplied by Rekor for this artifact,
        //    if we're doing online verification.
        // TODO(tnytown): Merkle inclusion

        // 6) Verify the Signed Entry Timestamp (SET) supplied by Rekor for this
        //    artifact.
        // TODO(tnytown) SET verification

        // 7) Verify that the signing certificate was valid at the time of
        //    signing by comparing the expiry against the integrated timestamp.
        let integrated_time = log_entry.integrated_time as u64;
        let not_before = tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs();
        let not_after = tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs();
        if !(not_before <= integrated_time && integrated_time <= not_after) {
            return Err(VerificationError::CertificateExpired);
        }
        debug!("data signed during validity period");

        debug!("successfully verified!");
        Ok(())
    }
}

impl<'a> Verifier<'a, SigstoreRepository> {
    pub fn production() -> SigstoreResult<Verifier<'a, SigstoreRepository>> {
        let updater = SigstoreRepository::new(None)?;

        Verifier::<'a, SigstoreRepository>::new(Default::default(), updater)
    }
}
