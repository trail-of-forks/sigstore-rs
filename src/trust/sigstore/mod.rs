//
// Copyright 2021 The Sigstore Authors.
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

//! Helper Structs to interact with the Sigstore TUF repository.
//!
//! The main interaction point is [`SigstoreTrustRoot`], which fetches Rekor's
//! public key and Fulcio's certificate.
//!
//! These can later be given to [`cosign::ClientBuilder`](crate::cosign::ClientBuilder)
//! to enable Fulcio and Rekor integrations.
use std::path::Path;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::debug;
use tuf::metadata::{RawSignedMetadata, TargetPath};
use tuf::repository::{
    EphemeralRepository, FileSystemRepository, HttpRepository, HttpRepositoryBuilder,
    RepositoryProvider,
};

use sigstore_protobuf_specs::dev::sigstore::{
    common::v1::TimeRange,
    trustroot::v1::{CertificateAuthority, TransparencyLogInstance, TrustedRoot},
};
use webpki::types::CertificateDer;

mod constants;

use crate::errors::{Result, SigstoreError};
pub use crate::trust::{ManualTrustRoot, TrustRoot};

enum TUFClient<R>
where
    R: RepositoryProvider<tuf::pouf::Pouf1>,
{
    Cached(tuf::client::Client<tuf::pouf::Pouf1, FileSystemRepository<tuf::pouf::Pouf1>, R>),
    Ephemeral(tuf::client::Client<tuf::pouf::Pouf1, EphemeralRepository<tuf::pouf::Pouf1>, R>),
}

impl<R> TUFClient<R>
where
    R: RepositoryProvider<tuf::pouf::Pouf1>,
{
    async fn from_remote(remote: R, cache_dir: Option<&Path>) -> Result<Self> {
        let config = Default::default();
        let root = RawSignedMetadata::new(
            constants::static_resource("root.json")
                .expect("failed to fetch embedded TUF root!")
                .to_owned(),
        );

        let result = match cache_dir {
            Some(dir) => Self::Cached(
                tuf::client::Client::with_trusted_root(
                    config,
                    &root,
                    FileSystemRepository::new(dir),
                    remote,
                )
                .await?,
            ),
            None => Self::Ephemeral(
                tuf::client::Client::with_trusted_root(
                    config,
                    &root,
                    EphemeralRepository::new(),
                    remote,
                )
                .await?,
            ),
        };

        Ok(result)
    }

    async fn fetch_target(&mut self, name: &str) -> Result<Box<dyn AsyncRead + Unpin + Send + '_>> {
        let path = TargetPath::new(name)?;
        let local: &dyn RepositoryProvider<tuf::pouf::Pouf1> = match self {
            TUFClient::Cached(c) => {
                c.fetch_target_to_local(&path).await?;
                c.local_repo()
            }
            TUFClient::Ephemeral(c) => {
                c.fetch_target_to_local(&path).await?;
                c.local_repo()
            }
        };

        let contents = local.fetch_target(&path).await?;

        // Very silly: the inner value is already boxed, but we want a Tokio AsyncRead type, which
        // we need to re-box ...
        Ok(Box::new(contents.compat()))
    }

    async fn update(&mut self) -> Result<bool> {
        Ok(match self {
            TUFClient::Cached(c) => c.update().await,
            TUFClient::Ephemeral(c) => c.update().await,
        }?)
    }
}

/// Securely fetches Rekor public key and Fulcio certificates from Sigstore's TUF repository.
#[derive(Debug)]
pub struct SigstoreTrustRoot {
    trusted_root: TrustedRoot,
}

impl SigstoreTrustRoot {
    /// Constructs a new trust root backed by the Sigstore Public Good Instance.
    pub async fn new(cache_dir: Option<&Path>) -> Result<Self> {
        // These are statically defined and should always parse correctly.
        let metadata_base = url::Url::parse(constants::TUF_REPO_BASE)?;
        let remote: HttpRepository<_, tuf::pouf::Pouf1> =
            HttpRepositoryBuilder::new(metadata_base, Default::default()).build();

        debug!("constructing TUF client ...");
        let mut client: TUFClient<_> = TUFClient::from_remote(remote, cache_dir).await?;

        debug!("updating TUF metadata ...");
        client.update().await?;

        debug!("fetching trusted root ...");
        let mut trusted_root_buf = Vec::new();
        client
            .fetch_target("trusted_root.json")
            .await?
            .read_to_end(&mut trusted_root_buf)
            .await?;

        Ok(Self {
            trusted_root: serde_json::from_slice(&trusted_root_buf)?,
        })
    }

    #[inline]
    fn tlog_keys(tlogs: &[TransparencyLogInstance]) -> impl Iterator<Item = &[u8]> {
        tlogs
            .iter()
            .filter_map(|tlog| tlog.public_key.as_ref())
            .filter(|key| is_timerange_valid(key.valid_for.as_ref(), false))
            .filter_map(|key| key.raw_bytes.as_ref())
            .map(|key_bytes| key_bytes.as_slice())
    }

    #[inline]
    fn ca_keys(
        cas: &[CertificateAuthority],
        allow_expired: bool,
    ) -> impl Iterator<Item = &'_ [u8]> {
        cas.iter()
            .filter(move |ca| is_timerange_valid(ca.valid_for.as_ref(), allow_expired))
            .flat_map(|ca| ca.cert_chain.as_ref())
            .flat_map(|chain| chain.certificates.iter())
            .map(|cert| cert.raw_bytes.as_slice())
    }
}

impl crate::trust::TrustRoot for SigstoreTrustRoot {
    /// Fetch Fulcio certificates from the given TUF repository or reuse
    /// the local cache if its contents are not outdated.
    ///
    /// The contents of the local cache are updated when they are outdated.
    fn fulcio_certs(&self) -> Result<Vec<CertificateDer>> {
        // Allow expired certificates: they may have been active when the
        // certificate was used to sign.
        let certs = Self::ca_keys(&self.trusted_root.certificate_authorities, true);
        let certs: Vec<_> = certs
            .map(|c| CertificateDer::from(c).into_owned())
            .collect();

        if certs.is_empty() {
            Err(SigstoreError::TufMetadataError(
                "Fulcio certificates not found".into(),
            ))
        } else {
            Ok(certs)
        }
    }

    /// Fetch Rekor public keys from the given TUF repository or reuse
    /// the local cache if it's not outdated.
    ///
    /// The contents of the local cache are updated when they are outdated.
    fn rekor_keys(&self) -> Result<Vec<&[u8]>> {
        let keys: Vec<_> = Self::tlog_keys(&self.trusted_root.tlogs).collect();

        if keys.len() != 1 {
            Err(SigstoreError::TufMetadataError(
                "Did not find exactly 1 active Rekor key".into(),
            ))
        } else {
            Ok(keys)
        }
    }

    /// Fetch CTFE public keys from the given TUF repository or reuse
    /// the local cache if it's not outdated.
    ///
    /// The contents of the local cache are updated when they are outdated.
    fn ctfe_keys(&self) -> Result<Vec<&[u8]>> {
        let keys: Vec<_> = Self::tlog_keys(&self.trusted_root.ctlogs).collect();

        if keys.is_empty() {
            Err(SigstoreError::TufMetadataError(
                "CTFE keys not found".into(),
            ))
        } else {
            Ok(keys)
        }
    }
}

/// Given a `range`, checks that the the current time is not before `start`. If
/// `allow_expired` is `false`, also checks that the current time is not after
/// `end`.
fn is_timerange_valid(range: Option<&TimeRange>, allow_expired: bool) -> bool {
    let now = chrono::Utc::now().timestamp();

    let start = range.and_then(|r| r.start.as_ref()).map(|t| t.seconds);
    let end = range.and_then(|r| r.end.as_ref()).map(|t| t.seconds);

    match (start, end) {
        // If there was no validity period specified, the key is always valid.
        (None, _) => true,
        // Active: if the current time is before the starting period, we are not yet valid.
        (Some(start), _) if now < start => false,
        // If we want Expired keys, then we don't need to check the end.
        _ if allow_expired => true,
        // If there is no expiry date, the key is valid.
        (_, None) => true,
        // If we have an expiry date, check it.
        (_, Some(end)) => now <= end,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::{fixture, rstest};
    use std::fs;
    use std::path::Path;
    use std::time::SystemTime;
    use tempfile::TempDir;

    fn verify(root: &SigstoreTrustRoot, cache_dir: Option<&Path>) {
        if let Some(cache_dir) = cache_dir {
            assert!(
                cache_dir.join("trusted_root.json").exists(),
                "the trusted root was not cached"
            );
        }

        assert!(
            root.fulcio_certs().is_ok_and(|v| !v.is_empty()),
            "no Fulcio certs established"
        );
        assert!(
            root.rekor_keys().is_ok_and(|v| !v.is_empty()),
            "no Rekor keys established"
        );
        assert!(
            root.ctfe_keys().is_ok_and(|v| !v.is_empty()),
            "no CTFE keys established"
        );
    }

    #[fixture]
    fn cache_dir() -> TempDir {
        TempDir::new().expect("cannot create temp cache dir")
    }

    async fn trust_root(cache: Option<&Path>) -> SigstoreTrustRoot {
        SigstoreTrustRoot::new(cache)
            .await
            .expect("failed to construct SigstoreTrustRoot")
    }

    #[rstest]
    #[tokio::test]
    async fn trust_root_fetch(#[values(None, Some(cache_dir()))] cache: Option<TempDir>) {
        let cache = cache.as_ref().map(|t| t.path());
        let root = trust_root(cache).await;

        verify(&root, cache);
    }

    #[rstest]
    #[tokio::test]
    async fn trust_root_outdated(cache_dir: TempDir) {
        let trusted_root_path = cache_dir.path().join("trusted_root.json");
        let outdated_data = b"fake trusted root";
        fs::write(&trusted_root_path, outdated_data)
            .expect("failed to write to trusted root cache");

        let cache = Some(cache_dir.path());
        let root = trust_root(cache).await;
        verify(&root, cache);

        let data = fs::read(&trusted_root_path).expect("failed to read from trusted root cache");
        assert_ne!(data, outdated_data, "TUF cache was not properly updated");
    }

    #[test]
    fn test_is_timerange_valid() {
        fn range_from(start: i64, end: i64) -> TimeRange {
            let base = chrono::Utc::now();
            let start: SystemTime = (base + chrono::TimeDelta::seconds(start)).into();
            let end: SystemTime = (base + chrono::TimeDelta::seconds(end)).into();

            TimeRange {
                start: Some(start.into()),
                end: Some(end.into()),
            }
        }

        assert!(is_timerange_valid(None, true));
        assert!(is_timerange_valid(None, false));

        // Test lower bound conditions

        // Valid: 1 ago, 1 from now
        assert!(is_timerange_valid(Some(&range_from(-1, 1)), false));
        // Invalid: 1 from now, 1 from now
        assert!(!is_timerange_valid(Some(&range_from(1, 1)), false));

        // Test upper bound conditions

        // Invalid: 1 ago, 1 ago
        assert!(!is_timerange_valid(Some(&range_from(-1, -1)), false));
        // Valid: 1 ago, 1 ago
        assert!(is_timerange_valid(Some(&range_from(-1, -1)), true))
    }
}
